# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion R3 -- load-time static ReDoS quarantine (council 1fee93f2).

NORTH STAR: no ``code_detectors.json`` regex that can catastrophically backtrack
ever reaches the active detector set ``scan_code`` runs on untrusted input.

R4 (later) makes ``scan_code`` read its detectors from the DB, so an authored /
edited ``code_detectors.json`` regex becomes an input to a matcher run against
untrusted code. R3 adds a dep-free, load-time guard in ``KnowledgeLoader`` so a
catastrophic-backtracking (CWE-1333) regex never enters ``_detectors_by_language``
(the active set): it is EXCLUDED, surfaced in ``quarantined_detectors`` (queryable),
and LOGGED -- never silently dropped. In-memory only; the byte-frozen S0
``code_detectors.json`` is untouched (guarded by R2's sha256 immovability test and
reconfirmed here).

PRECISION (R1 adversarial follow-up): a SINGLE unbounded quantifier (``.*`` /
``.+`` / ``[^x]+``) is POLYNOMIAL and ceiling-bounded by ``_MAX_LINE_LENGTH`` (4000)
-- it MUST survive. Only NESTED unbounded quantifiers and OVERLAPPING ALTERNATION
UNDER a quantifier are the exponential shapes the guard quarantines. Hyperion
verified all 41 migrated detectors are ReDoS-safe (assess_threat
``input_regex_dos``), so a migrated detector that trips the check is a bug in the
check, not a real bomb.

Scope: loader level. No live othrys.db, no production edit, no corpus write. The
synthetic bombs below are test-local strings ONLY -- never added to the corpus.
Firewall: hyperion imports only hyperion.*.
"""

from __future__ import annotations

import json
import logging
import shutil
import sys
from pathlib import Path

import pytest

# Repo root on sys.path so ``tests`` imports as a package under any invocation.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from hyperion.knowledge.loader import (
    _KNOWLEDGE_DIR,
    KnowledgeLoader,
    static_redos_reason,
)

# Frozen post-migration counts (R2 parity): python 29 / javascript 25.
_PY_COUNT = 29
_JS_COUNT = 25
_TOTAL_DETECTORS = 41

# Synthetic bombs -- TEST-LOCAL strings ONLY, deliberately NOT added to the corpus.
_NESTED_QUANTIFIER_BOMBS = [
    r"(?:a+)+", r"(a*)*", r"(a+)*", r"(a*)+", r"([a-z]+)+", r"(.*)*", r"(x+x+)+y",
]
_OVERLAPPING_ALTERNATION_BOMBS = [
    r"(a|a)*", r"(a|a)+", r"(a|ab)+", r"(ab|a.)+",
]
# H1 -- a catastrophic quantifier hidden inside a LOOKAROUND body. The three walkers
# recurse ASSERT/ASSERT_NOT subpatterns; ALL of these PASSED (returned None) before
# the fix -- the guard's blind spot. Grouped by the reason each must now report.
_LOOKAROUND_NESTED_BOMBS = [
    r"(?=(a+)+$)", r"(?!(a+)+z)", r"x(?=(a+)+b)y", r"foo(?=.*(a+)+$)bar",
]
_LOOKAROUND_ALTERNATION_BOMBS = [
    r"(?=(a|a)+z)", r"(?!(a|ab)+$)",
]
# H2 -- large BOUNDED nested quantifiers. A bounded max over _NESTED_REPEAT_CEILING
# is unbounded-equivalent for the nesting check: (a{1,1000}){1,1000} backtracks like
# (a+)+ . ALL of these PASSED (returned None) before the fix.
_LARGE_BOUNDED_NESTED_BOMBS = [
    r"(a{1,1000}){1,1000}", r"(a{1,100}){1,100}", r"(a{1,50}){1,50}",
    r"(a{1,1000}){1,1000}b",
]
# Below the ceiling a nested bounded pair is trivially bounded -- must NOT flag.
_SMALL_BOUNDED_NESTED_SAFE = [
    r"(a{1,3}){1,3}", r"(a+){1,3}", r"(a{1,5}){1,2}",
]
# H3 -- an AMBIGUOUS (min != max) inner repeat under an UNBOUNDED outer quantifier is
# exponential even when the inner bound is small and easily-accidental. ALL of these
# PASSED (returned None) before the fix: rule 1 keyed the inner on MAGNITUDE (max >
# _NESTED_REPEAT_CEILING), so a small-bounded ambiguous inner slipped through. Proven
# catastrophic: ``(a{1,2})+$`` is ~0.25s at len30 and >1s by len33. The outer ``+``
# is unbounded, so the reason is the unchanged "nested unbounded quantifier".
_H3_OUTER_UNBOUNDED_AMBIGUOUS_BOMBS = [
    r"(a{1,2})+$", r"(a{1,3})+$", r"(\d{1,3})+$", r"([a-z]{1,4})+$", r"(a{1,10})+$",
]
# H3 -- the BOTH-BOUNDED bomb: neither quantifier is unbounded, yet the search space
# inner_max ** outer_max = 9**9 = 387,420,489 is a DoS (measured >14s at len82). It
# PASSED before the fix (outer 9 <= ceiling, so rule 1 never inspected the body). Its
# reason names the both-bounded shape distinctly.
_H3_BOTH_BOUNDED_BOMBS = [
    r"(a{1,9}){1,9}$", r"(a{1,9}){1,9}",
]
# H3 precision -- must SURVIVE. A FIXED inner ``(a{3})+`` (min==max) is deterministic
# (measured 0.01ms), and a both-bounded pair whose search space stays under the
# ceiling ``(a{1,5}){1,5}`` = 5**5 = 3125 is trivially bounded (measured 0.11ms).
_H3_SAFE_CONTROLS = [
    r"(a{3})+$", r"(a{1,5}){1,5}$",
]
_COMPILE_FAILURES = [r"(unclosed", r"a{2,1}", r"[z-a]", r"(?P<n>)(?P<n>)"]

# The 8 real detectors carrying a SINGLE unbounded quantifier (polynomial,
# ceiling-bounded) that MUST survive -- the precision guard.
_BENIGN_SINGLE_UNBOUNDED = {
    "sql_format_string",
    "cors_wildcard",
    "weak_rsa_key",
    "connection_string_password",
    "assert_security",
    "prompt_injection_risk",
    "unrestricted_tool_access",
    "unvalidated_tool_output",
}
# Of those, the non-agent ones live in the active python bucket (the rest are
# agent-signal-gated and excluded from the language buckets regardless).
_BENIGN_IN_PYTHON_BUCKET = {
    "sql_format_string",
    "cors_wildcard",
    "weak_rsa_key",
    "connection_string_password",
    "assert_security",
}


def _all_detectors() -> list[dict]:
    """The 41 real detectors straight from JSON on disk (the source of truth)."""
    return json.loads(
        (_KNOWLEDGE_DIR / "code_detectors.json").read_text(encoding="utf-8")
    )["detectors"]


@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


# ===========================================================================
# (1) All 41 real detectors pass the quarantine; counts stay 29 / 25.
# ===========================================================================

def test_all_41_real_detectors_pass_quarantine():
    """Every migrated regex is ReDoS-safe -- static_redos_reason returns None for
    all 41. A migrated detector that trips the check is a bug in the check."""
    dets = _all_detectors()
    assert len(dets) == _TOTAL_DETECTORS
    offenders = [
        (d["id"], static_redos_reason(d["regex"]))
        for d in dets
        if static_redos_reason(d["regex"]) is not None
    ]
    assert offenders == [], offenders


def test_healthy_load_quarantines_nothing(kb):
    """On the real corpus the quarantine list is empty -- nothing dropped."""
    assert kb.get_quarantined_detectors() == []
    assert kb.quarantined_detectors == []


def test_counts_unchanged_after_quarantine(kb):
    """get_code_detectors counts are unchanged by the guard: 29 python / 25 js
    (R2 parity must not regress)."""
    assert len(kb.get_code_detectors("python")) == _PY_COUNT
    assert len(kb.get_code_detectors("javascript")) == _JS_COUNT


def test_get_quarantined_detectors_returns_fresh_list(kb):
    """A caller cannot corrupt the loader's record by mutating the result."""
    first = kb.get_quarantined_detectors()
    first.append({"id": "poison"})
    assert kb.get_quarantined_detectors() == []


# ===========================================================================
# (2) Synthetic bombs ARE quarantined -- both exponential shapes + compile fails.
# ===========================================================================

def test_synthetic_nested_quantifier_bombs_quarantined():
    for bomb in _NESTED_QUANTIFIER_BOMBS:
        assert static_redos_reason(bomb) == "nested unbounded quantifier", bomb


def test_synthetic_overlapping_alternation_bombs_quarantined():
    for bomb in _OVERLAPPING_ALTERNATION_BOMBS:
        reason = static_redos_reason(bomb)
        assert reason == "overlapping alternation under quantifier", (bomb, reason)


def test_h1_lookaround_nested_quantifier_bombs_quarantined():
    """H1: a nested unbounded quantifier hidden in a lookaround body is caught.

    These all PASSED the guard (returned None) before the walkers recursed
    ASSERT/ASSERT_NOT bodies -- the proven bypass this fix closes."""
    for bomb in _LOOKAROUND_NESTED_BOMBS:
        assert static_redos_reason(bomb) == "nested unbounded quantifier", bomb


def test_h1_lookaround_overlapping_alternation_bombs_quarantined():
    """H1: an overlapping alternation under a quantifier inside a lookaround body."""
    for bomb in _LOOKAROUND_ALTERNATION_BOMBS:
        reason = static_redos_reason(bomb)
        assert reason == "overlapping alternation under quantifier", (bomb, reason)


def test_h2_large_bounded_nested_quantifier_bombs_quarantined():
    """H2: a large BOUNDED nested quantifier pair is unbounded-equivalent and caught.

    (a{1,1000}){1,1000} and friends all PASSED (returned None) before the ceiling --
    rule 1 only fired on a truly unbounded max. The proven bypass this fix closes."""
    for bomb in _LARGE_BOUNDED_NESTED_BOMBS:
        assert static_redos_reason(bomb) == "nested unbounded quantifier", bomb


def test_small_bounded_nested_repeats_not_quarantined():
    """Precision for H2: a nested bounded pair BELOW the ceiling is trivially bounded
    (polynomial) and must survive -- the ceiling must not over-quarantine."""
    for safe in _SMALL_BOUNDED_NESTED_SAFE:
        assert static_redos_reason(safe) is None, safe


def test_h3_outer_unbounded_ambiguous_inner_bombs_quarantined():
    """H3: an AMBIGUOUS small-bounded inner (``(a{1,2})+``) under an unbounded outer
    is exponential. These all PASSED (returned None) before the inner check moved from
    magnitude to ambiguity -- the proven bypass this fix closes."""
    for bomb in _H3_OUTER_UNBOUNDED_AMBIGUOUS_BOMBS:
        assert static_redos_reason(bomb) == "nested unbounded quantifier", bomb


def test_h3_both_bounded_ambiguous_bombs_quarantined():
    """H3: the both-bounded bomb ``(a{1,9}){1,9}`` (9**9 = 387M states, >14s) whose
    search space exceeds the ceiling. It PASSED before the fix (neither quantifier is
    unbounded-equivalent, so rule 1 never inspected the body)."""
    for bomb in _H3_BOTH_BOUNDED_BOMBS:
        assert static_redos_reason(bomb) == "nested bounded ambiguous quantifier", bomb


def test_h3_safe_controls_not_quarantined():
    """H3 precision: a FIXED inner ``(a{3})+`` (deterministic) and a both-bounded pair
    under the ceiling ``(a{1,5}){1,5}`` (5**5 = 3125, ~0s) must survive -- the
    ambiguity rule and the search-space ceiling must not over-quarantine."""
    for safe in _H3_SAFE_CONTROLS:
        assert static_redos_reason(safe) is None, safe


def test_compile_failures_quarantined():
    """A regex that will not even compile fails closed (quarantined)."""
    for bad in _COMPILE_FAILURES:
        reason = static_redos_reason(bad)
        assert reason is not None and reason.startswith("uncompilable"), (bad, reason)


def test_non_string_regex_quarantined():
    """A detector without a string regex is quarantined (fail closed)."""
    assert static_redos_reason(None) is not None
    assert static_redos_reason(123) is not None


# ===========================================================================
# (3) Precision guard -- the 8 benign single-unbounded detectors are NOT flagged.
# ===========================================================================

def test_benign_single_unbounded_detectors_not_quarantined():
    """The 8 real detectors carrying a single unbounded quantifier survive: a
    lone ``.*`` / ``.+`` / ``[^x]+`` is polynomial, not exponential."""
    by_name = {d["name"]: d for d in _all_detectors()}
    for name in _BENIGN_SINGLE_UNBOUNDED:
        assert static_redos_reason(by_name[name]["regex"]) is None, name


def test_benign_single_unbounded_detectors_stay_in_active_set(kb):
    """The non-agent benign singles remain in the active python bucket."""
    present = {d["name"] for d in kb.get_code_detectors("python")}
    for name in _BENIGN_IN_PYTHON_BUCKET:
        assert name in present, name


def test_extra_benign_singles_not_quarantined():
    """Broader precision: assorted single-unbounded / bounded / branch-free
    patterns are all ReDoS-safe and must NOT be quarantined."""
    for safe in (r".*", r".+", r".*?", r"[^x]+", r"\bfoo\b.*bar",
                 r"(?:a|b|c)", r"(?:RSA |EC )?KEY", r"a{1,5}", r"foo|bar",
                 r"\d{6,}", r"(?:ab|ac)+", r"(?:foo|bar)+"):
        assert static_redos_reason(safe) is None, safe


# ===========================================================================
# (4) End-to-end OUTCOME proof -- a bomb authored into the corpus is EXCLUDED
#     from the active set, surfaced, and logged (the north star).
# ===========================================================================

def _write_corpus(tmp_path: Path, extra: list[dict]) -> Path:
    """Copy the real corpus into *tmp_path*, appending *extra* detectors to
    code_detectors.json. Proves the load-time path without touching the frozen
    source-of-truth corpus on disk."""
    for name in (
        "threat_vectors.json",
        "agent_threats.json",
        "decision_rules.json",
        "security_tools.json",
    ):
        shutil.copy(_KNOWLEDGE_DIR / name, tmp_path / name)
    doc = json.loads(
        (_KNOWLEDGE_DIR / "code_detectors.json").read_text(encoding="utf-8")
    )
    doc["detectors"] = list(doc["detectors"]) + extra
    (tmp_path / "code_detectors.json").write_text(
        json.dumps(doc), encoding="utf-8"
    )
    return tmp_path


def _detector(det_id: str, name: str, regex: str) -> dict:
    return {
        "id": det_id,
        "detector_kind": "code_shape",
        "name": name,
        "regex": regex,
        "languages": ["*"],
        "base_severity": "high",
        "cwe": "CWE-1333",
        "description": "synthetic (test only)",
        "remediation": "n/a",
        "requires_agent_signals": False,
        "category": "input_validation",
    }


def test_authored_bomb_excluded_surfaced_and_logged(tmp_path, caplog):
    """A catastrophic-backtracking regex authored into code_detectors.json is
    EXCLUDED from every active language bucket, surfaced in quarantined_detectors,
    and logged -- while the 41 real detectors are untouched (counts hold)."""
    corpus = _write_corpus(tmp_path, [_detector(
        "cd-test-redos_bomb", "redos_bomb", r"(?:a+)+$"
    )])
    with caplog.at_level(logging.WARNING, logger="hyperion.knowledge.loader"):
        loader = KnowledgeLoader(corpus)

    # Surfaced with a reason, never silently dropped.
    quarantined = {q["id"]: q for q in loader.get_quarantined_detectors()}
    assert "cd-test-redos_bomb" in quarantined
    assert quarantined["cd-test-redos_bomb"]["reason"] == "nested unbounded quantifier"

    # Logged at load.
    assert any(
        "cd-test-redos_bomb" in rec.getMessage() for rec in caplog.records
    ), [r.getMessage() for r in caplog.records]

    # EXCLUDED from every active language bucket (the north star).
    for lang in ("python", "javascript"):
        names = {d["name"] for d in loader.get_code_detectors(lang)}
        assert "redos_bomb" not in names, lang

    # The real detectors are untouched -- counts unchanged despite the bomb.
    assert len(loader.get_code_detectors("python")) == _PY_COUNT
    assert len(loader.get_code_detectors("javascript")) == _JS_COUNT


def test_authored_uncompilable_detector_excluded(tmp_path):
    """An uncompilable authored regex is quarantined too (fail closed)."""
    corpus = _write_corpus(tmp_path, [_detector(
        "cd-test-bad_regex", "bad_regex", r"(unclosed"
    )])
    loader = KnowledgeLoader(corpus)
    quarantined = {q["id"] for q in loader.get_quarantined_detectors()}
    assert "cd-test-bad_regex" in quarantined
    for lang in ("python", "javascript"):
        assert "bad_regex" not in {
            d["name"] for d in loader.get_code_detectors(lang)
        }


def test_quarantine_is_in_memory_only(tmp_path):
    """Building the loader NEVER writes code_detectors.json -- in-memory only, so
    the S0 byte-frozen artifact stays untouched (bomb present or not)."""
    real = _KNOWLEDGE_DIR / "code_detectors.json"
    before = real.read_bytes()
    KnowledgeLoader()  # real corpus: runs the quarantine over 41 clean detectors
    assert real.read_bytes() == before

    # Even a corpus that DOES quarantine leaves its own on-disk file unwritten.
    corpus = _write_corpus(tmp_path, [_detector(
        "cd-test-redos_bomb", "redos_bomb", r"(a|ab)+"
    )])
    copy_bytes = (corpus / "code_detectors.json").read_bytes()
    KnowledgeLoader(corpus)
    assert (corpus / "code_detectors.json").read_bytes() == copy_bytes


# ===========================================================================
# Firewall -- Hyperion stands alone.
# ===========================================================================

def test_import_firewall_intact():
    for name in list(sys.modules):
        root = name.split(".", 1)[0]
        assert root not in ("othrys", "coeus", "mnemos", "theia", "themis"), name
