# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion R2 -- the frozen parity + mutation harness for the detector migration.

Council 1fee93f2 (settled -- cite, do not re-litigate).

R1 migrated the ~36 hand-written scan-detector islands (``scan_code._get_patterns``:
``_HARDCODED_SECRETS`` / ``_INSECURE_CRYPTO`` / ``_WEB_SECURITY`` /
``_INSECURE_IMPORTS_PYTHON`` / ``_INSECURE_IMPORTS_JS``, plus the 7 ``_AGENT_THREATS``)
into ``knowledge/code_detectors.json``, read through
``loader.get_code_detectors(language)``.  The data move was byte-identical
(python 29 / javascript 25).  R4 (later) DELETES the islands and rewires
``scan_code`` to read its patterns from the DB, adding the language resolution the
islands did by hand (aliases + the unknown-language "include both" fallback).

NORTH STAR: a byte-frozen, per-stratum proof that ``scan_code`` reading from the DB
fires IDENTICALLY to the islands, that BINDS (a removed / altered detector turns it
RED), and that pins the language resolution R4 must implement -- WITH the failing
case landed first.

The proof is airtight by construction: the migrated detectors are byte-identical to
the island tuples AND in the same iteration order (universal-then-language), so a
scanner iterating them produces identical findings.  R4 has now DELETED the islands
and rewired ``scan_code`` to READ the DB, and ``get_code_detectors`` RESOLVES aliased
/ unknown languages (the R1 adversarial finding).  The island firing that anchors the
RHS below is reconstructed from the byte-frozen artifact by
``tests/_hyperion_island_snapshot.island_reference`` (never a live production symbol),
so the parity + mutation proof survives the islands' deletion.  The two cases that
were R4-gated as ``xfail(strict=True)`` are now plain green.

REJECT criteria (council 1fee93f2), encoded or documented below:
  * any stratum not equal-or-superset of its island firing     -> parity tests
  * any hard-invariant fixture stops firing                      -> fixture guard
  * patterns_checked != 29 / 25                                  -> count test
  * the mutation arm stays green on a removed detector           -> mutation tests
  * the S0 answer-key sha256 changed instead of a NEW artifact   -> immovability test

Scope: loader / testbed level.  No live othrys.db, no re-seed, no production edit --
this story adds a NEW frozen artifact and tests only.  Firewall: hyperion imports
only hyperion.* (never othrys / coeus / mnemos / theia / themis).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

# Repo root on sys.path so the S0 module imports as a package under any invocation.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import hyperion.tools._shared as sh
from hyperion.knowledge.loader import _KNOWLEDGE_DIR, KnowledgeLoader
from hyperion.tools.scan_code import scan_code
from tests._hyperion_island_snapshot import (
    ISLAND_AGENT_REFERENCE,
    _detector_tuple,
    island_reference,
)
from tests.test_hyperion_retrofit_s0 import (
    ANSWER_KEY_SHA256,
    BASELINE_C_PATTERNS_CHECKED,
    BASELINE_C_SECURE_FIRING,
    BASELINE_C_SECURE_TOTAL,
    BASELINE_C_VULN_FIRING,
    BASELINE_C_VULN_TOTAL,
    KNOWLEDGE_DIR,
    _load_corpus,
    canonical,
    stratum_c_coverage,
)

# ===========================================================================
# The NEW frozen artifact -- a Stratum-C sub-arm, DISTINCT from the S0 answer key.
# The S0 answer-key sha256 (58975c63...) stays IMMOVABLE (test below); this pins
# the code_detectors.json detector SET on its OWN sha256.
# ===========================================================================

ARTIFACT_PATH = Path(__file__).parent / "_hyperion_code_detectors.json"
NEW_ARTIFACT_SHA256 = (
    "b294846ee2ee49324147c8e113e4c703cce3dadf084a244c4508ef6c73544638"
)
# The immovable S0 answer key -- must NOT be touched by this story.
_S0_ANSWER_KEY_SHA256 = (
    "58975c63ba467852e8922c8608bea04503b063cfa705ea08181c663e93db323a"
)

DETECTORS_JSON = _KNOWLEDGE_DIR / "code_detectors.json"

# Frozen post-migration counts (island parity: universal 20 + py 9 / js 5; 7 agent).
_PY_COUNT = 29
_JS_COUNT = 25
_AGENT_COUNT = 7
_TOTAL_DETECTORS = 41

# The island tuple projection (_detector_tuple) and the frozen island reconstruction
# (island_reference / ISLAND_AGENT_REFERENCE) live in the shared snapshot leaf, read
# from the byte-frozen artifact so they survive the deletion of the production islands.
def _load_detectors() -> list[dict]:
    """Load the detector list straight from JSON on disk (the source of truth)."""
    return json.loads(DETECTORS_JSON.read_text(encoding="utf-8"))["detectors"]


def _agent_detectors() -> list[dict]:
    """The 7 agent-signal-gated detectors, in file order (get_code_detectors
    excludes these -- they run only when _has_agent_signals fires)."""
    return [d for d in _load_detectors() if d.get("requires_agent_signals")]


def _firing_names(patterns, code: str) -> set[str]:
    """Return the set of detector names whose regex matches any line of *code*.

    Mirrors scan_code's per-(pattern, line) ``re.search`` on the language patterns
    only (the reference "island firing" used to locate the removed-detector cases).
    """
    names: set[str] = set()
    for name, regex, *_ in patterns:
        try:
            rx = re.compile(regex)
        except re.error:
            continue
        for line in code.splitlines():
            if rx.search(line):
                names.add(name)
                break
    return names


def _assert_loader_parity(detectors: list[dict], island_patterns: list) -> None:
    """Raise AssertionError unless *detectors* byte-match *island_patterns* in order.

    The ONE parity predicate the real parity tests AND the mutation arm both drive
    (one source of truth, so the mutation arm proves the very check the parity tests
    rely on). A count mismatch or any field mismatch raises.
    """
    assert len(detectors) == len(island_patterns), (
        len(detectors), len(island_patterns),
    )
    for d, t in zip(detectors, island_patterns):
        assert _detector_tuple(d) == tuple(t), d.get("name", "?")


@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


# ===========================================================================
# (1) The NEW frozen artifact -- byte-frozen, answer-key style, drift = RED.
# ===========================================================================

def test_new_artifact_matches_frozen_sha256():
    """code_detectors.json canonicalises to the recorded, frozen sha256."""
    doc = json.loads(DETECTORS_JSON.read_text(encoding="utf-8"))
    assert hashlib.sha256(canonical(doc).encode("utf-8")).hexdigest() == (
        NEW_ARTIFACT_SHA256
    )


def test_new_artifact_byte_identical_to_frozen_file():
    """Regenerating the canonical form from code_detectors.json is byte-for-byte the
    committed frozen artifact. If the detector set ever drifts, this fails loud."""
    doc = json.loads(DETECTORS_JSON.read_text(encoding="utf-8"))
    regenerated = canonical(doc).encode("utf-8")
    on_disk = ARTIFACT_PATH.read_bytes()
    assert regenerated == on_disk
    assert hashlib.sha256(on_disk).hexdigest() == NEW_ARTIFACT_SHA256


def test_s0_answer_key_sha256_is_immovable_and_distinct():
    """REJECT guard: the S0 answer-key sha256 is untouched (NOT re-pinned to satisfy
    this story), and the new artifact is a DISTINCT hash -- a NEW sub-arm, not an
    edit to the immovable baseline."""
    assert ANSWER_KEY_SHA256 == _S0_ANSWER_KEY_SHA256
    assert NEW_ARTIFACT_SHA256 != ANSWER_KEY_SHA256


def test_artifact_detector_totals():
    """The frozen set is the full migration: 41 detectors = 34 language + 7 agent."""
    dets = _load_detectors()
    assert len(dets) == _TOTAL_DETECTORS
    assert len(_agent_detectors()) == _AGENT_COUNT
    non_agent = [d for d in dets if not d.get("requires_agent_signals")]
    assert len(non_agent) == _TOTAL_DETECTORS - _AGENT_COUNT  # 34


# ===========================================================================
# (2) Island -> entry byte-equality map. Both languages + the 7 agent detectors.
#     Byte-identical fields AND identical order == a faithful data migration.
# ===========================================================================

def test_python_detectors_byte_identical_to_island(kb):
    """Every python detector is byte-identical to the island tuple it replaced,
    element-for-element, in island_reference order."""
    _assert_loader_parity(kb.get_code_detectors("python"), island_reference("python"))


def test_javascript_detectors_byte_identical_to_island(kb):
    """Every javascript detector is byte-identical to the island tuple it replaced,
    element-for-element, in island_reference order."""
    _assert_loader_parity(
        kb.get_code_detectors("javascript"), island_reference("javascript")
    )


def test_agent_detectors_byte_identical_to_island():
    """The 7 agent-signal-gated detectors are byte-identical to the frozen island.

    These are excluded from get_code_detectors (they run only under
    _has_agent_signals), so they are checked against the frozen artifact in file
    order (ISLAND_AGENT_REFERENCE)."""
    _assert_loader_parity(_agent_detectors(), ISLAND_AGENT_REFERENCE)


# ===========================================================================
# (3) Loader-level parity -- counts, invariants, and no shared-index aliasing.
# ===========================================================================

def test_loader_counts_match_patterns_checked(kb):
    """get_code_detectors returns exactly scan_code's patterns_checked count:
    29 python / 25 javascript (the agent island is excluded from both)."""
    assert len(kb.get_code_detectors("python")) == _PY_COUNT
    assert len(kb.get_code_detectors("javascript")) == _JS_COUNT
    assert BASELINE_C_PATTERNS_CHECKED == {"python": _PY_COUNT, "javascript": _JS_COUNT}


def test_get_code_detectors_returns_fresh_list(kb):
    """A caller cannot corrupt the shared per-language index by mutating the result."""
    first = kb.get_code_detectors("python")
    first.append({"name": "poison"})
    second = kb.get_code_detectors("python")
    assert len(second) == _PY_COUNT
    assert all(d.get("name") != "poison" for d in second)


def test_stratum_c_firing_baseline_unchanged():
    """REJECT guard: the frozen stratum-C firing SETS are intact after the migration
    (equal, never a superset regression) -- 12 vuln firing, 2 secure firing, graded
    ALONE and never pooled (m-e8ccb163)."""
    cov = stratum_c_coverage(KNOWLEDGE_DIR)
    assert cov["vuln_total"] == BASELINE_C_VULN_TOTAL
    assert cov["secure_total"] == BASELINE_C_SECURE_TOTAL
    assert cov["vuln_firing"] == BASELINE_C_VULN_FIRING
    assert len(cov["vuln_firing"]) == 12
    assert cov["secure_firing"] == BASELINE_C_SECURE_FIRING
    assert len(cov["secure_firing"]) == 2


def test_hard_invariant_fixtures_still_fire(
    vulnerable_python_sql_injection,
    vulnerable_python_command_injection,
    vulnerable_python_hardcoded_secrets,
    vulnerable_python_deserialization,
    vulnerable_javascript_xss,
):
    """REJECT guard: the curated hard-invariant fixtures still produce findings --
    no unambiguous vulnerability was dropped by the migration."""
    for code, lang in (
        (vulnerable_python_sql_injection, "python"),
        (vulnerable_python_command_injection, "python"),
        (vulnerable_python_hardcoded_secrets, "python"),
        (vulnerable_python_deserialization, "python"),
        (vulnerable_javascript_xss, "javascript"),
    ):
        assert scan_code(code, lang)["findings"], code


# ===========================================================================
# (4a) language-resolution parity (was R4-gated xfail, now plain green).
#      get_code_detectors returned [] for every non-canonical language arg before R4
#      (the R1 adversarial finding); R4 added the resolution the islands did by hand,
#      so these now pass.
# ===========================================================================

# The aliases and unknown languages the islands resolved by hand:
#   py -> python; js/typescript/ts -> javascript;  go/java/ruby -> BOTH; case-fold.
_RESOLUTION_LANGS = ("py", "js", "typescript", "ts", "go", "java", "ruby", "PYTHON")


def test_language_resolution_parity_with_islands(kb):
    """get_code_detectors(lang) must equal island_reference(lang) for aliased AND
    unknown languages -- byte-identical, in order. R4 added the resolution the islands
    did by hand, so this holds for every non-canonical arg."""
    for lang in _RESOLUTION_LANGS:
        _assert_loader_parity(kb.get_code_detectors(lang), island_reference(lang))


# ===========================================================================
# (4b) scan_code sources its patterns from the DB (was R4-gated xfail, now green).
#      Before R4 scan_code read the islands and IGNORED get_code_detectors, so a
#      detector removed from the DB still fired. R4 rewired scan_code, so the removed
#      detector stops firing.
# ===========================================================================

_REMOVED_DETECTOR = "sql_format_string"  # a universal (["*"]) detector, both langs


def _stratum_c_samples() -> list[tuple[str, str]]:
    """The stratum-C hard fixtures + every corpus example, as (code, language)."""
    samples: list[tuple[str, str]] = []
    vectors = _load_corpus(KNOWLEDGE_DIR)[0]
    for v in vectors:
        ex = v.get("examples") or {}
        for code in (ex.get("vulnerable"), ex.get("secure")):
            if code:
                samples.append((code, "python"))
    return samples


def test_scan_code_firing_tracks_the_db_not_the_islands(
    monkeypatch,
    vulnerable_python_sql_injection,
    vulnerable_javascript_xss,
):
    """scan_code's firing SET follows the DB detector set, not the frozen islands.

    Remove one universal detector from the DB and prove scan_code stops reporting it
    on every stratum-C fixture + corpus example the island fires it on. Green since R4
    sources scan_code from get_code_detectors: the removed detector never fires again.
    """
    samples = [
        (vulnerable_python_sql_injection, "python"),
        (vulnerable_javascript_xss, "javascript"),
    ] + _stratum_c_samples()

    # Reference: the samples on which the island fires the detector we will remove.
    fires_removed = [
        (code, lang)
        for code, lang in samples
        if _REMOVED_DETECTOR in _firing_names(island_reference(lang), code)
    ]
    assert fires_removed, "no sample fires the detector under test"

    # Remove the detector from the DB set scan_code reads (post-R4 seam).
    orig = KnowledgeLoader.get_code_detectors
    monkeypatch.setattr(
        KnowledgeLoader,
        "get_code_detectors",
        lambda self, language: [
            d for d in orig(self, language) if d["name"] != _REMOVED_DETECTOR
        ],
    )
    monkeypatch.setattr(sh, "_knowledge", None)  # drop the cached singleton

    # Once scan_code reads from the DB, the removed detector never fires again.
    for code, lang in fires_removed:
        firing = {f["pattern"] for f in scan_code(code, lang)["findings"]}
        assert _REMOVED_DETECTOR not in firing, (lang, code)


# ===========================================================================
# (5) Mutation arm (Directive 10) -- prove the parity check BINDS.
#     A parity test that stays green when a detector vanishes proves nothing;
#     these show the check goes RED on a removed AND on an altered detector.
# ===========================================================================

def test_mutation_removed_detector_breaks_parity(kb):
    """Removing one migrated detector makes the loader-level parity check FAIL."""
    dets = kb.get_code_detectors("python")
    mutated = [d for d in dets if d["name"] != _REMOVED_DETECTOR]
    assert len(mutated) == len(dets) - 1
    with pytest.raises(AssertionError):
        _assert_loader_parity(mutated, island_reference("python"))


def test_mutation_altered_detector_breaks_parity(kb):
    """Altering one field of one migrated detector makes the parity check FAIL."""
    dets = [dict(d) for d in kb.get_code_detectors("python")]
    dets[0] = {**dets[0], "regex": dets[0]["regex"] + "X"}  # one-byte drift
    with pytest.raises(AssertionError):
        _assert_loader_parity(dets, island_reference("python"))


def test_mutation_reordered_detectors_break_parity(kb):
    """Order matters: swapping two migrated detectors makes the parity check FAIL
    (byte-identical fields in the WRONG order would still change scan iteration)."""
    dets = list(kb.get_code_detectors("python"))
    dets[0], dets[1] = dets[1], dets[0]
    with pytest.raises(AssertionError):
        _assert_loader_parity(dets, island_reference("python"))


# ===========================================================================
# Firewall -- Hyperion stands alone.
# ===========================================================================

def test_import_firewall_intact():
    for name in list(sys.modules):
        root = name.split(".", 1)[0]
        assert root not in ("othrys", "coeus", "mnemos", "theia", "themis"), name
