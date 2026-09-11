# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""grade_detector_batch -- the per-stratum MEASUREMENT arm of the promotion quality
gate (S5, story-8cd2b22f; council cca4df7c).

NORTH STAR (this tool's half): run the curated scan_code detector island UNION a
PROPOSED candidate batch over the 65 vulnerable + 65 secure stratum-C examples and
return the per-stratum firing COUNTS -- baseline (island alone) and candidate
(island + batch) -- reusing S0's stratum_c_coverage + BASELINE_C_* as the ONE
source of truth (never re-deriving 12/2). The generic othrys.admission.admit_batch
consumes the counts as plain data; this tool never decides admission and never
imports othrys.

Testbed/loader level only -- no live othrys.db, no :9876, no re-seed.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

from hyperion.knowledge.loader import _KNOWLEDGE_DIR, KnowledgeLoader
from hyperion.tools.grade_detector_batch import (
    BASELINE_C_SECURE_FIRING,
    BASELINE_C_SECURE_TOTAL,
    BASELINE_C_VULN_FIRING,
    BASELINE_C_VULN_TOTAL,
    grade_detector_batch,
    stratum_c_coverage,
)

_KDIR = Path(_KNOWLEDGE_DIR)
_FORBIDDEN_ROOTS = ("othrys", "coeus", "mnemos", "theia", "themis")

# The module object -- for the firewall assertion below.
gdb_mod = sys.modules["hyperion.tools.grade_detector_batch"]


def _det(regex: str, **over) -> dict:
    """A minimal well-formed candidate detector carrying only a regex + overrides."""
    d = {"regex": regex, "languages": ["*"], "name": "probe",
         "base_severity": "high", "cwe": "CWE-0", "description": "d", "remediation": "r"}
    d.update(over)
    return d


def _find_gain_token() -> str:
    """A token in a currently-MISSED vulnerable example, absent from EVERY secure
    example -- so a detector matching it raises vuln recall without adding a false
    positive. Computed from the live corpus so it survives corpus edits."""
    cov = stratum_c_coverage()
    vectors = json.loads(
        (_KDIR / "threat_vectors.json").read_text(encoding="utf-8")
    )["vectors"]
    secure_blob = "\n".join((v.get("examples") or {}).get("secure", "") for v in vectors)
    for v in vectors:
        ex = v.get("examples") or {}
        vuln = ex.get("vulnerable")
        if not vuln or v["id"] in cov["vuln_firing"]:
            continue
        for tok in sorted(set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,}", vuln)),
                          key=len, reverse=True):
            if tok not in secure_blob:
                return tok
    pytest.skip("no clean gain token in the current corpus")


# ===========================================================================
# Baseline arm -- reuses S0's frozen 12/2 (no re-hardcoded floor).
# ===========================================================================

def test_baseline_arm_reuses_S0_frozen_sets():
    """stratum_c_coverage (the ONE source of truth) reproduces the frozen S0
    stratum-C floor EXACTLY -- 12 vuln firing, 2 secure firing, 65/65."""
    cov = stratum_c_coverage()
    assert cov["vuln_firing"] == BASELINE_C_VULN_FIRING
    assert cov["secure_firing"] == BASELINE_C_SECURE_FIRING
    assert cov["vuln_total"] == BASELINE_C_VULN_TOTAL == 65
    assert cov["secure_total"] == BASELINE_C_SECURE_TOTAL == 65
    assert len(BASELINE_C_VULN_FIRING) == 12
    assert len(BASELINE_C_SECURE_FIRING) == 2


def test_baseline_only_batch_returns_frozen_12_2():
    """An empty batch grades the island alone: baseline == candidate == 12/2, 65/65
    -- the required proof the tool returns the frozen floor for a no-op batch."""
    g = grade_detector_batch([])
    assert g["ok"] is True
    assert g["baseline_vuln"] == 12
    assert g["baseline_secure"] == 2
    assert g["candidate_vuln"] == 12
    assert g["candidate_secure"] == 2
    assert g["vuln_total"] == 65
    assert g["secure_total"] == 65


def test_none_batch_equals_empty_batch():
    """No batch argument grades the island alone, identical to an empty list."""
    assert grade_detector_batch() == grade_detector_batch([])


# ===========================================================================
# Candidate arm -- the augmentation seam actually changes the counts.
# ===========================================================================

def test_candidate_batch_detects_a_genuine_gain():
    """A detector matching a missed vulnerable example (token absent from every
    secure example) RAISES candidate_vuln above baseline WITHOUT raising the FP
    count -- proof the candidate arm measures a real per-stratum gain."""
    token = _find_gain_token()
    g = grade_detector_batch([_det(re.escape(token))])
    assert g["ok"] is True
    assert g["candidate_vuln"] > g["baseline_vuln"]      # strict recall gain
    assert g["candidate_secure"] == g["baseline_secure"] == 2  # no new false positive


def test_fp_flooding_batch_raises_secure_firing():
    """A broad detector that fires on secure code (the 316-net hazard in miniature)
    drives candidate_secure ABOVE the frozen 2 -- so the gate can see the FP flood
    the pooled/recall-only view would miss."""
    g = grade_detector_batch([_det(r"[a-z]")])
    assert g["ok"] is True
    assert g["candidate_secure"] > 2
    assert g["candidate_secure"] > g["baseline_secure"]


def test_redos_candidate_is_quarantined_no_gain():
    """A catastrophic-backtracking candidate regex is ReDoS-quarantined at load, so
    it enters NO active detector set and the grade is unchanged (fail closed) -- the
    grader inherits S4's quarantine, it does not admit an unsafe regex."""
    g = grade_detector_batch([_det(r"(a+)+$")])
    assert g["candidate_vuln"] == g["baseline_vuln"]
    assert g["candidate_secure"] == g["baseline_secure"]


# ===========================================================================
# Robustness + verify-before-trust.
# ===========================================================================

def test_batch_alias_accepted():
    """A caller may pass the batch as ``batch=`` (aliased to candidate_batch)."""
    assert grade_detector_batch(batch=[]) == grade_detector_batch([])


def test_malformed_candidates_ignored_not_crashed():
    """A non-dict entry and a dict without a regex are skipped, never crash the
    scan; the grade falls back to the baseline counts."""
    g = grade_detector_batch(["not-a-dict", {"name": "no-regex"}, {"regex": ""}])
    assert g["ok"] is True
    assert g["candidate_vuln"] == g["baseline_vuln"] == 12
    assert g["candidate_secure"] == g["baseline_secure"] == 2


def test_string_json_batch_is_coerced():
    """MCP transport may flatten the list to a JSON string; it is coerced back."""
    g = grade_detector_batch(json.dumps([]))
    assert g["ok"] is True and g["candidate_vuln"] == 12


# ===========================================================================
# The KnowledgeLoader grading seam.
# ===========================================================================

def test_extra_code_detectors_enter_the_active_set():
    """The loader's extra_code_detectors seam routes a candidate into the SAME
    per-language scan set as the shipped island (additive; baseline unchanged)."""
    base = len(KnowledgeLoader().get_code_detectors("python"))
    aug = KnowledgeLoader(extra_code_detectors=[_det(r"unique_probe_token")])
    assert len(aug.get_code_detectors("python")) == base + 1
    # A fresh default loader is unaffected (in-memory only, disk untouched).
    assert len(KnowledgeLoader().get_code_detectors("python")) == base


def test_extra_detectors_none_is_byte_identical_baseline():
    """extra_code_detectors=None loads exactly the shipped island."""
    assert (len(KnowledgeLoader(extra_code_detectors=None).get_code_detectors("python"))
            == len(KnowledgeLoader().get_code_detectors("python")))


# ===========================================================================
# CWE-400 -- the candidate batch carries a NAMED ceiling (F1, finding f-7eded2e98ab8).
# ===========================================================================

def test_over_ceiling_batch_refused_fail_closed():
    """A batch larger than _MAX_CANDIDATE_BATCH is REFUSED fail-closed -- not graded,
    not truncated. The augmented arm's cost is linear in batch size (a 5000-detector
    batch took ~50s), so an over-ceiling batch is a CWE-400 vector and is rejected at
    the point the input is read, never partially measured."""
    from hyperion.tools.grade_detector_batch import _MAX_CANDIDATE_BATCH
    oversized = [_det(re.escape(f"__probe_{i}__")) for i in range(_MAX_CANDIDATE_BATCH + 1)]
    g = grade_detector_batch(oversized)
    assert g["ok"] is False
    assert "ceiling" in g["reason"].lower() or "too large" in g["reason"].lower()
    # Refused, NOT graded: no per-stratum counts are produced for an over-ceiling batch.
    assert "candidate_secure" not in g and "candidate_vuln" not in g


def test_at_ceiling_batch_still_grades():
    """A batch exactly AT the ceiling still grades -- the bound refuses only ABOVE it,
    it does not truncate an at-ceiling batch."""
    from hyperion.tools.grade_detector_batch import _MAX_CANDIDATE_BATCH
    at = [_det(re.escape(f"__no_match_token_{i}__")) for i in range(_MAX_CANDIDATE_BATCH)]
    g = grade_detector_batch(at)
    assert g["ok"] is True
    assert len(at) == _MAX_CANDIDATE_BATCH
    # Non-matching tokens: no gain, counts fall back to the frozen baseline.
    assert g["candidate_vuln"] == g["baseline_vuln"] == 12
    assert g["candidate_secure"] == g["baseline_secure"] == 2


# ===========================================================================
# MEASUREMENT INTEGRITY -- an incomplete augmented scan fails CLOSED (F2, the
# important half of finding f-7eded2e98ab8). scan_code fails OPEN on a per-match
# ReDoS timeout (it DROPS the finding); a dropped SECURE finding under-counts the
# false-positive count -- the ONE direction that admits a batch that should be
# rejected -- so the grade must refuse rather than certify an under-counted FP.
# ===========================================================================

def _secure_examples() -> set[str]:
    vectors = json.loads((_KDIR / "threat_vectors.json").read_text(encoding="utf-8"))["vectors"]
    return {(v.get("examples") or {}).get("secure") for v in vectors} - {None, ""}


def test_augmented_incomplete_scan_fails_closed(monkeypatch):
    """A candidate whose scan on a SECURE example is INCOMPLETE (timed out) makes the
    grade return ok:False with the reason -- AND the OLD behaviour (ignore incomplete,
    count findings-only) would have UNDER-counted the FP and admitted (failing-first)."""
    import hyperion.tools.grade_detector_batch as gdb
    broad = _det(r"[a-z]")   # a real FP flood: fires on ~every secure example

    # (a) COMPLETE scan: the broad candidate floods secure examples -- candidate_secure
    # is well above the ceiling of 2, so a COMPLETE grade shows a batch that SHOULD be
    # rejected (its FP count is real and high).
    complete = grade_detector_batch([broad])
    assert complete["ok"] is True
    assert complete["candidate_secure"] > 2

    # (b) Now make scan_code TIME OUT on every secure example in the AUGMENTED arm only
    # (kb is not None): the FP finding is DROPPED (fail-open) and ``incomplete`` is
    # flagged (fail-loud). Deterministic stand-in for a real catastrophic-regex-on-a-
    # secure-example timeout under the 1s per-match deadline.
    secure = _secure_examples()
    real_scan = gdb.scan_code

    def scan_secure_timeout(code, language, kb=None):
        res = real_scan(code, language, kb=kb)
        if kb is not None and code in secure and res["findings"]:
            return {**res, "findings": [], "incomplete": True,
                    "timed_out": [{"detector": "candidate", "line": 1}], "skipped": []}
        return res

    monkeypatch.setattr(gdb, "scan_code", scan_secure_timeout)

    # NEW behaviour: the augmented arm is incomplete -> fail CLOSED, NOT graded.
    g = grade_detector_batch([broad])
    assert g["ok"] is False
    assert "incomplete" in g["reason"].lower()
    assert "candidate_secure" not in g   # no under-counted number is emitted

    # PROVE the OLD behaviour (findings-only, ignore incomplete) would UNDER-count and
    # admit: the augmented secure firing set is now emptied by the timeouts, so the OLD
    # candidate_secure would read far BELOW the complete count -- and at/under the
    # ceiling of 2, i.e. the ADMIT direction -- for the SAME broad candidate a complete
    # scan shows flooding secure. The ``incomplete`` ledger is the fail-loud signal the
    # OLD code ignored.
    aug_loader = KnowledgeLoader(extra_code_detectors=[gdb._normalise_candidate(broad, 0)])
    cov = gdb.stratum_c_coverage(loader=aug_loader)
    assert cov["incomplete"]                                    # fail-loud signal present
    old_candidate_secure = len(cov["secure_firing"])           # what the OLD code would report
    assert old_candidate_secure < complete["candidate_secure"]  # UNDER-counted
    assert old_candidate_secure <= 2                            # would pass the FP ceiling -> ADMIT


def test_baseline_arm_carries_no_incomplete_on_clean_corpus():
    """The baseline arm (shipped island, ReDoS-quarantined) grades the clean corpus
    with an EMPTY incomplete ledger -- the fail-closed path is driven only by an
    untrusted candidate batch, never by the clean island."""
    cov = stratum_c_coverage()
    assert cov["incomplete"] == []


# ===========================================================================
# Firewall -- the grader stands inside Hyperion.
# ===========================================================================

def test_module_firewall_intact():
    src = Path(gdb_mod.__file__).read_text(encoding="utf-8")
    for root in _FORBIDDEN_ROOTS:
        assert f"import {root}" not in src
        assert f"from {root}" not in src
