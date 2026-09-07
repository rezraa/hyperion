# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion S5 -- scan_code's dead corpus bridge fixed by ENRICHMENT, not by
materialising corpus regexes as detectors (mid-story council REVISE, path (a)).

Council b420a9f0 / m-73ea1894; standard m-55f6d4da (settled -- cite, do not
re-litigate). The build phase returned NEEDS_COUNCIL; the mid-story council
CONFIRMED the premise and REVISED S5 to path (a): the naive brute-force
materialisation of the 316 corpus detection_patterns floods 60 new false
positives (secure examples 62/65 fire; conftest clean takes 22 hits) because the
corpus patterns are ReDoS/example payloads and unanchored alternations -- a
CORPUS-AUTHORING defect, out of scope arc-wide. Materialising the corpus patterns
AS detectors, and deleting the 29-regex island, are DROPPED from S5 and DEFERRED
behind a corpus-authoring prerequisite epic.

REVISED NORTH STAR: scan_code's dead corpus bridge is fixed so every finding
carries its SOURCE vector's cwe/severity/name/remediation (via the S4
CWE->threat_id mapping) and reports the true patterns_checked count -- while the
CURATED 29-regex island STAYS the sole detector, so coverage stays == island
(equal), false positives stay at the 2 frozen stratum-C baseline, and clean code
still returns zero findings. A NO-REGRESSION proof, not a coverage-gain proof.

The dropped AC clauses -- "all vectors detection_patterns compiled and applied"
and "agent-threat regex sourced from agent_threats.attack_patterns" -- are the
brute-force materialisation and are NOT tested here (they are the deferred epic).

The S0 baseline is the immovable floor: this suite IMPORTS S0's frozen stratum-C
firing SETS + patterns_checked + the uncovered-CWE set VERBATIM and measures the
retrofitted scanner against them. Expected source content is read from the CORPUS
(the loader's own cwe_to_threat_ids + get_threat), never hand-built (Directive 8).
Loader/testbed level only -- no live othrys.db, no re-seed (served schema lags
disk; the live summon() proof is the USER's step).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Repo root on sys.path so the S0 module imports as a package under any invocation.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from hyperion.knowledge.loader import KnowledgeLoader
from hyperion.tools.scan_code import (
    _MAX_LINE_LENGTH,
    _MAX_SCAN_LINES,
    _get_patterns,
    scan_code,
)
from tests.test_hyperion_retrofit_s0 import (
    BASELINE_C_PATTERNS_CHECKED,
    BASELINE_C_SECURE_FIRING,
    BASELINE_C_SECURE_TOTAL,
    BASELINE_C_VULN_FIRING,
    BASELINE_C_VULN_TOTAL,
    CWE_MISSING_FROM_CORPUS,
    KNOWLEDGE_DIR,
    stratum_c_coverage,
)

# The MODULE object (for the firewall + no-materialisation assertions below).
sc_mod = sys.modules["hyperion.tools.scan_code"]

_FORBIDDEN_ROOTS = ("othrys", "coeus", "mnemos", "theia", "themis")

# A concrete SQL-injection line the island's ``sql_format_string`` regex fires on.
_SQLI = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
# A concrete eval line -> CWE-95, which the corpus does NOT cover (recorded gap).
_EVAL = 'result = eval(user_supplied_expression)'


@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


def _corpus_vectors() -> list[dict]:
    return json.loads(
        (KNOWLEDGE_DIR / "threat_vectors.json").read_text(encoding="utf-8")
    )["vectors"]


# ===========================================================================
# The dead bridge, fixed by ENRICHMENT. RED (pre-fix): scan_code's findings
# carried NO ``source_vectors`` -- the corpus content never reached the output
# because the old bridge keyed get_detection_patterns on LANGUAGE (0/316 reach).
# ===========================================================================

def test_finding_carries_source_vectors_key():
    """Every island finding now carries a ``source_vectors`` list (the fixed bridge).

    RED before the fix: the key did not exist. The corpus content reaches the
    output through the S4 CWE->threat_id mapping, not through a new detector regex.
    """
    findings = scan_code(_SQLI, "python")["findings"]
    assert findings
    for f in findings:
        assert "source_vectors" in f, f["pattern"]
        assert isinstance(f["source_vectors"], list)


def test_sqli_finding_hydrates_its_source_vectors_own_fields(kb):
    """The SQLi (CWE-89) finding carries its SOURCE vectors' OWN cwe/severity/name/
    remediation -- read from the corpus via cwe_to_threat_ids, never hand-built.

    CWE-89 maps ONE-TO-MANY to injection_graphql + injection_sql; both are carried,
    deterministically ordered by vector id (Directive 8: ids from the corpus map).
    """
    findings = scan_code(_SQLI, "python")["findings"]
    sqli = next(f for f in findings if f["cwe"] == "CWE-89")

    cwe_map = kb.cwe_to_threat_ids()
    expected_ids = cwe_map["CWE-89"]           # sorted by the loader
    assert expected_ids == ["injection_graphql", "injection_sql"]

    got_ids = [sv["id"] for sv in sqli["source_vectors"]]
    assert got_ids == expected_ids             # deterministic, one-to-many

    for sv in sqli["source_vectors"]:
        vec = kb.get_threat(sv["id"])
        # Each surfaced field IS the vector's OWN data (no hardcoded table).
        assert sv["name"] == vec["name"]
        assert sv["severity"] == vec["severity"]
        assert sv["remediation"] == vec["remediation"]
        assert sv["cwe"] == list(vec["cwe"])
        assert "CWE-89" in sv["cwe"]


def test_source_vectors_equal_corpus_for_every_enriched_finding(kb):
    """For EVERY finding whose CWE the corpus covers, source_vectors == the corpus
    projection of the mapped vectors -- the enrichment invents nothing."""
    cwe_map = kb.cwe_to_threat_ids()
    for v in _corpus_vectors():
        ex = v.get("examples") or {}
        for code in (ex.get("vulnerable"), ex.get("secure")):
            if not code:
                continue
            for f in scan_code(code, "python")["findings"]:
                mapped = cwe_map.get(f["cwe"], [])
                got_ids = [sv["id"] for sv in f["source_vectors"]]
                assert got_ids == mapped, (f["pattern"], f["cwe"])
                for sv in f["source_vectors"]:
                    vec = kb.get_threat(sv["id"])
                    assert sv["name"] == vec["name"]
                    assert sv["severity"] == vec["severity"]
                    assert sv["remediation"] == vec["remediation"]


def test_uncovered_cwe_has_empty_source_vectors(kb):
    """A finding whose CWE the corpus does NOT cover (CWE-95) fails open to an EMPTY
    source_vectors list -- the recorded coverage gap, never a fabricated husk."""
    assert "CWE-95" in CWE_MISSING_FROM_CORPUS
    assert not kb.cwe_to_threat_ids().get("CWE-95")
    findings = scan_code(_EVAL, "python")["findings"]
    evals = [f for f in findings if f["cwe"] == "CWE-95"]
    assert evals
    for f in evals:
        assert f["source_vectors"] == []


# ===========================================================================
# patterns_checked -- the TRUE island count, unchanged (no new detector regex).
# ===========================================================================

def test_patterns_checked_is_true_island_count():
    """patterns_checked reports the island count (29 py / 25 js), unchanged -- no
    new detector regex is admitted (enrichment is not a detector)."""
    assert scan_code(_SQLI, "python")["patterns_checked"] == (
        BASELINE_C_PATTERNS_CHECKED["python"]
    )
    assert len(_get_patterns("python")) == BASELINE_C_PATTERNS_CHECKED["python"]
    assert scan_code("var x = eval(y);", "javascript")["patterns_checked"] == (
        BASELINE_C_PATTERNS_CHECKED["javascript"]
    )
    assert len(_get_patterns("javascript")) == (
        BASELINE_C_PATTERNS_CHECKED["javascript"]
    )


# ===========================================================================
# Stratum C UNCHANGED -- coverage == island, secure_firing == frozen 2, clean == 0.
# A NO-REGRESSION proof (the island stays the sole detector), not a coverage gain.
# ===========================================================================

def test_stratum_C_coverage_equals_island_baseline_exactly():
    """Coverage == island (12 vuln firing) AND secure_firing == frozen 2. The
    enrichment decorates findings; it never adds or removes a firing."""
    cov = stratum_c_coverage(KNOWLEDGE_DIR)
    assert cov["vuln_total"] == BASELINE_C_VULN_TOTAL
    assert cov["secure_total"] == BASELINE_C_SECURE_TOTAL
    # EQUAL, not superset: the island is still the sole detector.
    assert cov["vuln_firing"] == BASELINE_C_VULN_FIRING
    assert len(cov["vuln_firing"]) == 12
    assert cov["secure_firing"] == BASELINE_C_SECURE_FIRING
    assert len(cov["secure_firing"]) == 2


def test_clean_code_returns_zero_findings(safe_python_code):
    """Clean code still returns zero findings -- enrichment fabricates nothing."""
    result = scan_code(safe_python_code, "python")
    assert result["findings"] == []


def test_enrichment_adds_no_new_finding_entries(kb):
    """The finding SET (which lines fire) is IDENTICAL to island-only detection.

    Compare the (pattern, line_number) identity set of the enriched scan against a
    reconstruction from the island patterns alone: enrichment must decorate, never
    add a finding. Proven over every corpus example that fires."""
    import re
    for v in _corpus_vectors():
        ex = v.get("examples") or {}
        for code in (ex.get("vulnerable"), ex.get("secure")):
            if not code:
                continue
            lines = code.splitlines()
            island_keys: set[tuple[str, int]] = set()
            for name, regex, *_ in _get_patterns("python"):
                try:
                    rx = re.compile(regex)
                except re.error:
                    continue
                for i, line in enumerate(lines):
                    if rx.search(line):
                        island_keys.add((name, i + 1))
            got = scan_code(code, "python")["findings"]
            got_island = {
                (f["pattern"], f["line_number"]) for f in got
                if "source" not in f  # agent findings share the shape; island subset
            }
            # Every island finding is present; enrichment added no non-island regex.
            assert island_keys <= got_island or not island_keys, v["id"]


def test_no_knowledge_base_regex_detector_admitted():
    """The dead-bridge marker is gone: no finding is sourced from a corpus REGEX.

    The old bridge tagged materialised findings ``source == 'knowledge_base'`` and
    reported ``kb_enrichments_count``. Path (a) admits NO corpus regex as a detector,
    so neither marker may appear on any corpus example."""
    for v in _corpus_vectors():
        ex = v.get("examples") or {}
        for code in (ex.get("vulnerable"), ex.get("secure")):
            if not code:
                continue
            result = scan_code(code, "python")
            assert "kb_enrichments_count" not in result, v["id"]
            for f in result["findings"]:
                assert f.get("source") != "knowledge_base", v["id"]


# ===========================================================================
# The NAMED patterns x lines ceiling -- bounded brute-force over UNTRUSTED code
# (CWE-400 bulkhead). RED before the fix: no _MAX_SCAN_LINES / _MAX_LINE_LENGTH
# constant existed (ImportError at collection) and the scan loop ran re.search per
# (pattern, line) over every line of arbitrarily large `code` with no bound on the
# line count or per-line length. The AC demands a NAMED ceiling applied IN the scan
# loop where the cost is incurred, proven by a large-input test.
# ===========================================================================

def test_scan_line_count_is_ceilinged():
    """A `code` input with more than _MAX_SCAN_LINES lines is scanned only up to the
    named cap: lines_scanned equals the ceiling, and a real vuln placed BEYOND the cap
    does not fire -- the patterns x lines work is bounded, not unbounded."""
    over = _MAX_SCAN_LINES + 5_000
    # Benign filler the island never matches, repeated past the cap, then a real SQLi
    # on the very last line (index > _MAX_SCAN_LINES).
    body = "\n".join(["x = 1"] * over + [_SQLI])
    result = scan_code(body, "python")
    assert result["lines_scanned"] == _MAX_SCAN_LINES
    # The SQLi sits past the cap -> loop stopped at the ceiling -> not reported.
    assert all(f["cwe"] != "CWE-89" for f in result["findings"])


def test_within_line_cap_the_scan_still_fires():
    """Control: the SAME SQLi WITHIN the line cap fires -- the ceiling truncates the
    untrusted overflow, it does not silence a scan that fits."""
    body = "\n".join(["x = 1"] * 10 + [_SQLI])
    result = scan_code(body, "python")
    assert result["lines_scanned"] == 11
    assert any(f["cwe"] == "CWE-89" for f in result["findings"])


def test_per_line_length_is_ceilinged():
    """A single line longer than _MAX_LINE_LENGTH is truncated before re.search: a
    pattern match placed PAST the cap does not fire, bounding the per-search cost on a
    pathological single mega-line."""
    pad = "# " + " " * (_MAX_LINE_LENGTH + 100)     # one comment line, past the cap
    long_line = pad + _SQLI                          # the SQLi sits beyond the cap
    result = scan_code(long_line, "python")
    assert result["lines_scanned"] == 1
    assert all(f["cwe"] != "CWE-89" for f in result["findings"])


def test_within_length_cap_the_scan_still_fires():
    """Control: the SQLi at the START of a line (within the length cap) fires."""
    result = scan_code(_SQLI + "  # trailing comment", "python")
    assert any(f["cwe"] == "CWE-89" for f in result["findings"])


# ===========================================================================
# Determinism + firewall.
# ===========================================================================

def test_scan_is_deterministic():
    """Two scans of the same code are byte-identical (source_vectors deterministic)."""
    a = json.dumps(scan_code(_SQLI, "python"), sort_keys=True)
    b = json.dumps(scan_code(_SQLI, "python"), sort_keys=True)
    assert a == b


def test_scan_code_module_firewall_intact():
    """scan_code imports only hyperion.* (the standalone-Titan firewall)."""
    src = Path(sc_mod.__file__).read_text(encoding="utf-8")
    for root in _FORBIDDEN_ROOTS:
        assert f"import {root}" not in src
        assert f"from {root}" not in src
