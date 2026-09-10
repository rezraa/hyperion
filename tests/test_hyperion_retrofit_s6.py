# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion S6 -- delete the matcher + recognition islands at zero callers, and
reconcile the drifted server.py duplicate to a SINGLE source (no shim).

Council b420a9f0 / m-73ea1894; AMENDED by mid-story council 5eec34ab (S5 rescoped
to ENRICHMENT -> the 29-regex scan island is the PERMANENT sole detector).

NORTH STAR: one source of truth per concept. The substring matcher
(``match_structural_signals``) and every recognition-side island are GONE at zero
production callers, and server.py no longer carries a second, drifted copy of the
tool bodies -- ``scan_code`` / ``assess_threat`` / ``plan_remediation`` delegate to
the single filed source (as ``get_signal_index`` already does), no shim. The scan
detector island STAYS as the permanent sole detector; all three S0 strata still
meet their frozen floors.

RED-by-construction against pre-S6 code: before this story server.py's inline
``scan_code`` returned ``{target, language, findings:[{type,cwe,severity,name,
detail,line_hint,evidence}], summary:{total,...}}`` while the filed tool returns
``{findings:[{pattern,...}], summary:{critical,high,medium,low}, risk_score,
lines_scanned, patterns_checked}`` -- the delegation-parity assertions below fail on
that drift, and the deletion assertions fail while the matcher/islands exist.

Loader/testbed level only -- no live othrys.db, no re-seed (served schema lags disk;
the live summon() proof is the USER's post-re-seed step).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

import hyperion.server as server
from hyperion.knowledge.loader import KnowledgeLoader
from hyperion.tools.assess_threat import assess_threat as filed_assess_threat
from hyperion.tools.get_signal_index import get_signal_index as filed_get_signal_index
from hyperion.tools.plan_remediation import plan_remediation as filed_plan_remediation
from hyperion.tools.scan_code import scan_code as filed_scan_code
from tests.test_hyperion_retrofit_s0 import (
    BASELINE_A_COMBINED,
    BASELINE_A_LEG1,
    BASELINE_A_LEG2,
    BASELINE_B,
    BASELINE_C_PATTERNS_CHECKED,
    BASELINE_C_SECURE_FIRING,
    BASELINE_C_SECURE_TOTAL,
    BASELINE_C_VULN_FIRING,
    BASELINE_C_VULN_TOTAL,
    KNOWLEDGE_DIR,
    build_answer_key,
    stratum_c_coverage,
)
from tests.test_hyperion_retrofit_s2 import _recall  # accessor recall (production path)

# The package re-exports each tool function under its dotted name, shadowing the
# submodule attribute; reach the real module objects via sys.modules (S4 precedent).
scan_mod = sys.modules["hyperion.tools.scan_code"]
_SRC = Path(scan_mod.__file__).resolve().parents[2]  # .../src

# The recognition-side symbols deleted at S6, plus the scan-detector islands deleted
# at R4 (council 49fd71da): scan_code now reads its detectors from the DB
# (get_code_detectors / get_agent_code_detectors), so _get_patterns and the six island
# lists are gone. The agent-signal GATE (_AGENT_SIGNAL_KEYWORDS / _has_agent_signals)
# is control logic, not a detector, and STAYS in scan_code -- so it is NOT listed here.
_DELETED_RECOGNITION_SYMBOLS = (
    "match_structural_signals",
    "_DECISION_RULES",
    "_AGENT_THREAT_PATTERNS",
    "_AGENT_SIGNALS",
    "_REMEDIATIONS",
    "_GENERIC_REMEDIATION",
    "_RISK_LEVELS",
    "_rule_signal_index",
    # R4: the deleted scan-detector islands + their per-language builder.
    "_get_patterns",
    "_HARDCODED_SECRETS",
    "_INSECURE_IMPORTS_PYTHON",
    "_INSECURE_IMPORTS_JS",
    "_INSECURE_CRYPTO",
    "_WEB_SECURITY",
    "_AGENT_THREATS",
)


@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


@pytest.fixture()
def answer_key() -> dict:
    return build_answer_key(KNOWLEDGE_DIR)


# ===========================================================================
# server.py delegates to the ONE filed source (no drifted second body, no shim).
# ===========================================================================

def test_server_scan_code_delegates_to_filed_body():
    code = 'password = "hunter2test"\nimport os\nos.system(user_input)\neval(x)'
    assert server.scan_code(code, "python") == filed_scan_code(code, "python")


def test_server_assess_threat_delegates_to_filed_body():
    sid = filed_get_signal_index()["threat_signals"][0]["signal_id"]
    assert server.assess_threat("sys", [sid]) == filed_assess_threat("sys", [sid])


def test_server_plan_remediation_delegates_to_filed_body():
    finding = {"threat_id": "injection_sql"}
    assert server.plan_remediation(finding) == filed_plan_remediation(finding)


def test_server_get_signal_index_delegates_to_filed_body():
    assert server.get_signal_index() == filed_get_signal_index()


def test_server_signatures_are_the_filed_retrofit_contract():
    """The reconciled server tools expose the filed retrofit signature, not the
    retired drifted one (no ``structural_signals`` / ``assets`` / ``language`` shim)."""
    import inspect

    assess_params = list(inspect.signature(server.assess_threat).parameters)
    assert "matched_signal_ids" in assess_params
    assert "structural_signals" not in assess_params
    assert "assets" not in assess_params

    plan_params = list(inspect.signature(server.plan_remediation).parameters)
    assert "language" not in plan_params
    assert "constraints" not in plan_params


def test_server_carries_no_inline_scan_island():
    """The drifted inline detector tables are gone from server.py -- the scanner's
    one source of truth is the filed module."""
    assert not hasattr(server, "_SCAN_PATTERNS")
    assert not hasattr(server, "_CWE_DB")


# ===========================================================================
# The matcher + recognition islands are deleted at zero callers, no shim.
# ===========================================================================

def test_matcher_deleted_from_loader():
    assert not hasattr(KnowledgeLoader, "match_structural_signals")


def test_no_deleted_recognition_symbol_referenced_in_src():
    """Grep proves zero references (definition, assignment, call or import) to any
    deleted recognition-side symbol anywhere under src/hyperion -- docstrings scrubbed
    too, so a bare-name grep is clean."""
    offenders: dict[str, list[str]] = {}
    for py in sorted((_SRC / "hyperion").rglob("*.py")):
        text = py.read_text(encoding="utf-8")
        hits = [sym for sym in _DELETED_RECOGNITION_SYMBOLS if sym in text]
        if hits:
            offenders[str(py.relative_to(_SRC))] = hits
    assert not offenders, f"deleted recognition-side symbols still referenced: {offenders}"


def test_no_shim_or_alias_reintroduced():
    """No deprecation shim: the retired prose/language params are not re-added as
    aliases on the filed tools, and the loader exposes no matcher alias."""
    import inspect

    assert not hasattr(KnowledgeLoader, "match_structural_signals")
    assess_params = list(inspect.signature(filed_assess_threat).parameters)
    plan_params = list(inspect.signature(filed_plan_remediation).parameters)
    assert "structural_signals" not in assess_params
    assert "language" not in plan_params


# ===========================================================================
# The scan detector islands are DELETED (R4) -- scan_code reads the DB. The agent
# signal gate stays (control logic, not a detector); a known vuln still fires.
# ===========================================================================

def test_scan_detector_island_deleted(kb):
    """R4 (council 49fd71da): _get_patterns and the six island lists are gone from
    scan_code -- the detectors now come from the DB (get_code_detectors). The
    agent-signal GATE stays (control logic, not a detector), the per-language counts
    are the frozen 29 / 25, and a known vulnerability still fires."""
    for sym in (
        "_get_patterns", "_HARDCODED_SECRETS", "_INSECURE_IMPORTS_PYTHON",
        "_INSECURE_IMPORTS_JS", "_INSECURE_CRYPTO", "_WEB_SECURITY",
        "_AGENT_THREATS",
    ):
        assert not hasattr(scan_mod, sym), sym
    # The agent-signal gate is control logic, not a detector -- it STAYS.
    assert hasattr(scan_mod, "_AGENT_SIGNAL_KEYWORDS")
    assert hasattr(scan_mod, "_has_agent_signals")
    # The DB is now the sole detector source, at the frozen per-language counts.
    assert len(kb.get_code_detectors("python")) == BASELINE_C_PATTERNS_CHECKED["python"]
    assert len(kb.get_code_detectors("javascript")) == (
        BASELINE_C_PATTERNS_CHECKED["javascript"]
    )
    # A known vulnerability still fires through the DB detector set.
    assert filed_scan_code("eval(user_input)", "python")["findings"]


# ===========================================================================
# Per-stratum re-run holds >= S0 on ALL THREE strata (never pooled), via the
# PRODUCTION recognition surface (accessor + hydrate) and the scan detector.
# ===========================================================================

def test_stratum_A_floor_holds_via_accessor(kb, answer_key):
    view = filed_get_signal_index()["threat_signals"]
    leg1 = _recall(kb.hydrate, view, answer_key["stratum_A"]["leg1_vector_signals"])
    leg2 = _recall(kb.hydrate, view, answer_key["stratum_A"]["leg2_decision_rules"])
    combined = (leg1[0] + leg2[0], leg1[1] + leg2[1])
    assert leg1[0] >= BASELINE_A_LEG1[0], (leg1, BASELINE_A_LEG1)
    assert leg2[0] >= BASELINE_A_LEG2[0], (leg2, BASELINE_A_LEG2)
    assert combined[0] >= BASELINE_A_COMBINED[0], (combined, BASELINE_A_COMBINED)


def test_stratum_B_floor_holds_via_accessor(kb, answer_key):
    view = filed_get_signal_index()["agent_threat_signals"]
    legb = _recall(kb.hydrate_agent, view, answer_key["stratum_B"]["agent_detection_signals"])
    assert legb[0] >= BASELINE_B[0], (legb, BASELINE_B)


def test_stratum_C_floor_holds_via_scan_detector():
    cov = stratum_c_coverage(KNOWLEDGE_DIR)
    assert cov["vuln_total"] == BASELINE_C_VULN_TOTAL
    assert cov["secure_total"] == BASELINE_C_SECURE_TOTAL
    # Coverage equals-or-beats the frozen island firing set; NO new secure-example
    # false positive beyond the frozen two.
    assert cov["vuln_firing"] >= BASELINE_C_VULN_FIRING
    assert cov["secure_firing"] == BASELINE_C_SECURE_FIRING


# ===========================================================================
# monitor_threat / log_finding untouched (pure engines, out of S6 scope).
# ===========================================================================

def test_monitor_threat_and_log_finding_still_serve(tmp_path, monkeypatch):
    pb = server.monitor_threat("prompt_injection")
    assert pb["threat_type"] == "prompt_injection"
    assert "playbook" in pb and pb["severity"] == "CRITICAL"

    logged = server.log_finding("code_scan", "t", "HIGH", "CWE-89")
    assert logged["logged"] is True and logged["finding_id"]


# ===========================================================================
# Firewall (standalone Titan) -- covered in full by test_firewall.py's AST scan
# over all of src/hyperion, which now includes the reconciled server.py.
# ===========================================================================

def test_server_module_imports_no_sibling():
    tree = ast.parse(Path(server.__file__).read_text(encoding="utf-8"))
    forbidden = ("othrys", "coeus", "mnemos", "theia", "themis")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] not in forbidden, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in forbidden, node.module
