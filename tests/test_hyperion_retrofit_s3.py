# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion S3 -- assess_threat retrofit onto hydrate; islands deleted.

Council b420a9f0 / m-73ea1894; standard m-55f6d4da (settled -- do not re-litigate).
Precedent mirrored: the Coeus/Mnemos four-step tool retrofit (retrieve via
matched_signal_ids+hydrate -> optional deterministic gate -> reason over each
node's OWN fields -> fail-closed envelope; islands + matcher deleted LAST).

NORTH STAR: assess_threat recognises a caller's signals against get_signal_index
(matched_signal_ids) and returns a ``threat_model`` hydrated from the 65
threat_vectors' OWN fields (cwe, owasp, mitre_attack, severity, attack_surface,
remediation) plus ``agent_risks`` hydrated from the 13 agent_threats (mitigation,
attack_patterns) through the four-state fail-closed envelope, so natural-language
signals no longer yield an empty model and no hardcoded island survives in the
tool's path.

The S0 baseline is the immovable floor: this suite IMPORTS S0's frozen baseline
+ query set VERBATIM and measures the retrofitted TOOL on the SAME frozen queries.
All positive-case signal ids are obtained from the ACCESSOR's OWN output, never
hand-built (Directive 8). Loader/testbed level only -- no live othrys.db, no
re-seed (served schema lags disk; the live summon() proof is the USER's step).
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

import hyperion.tools.assess_threat as at_mod
from hyperion.knowledge.loader import KnowledgeLoader
from hyperion.tools._shared import _MAX_MATCHED_SIGNALS
from hyperion.tools.assess_threat import assess_threat
from hyperion.tools.get_signal_index import get_signal_index
from tests.test_hyperion_retrofit_s0 import (
    BASELINE_A_LEG1,
    KNOWLEDGE_DIR,
    RECALL_K,
    _load_corpus,
)

# The reproduced-premise signal: verbatim injection_sql.signals[0] -- the natural-
# language signal S0 measured returning an EMPTY threat_model on the old matcher.
_SQL_SIGNAL = "user input concatenated into SQL query string"
_SQL_VECTOR = "injection_sql"


# ===========================================================================
# Recognition helpers -- ids from the accessor's OWN output (Directive 8).
# ===========================================================================

@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


@pytest.fixture()
def nested() -> dict:
    return get_signal_index()


def _text_to_sid(view: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for entry in view:
        out.setdefault(entry["signal_text"].strip(), entry["signal_id"])
    return out


def _tool_threat_ids(sid: str, k: int = RECALL_K) -> list[str]:
    """The threat_model ids the retrofitted TOOL returns for one recognised sid."""
    return [e["id"] for e in assess_threat("sys", [sid], k=k)["threat_model"]]


def _tool_agent_ids(sid: str, k: int = RECALL_K) -> list[str]:
    return [e["id"] for e in assess_threat("sys", [sid], k=k)["agent_risks"]]


# ===========================================================================
# New contract: retrieve via matched_signal_ids (the retired prose param is gone).
# ===========================================================================

def test_signature_is_matched_signal_ids_no_prose_shim():
    import inspect

    params = list(inspect.signature(assess_threat).parameters)
    assert "matched_signal_ids" in params
    assert "structural_signals" not in params  # retired, no alias shim
    assert "assets" not in params              # fabricated impact map dropped


# ===========================================================================
# The reproduced S0 premise: the natural-language signal now hydrates a model.
# (The pre-fix matcher re-execution was retired with the matcher at S6; the S0
# leg1 18/240 floor stays frozen and is enforced via the accessor below.)
# ===========================================================================

def test_premise_natural_language_signal_hydrates_post_fix(nested):
    """POST-FIX: recognised against the accessor, the SAME signal yields a
    NON-EMPTY threat_model containing injection_sql -- the empty model is gone."""
    sid = _text_to_sid(nested["threat_signals"])[_SQL_SIGNAL]
    result = assess_threat("web api with a sql database", [sid])
    assert result["threat_model"], "natural-language signal must yield a model"
    assert _SQL_VECTOR in [e["id"] for e in result["threat_model"]]
    assert result["threat_retrieval_state"] in ("hit", "low_confidence")


# ===========================================================================
# threat_model carries the hydrated vector's OWN fields (no hardcoded table).
# ===========================================================================

def test_threat_model_entries_carry_vectors_own_fields(kb, nested):
    sid = _text_to_sid(nested["threat_signals"])[_SQL_SIGNAL]
    entry = next(
        e for e in assess_threat("sys", [sid])["threat_model"] if e["id"] == _SQL_VECTOR
    )
    vector = kb.get_threat(_SQL_VECTOR)
    # Every north-star field is surfaced AS the corpus vector's own data.
    for f in ("cwe", "owasp", "mitre_attack", "severity", "attack_surface", "remediation"):
        assert entry[f] == vector[f], f
    # The retrieval envelope rides along; no husk (required fields all present).
    assert entry["retrieval"]["seed"] is True
    assert entry["severity"] == "critical"
    assert entry["cwe"] == ["CWE-89"]


def test_no_hardcoded_surface_table_in_output(nested):
    """The old fabricated shape is gone: no risk_summary, no overall_risk_score,
    no per-surface risk_score computed from _RISK_LEVELS x env_multiplier."""
    sid = _text_to_sid(nested["threat_signals"])[_SQL_SIGNAL]
    result = assess_threat("sys", [sid], constraints={"environment": "production"})
    assert "risk_summary" not in result
    assert "overall_risk_score" not in result
    for entry in result["threat_model"]:
        assert "risk_score" not in entry       # no fabricated scalar
        assert "risk_level" not in entry       # severity is the vector's OWN field


# ===========================================================================
# agent_risks built from hydrated agent_threats' OWN fields (not the island).
# ===========================================================================

def test_agent_risks_from_hydrated_agent_threats(kb, nested):
    """Pick an agent detection_signal whose sid is NOT shared with the threat view
    (disjoint routing), so this exercises the agent corpus alone."""
    threat_sids = {e["signal_id"] for e in nested["threat_signals"]}
    agent_view = nested["agent_threat_signals"]
    entry = next(e for e in agent_view if e["signal_id"] not in threat_sids)
    sid, answer = entry["signal_id"], entry["agent_threat_ids"][0]

    result = assess_threat("llm agent with tools", [sid])
    ar_ids = [e["id"] for e in result["agent_risks"]]
    assert answer in ar_ids
    # OWN fields hydrated from the corpus, not _AGENT_THREAT_PATTERNS.
    agent = kb.get_agent_threat(answer)
    got = next(e for e in result["agent_risks"] if e["id"] == answer)
    assert got["mitigation"] == agent["mitigation"]
    assert got["attack_patterns"] == agent["attack_patterns"]
    # Disjoint routing: an agent-only sid leaves the threat view abstaining.
    assert result["threat_model"] == []
    assert result["threat_retrieval_state"] == "no_match"


# ===========================================================================
# Islands removed from the module's path (assess_threat no longer imports them).
# ===========================================================================

def test_inline_islands_deleted_from_module():
    for symbol in (
        "_DECISION_RULES",
        "_AGENT_THREAT_PATTERNS",
        "_AGENT_SIGNALS",
        "_RISK_LEVELS",
        "_compute_surface_risk",
    ):
        assert not hasattr(at_mod, symbol), symbol


# ===========================================================================
# Fail-closed envelope: empty / mistyped ids -> NO_MATCH + unmatched_signals.
# ===========================================================================

def test_empty_ids_are_no_match_fail_closed():
    result = assess_threat("sys", [])
    assert result["threat_model"] == []
    assert result["agent_risks"] == []
    assert result["threat_retrieval_state"] == "no_match"
    assert result["agent_retrieval_state"] == "no_match"


def test_mistyped_id_is_unmatched_not_a_husk():
    result = assess_threat("sys", ["sig-does-not-exist"])
    assert result["threat_model"] == []
    assert result["agent_risks"] == []
    assert result["threat_retrieval_state"] == "no_match"
    assert "sig-does-not-exist" in result["unmatched_signals"]


def test_wrong_type_ids_do_not_crash():
    result = assess_threat("sys", "not-a-list")
    assert result["threat_model"] == []
    assert result["threat_retrieval_state"] == "no_match"


# ===========================================================================
# threat-vector stratum recall via the TOOL >= S0 baseline (never a husk lookup).
# ===========================================================================

def test_tool_threat_vector_recall_beats_S0_baseline(nested):
    view = nested["threat_signals"]
    text2sid = _text_to_sid(view)
    _, _, _ = _load_corpus(KNOWLEDGE_DIR)
    vectors = _load_corpus(KNOWLEDGE_DIR)[0]
    pairs = [[s, v["id"]] for v in vectors for s in v.get("signals", [])]
    hits = 0
    for query, answer in pairs:
        sid = text2sid.get(query.strip())
        if sid is None:
            continue
        if answer in _tool_threat_ids(sid):
            hits += 1
    assert hits >= BASELINE_A_LEG1[0], (hits, BASELINE_A_LEG1)
    # Measured effect of the S2 dissolve carried through the tool: full recall.
    assert (hits, len(pairs)) == (240, 240)


# ===========================================================================
# Named ceiling: matched_signal_ids capped BEFORE hydrate (cost boundary).
# ===========================================================================

def test_matched_signal_ids_capped_before_hydrate(nested):
    sid = _text_to_sid(nested["threat_signals"])[_SQL_SIGNAL]
    # Real id within the cap -> resolves.
    assert _SQL_VECTOR in [
        e["id"] for e in assess_threat("sys", [sid] + ["sig-x"] * 10)["threat_model"]
    ]
    # Real id pushed PAST the cap by junk -> excluded, so it does not resolve.
    padded = ["sig-junk"] * _MAX_MATCHED_SIGNALS + [sid]
    assert assess_threat("sys", padded)["threat_model"] == []


# ===========================================================================
# The optional constraint gate excludes on the vector's OWN metadata.
# ===========================================================================

def test_constraint_gate_excludes_on_own_fields(nested):
    """A severity floor of 'critical' keeps injection_sql (critical) and surfaces
    any lower-severity co-retrieved vector in filtered_out -- exclusion on the
    vector's OWN severity, no fabricated scalar."""
    sid = _text_to_sid(nested["threat_signals"])[_SQL_SIGNAL]
    result = assess_threat("sys", [sid], constraints={"severity": "critical"})
    kept = [e["id"] for e in result["threat_model"]]
    assert _SQL_VECTOR in kept
    for e in result["threat_model"]:
        assert e["severity"] == "critical"
    for f in result["filtered_out"]:
        assert f["severity"] != "critical"


def test_constraint_gate_empties_all_abstains_state_matches_data(nested):
    """The gate-removes-EVERYTHING case: a constraint that excludes every
    retrieved vector must leave the envelope's state and data consistent. The
    signal IS recognised (so retrieval alone is a hit), but the post-gate model
    is empty -- the surfaced threat_retrieval_state must therefore ABSTAIN, never
    report hit/low_confidence over threat_model==[] (the broken state<->data
    contract in the four-state fail-closed envelope). filtered_out names why the
    model is empty (the gate), not a failed retrieval."""
    sid = _text_to_sid(nested["threat_signals"])[_SQL_SIGNAL]
    # category the corpus never carries -> filter_by_constraints removes all.
    result = assess_threat("sys", [sid, sid], constraints={"category": "no-such-category"})
    assert result["threat_model"] == []
    # State and data agree: an empty model never rides a non-abstaining state.
    assert result["threat_retrieval_state"] not in ("hit", "low_confidence")
    assert result["threat_retrieval_state"] == "no_match"
    # The emptiness came from the gate (vectors WERE retrieved then excluded),
    # so filtered_out records the constraint that removed them.
    assert result["filtered_out"], "the gate must record the excluded vectors"
    assert any(_SQL_VECTOR == f["id"] for f in result["filtered_out"])


# ===========================================================================
# Determinism: the same ids yield byte-identical output (engine is deterministic).
# ===========================================================================

def test_output_is_deterministic(nested):
    sid = _text_to_sid(nested["threat_signals"])[_SQL_SIGNAL]
    a = json.dumps(assess_threat("sys", [sid]), sort_keys=True)
    b = json.dumps(assess_threat("sys", [sid]), sort_keys=True)
    assert a == b
