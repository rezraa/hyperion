# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion S4 -- plan_remediation retrofit onto hydrate (seed-from-node); islands
deleted; the dead CWE->threat_id bridge fixed.

Council b420a9f0 / m-73ea1894; standard m-55f6d4da (settled -- do not re-litigate).
Precedent mirrored: the Mnemos seed-from-node retrofit (``suggest_refactor``): the
caller already HOLDS the node's identity, so retrieval is seeded from THAT vector's
OWN signals -> ONE ``kb.hydrate`` -> reason over own fields -> fail-closed envelope;
the inline islands + the dead bridge are removed.

NORTH STAR: plan_remediation, given a real finding (a ``threat_id``, or a ``cwe``
mapped to threat_id via the S0-frozen corpus-built mapping), returns remediation +
examples + detection_patterns + related-via-fan-out hydrated from the threat_vectors
corpus through the four-state fail-closed envelope -- the dead ``get_remediation(cwe)``
bridge fixed to key on threat_id with the correct return shape, ``_REMEDIATIONS`` /
``_GENERIC_REMEDIATION`` deleted from the tool's path, and a threat_id with no corpus
node returning DANGLING, never a silent generic husk.

The S0 baseline is the immovable floor: this suite IMPORTS S0's frozen cwe->threat_id
mapping + the covered/uncovered CWE sets VERBATIM and measures the retrofitted TOOL
against them. Expected remediation content is read from the CORPUS (the loader's own
accessors), never hand-built (Directive 8). Loader/testbed level only -- no live
othrys.db, no re-seed (served schema lags disk; the live summon() proof is the USER's
step).
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import pytest

# Repo root on sys.path so the S0 module imports as a package under any invocation.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from hyperion.knowledge.loader import KnowledgeLoader
from hyperion.tools import _shared
from hyperion.tools._shared import _MAX_MATCHED_SIGNALS
from hyperion.tools.plan_remediation import plan_remediation
from tests.test_hyperion_retrofit_s0 import (
    CWE_MISSING_FROM_CORPUS,
    KNOWLEDGE_DIR,
    REMEDIATION_ISLAND_CWES,
    build_answer_key,
)

# The MODULE object (not the function the package __init__ binds under the same
# name) -- for the island-deleted + firewall assertions below.
pr_mod = sys.modules["hyperion.tools.plan_remediation"]


@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


@pytest.fixture()
def frozen_cwe_map() -> dict:
    """The S0-frozen, byte-frozen cwe -> sorted[threat_id] mapping."""
    return build_answer_key(KNOWLEDGE_DIR)["cwe_to_threat_ids"]


# ===========================================================================
# The dead bridge, fixed. RED (by measurement/history): the loader keys
# remediation on threat_id, so the OLD tool's ``kb.get_remediation(cwe)`` reached
# NOTHING (None) and fell back to the inline islands. GREEN: the bridge keys on
# threat_id and returns the corpus content.
# ===========================================================================

def test_get_remediation_keys_on_threat_id_not_cwe(kb):
    """The dead-bridge root cause, pinned: a CWE passed to the threat-id-keyed
    loader lookup returns None -- the OLD tool did exactly this and got nothing,
    then produced island/generic content. A real threat_id returns the corpus text."""
    assert kb.get_remediation("CWE-89") is None            # the dead bridge
    assert kb.get_remediation("injection_sql") == (
        kb.get_threat("injection_sql")["remediation"]
    )


def test_inline_islands_deleted_from_module():
    for symbol in ("_REMEDIATIONS", "_GENERIC_REMEDIATION"):
        assert not hasattr(pr_mod, symbol), symbol


def test_signature_dropped_language_and_constraints_no_shim():
    params = list(inspect.signature(plan_remediation).parameters)
    assert "finding" in params
    assert "k" in params
    # Retired params that only ever selected content FROM the deleted islands.
    assert "language" not in params
    assert "constraints" not in params


def test_module_imports_only_hyperion(kb):
    """Firewall: the retrofitted module pulls only hyperion.* (no sibling Titan)."""
    src = Path(pr_mod.__file__).read_text(encoding="utf-8")
    for bad in ("import coeus", "import mnemos", "import theia", "import themis",
                "import othrys", "from coeus", "from mnemos", "from theia",
                "from themis", "from othrys"):
        assert bad not in src, bad


# ===========================================================================
# The corpus-built cwe->threat_id bridge EQUALS the S0-frozen mapping.
# ===========================================================================

def test_loader_cwe_mapping_equals_S0_frozen(kb, frozen_cwe_map):
    assert kb.cwe_to_threat_ids() == frozen_cwe_map


def test_cwe_mapping_is_one_to_many(kb):
    """CWE-89 maps to more than one vector -- the finding->vector bridge is
    one-to-many, so a cwe-only finding may hydrate several remediations."""
    assert kb.cwe_to_threat_ids()["CWE-89"] == ["injection_graphql", "injection_sql"]


# ===========================================================================
# threat_id finding -> remediation hydrated from the vector's OWN fields.
# ===========================================================================

def test_threat_id_hydrates_own_corpus_content(kb):
    r = plan_remediation({"threat_id": "injection_sql", "severity": "critical"})
    assert r["retrieval_state"] == "hit"
    assert r["source"] == "threat_id"
    entry = next(e for e in r["remediations"] if e["id"] == "injection_sql")
    vector = kb.get_threat("injection_sql")
    # The north-star content -- each field IS the corpus vector's own data.
    assert entry["remediation"] == vector["remediation"]
    assert entry["examples"] == kb.get_examples("injection_sql")
    assert entry["detection_patterns"] == kb.get_detection_patterns("injection_sql")
    # Ride-along data: the vector's OWN severity/cwe (never an invented verdict).
    assert entry["severity"] == vector["severity"]
    assert entry["cwe"] == vector["cwe"]
    # Plain JSON types (a frozen tuple would compare unequal to the corpus list).
    assert isinstance(entry["cwe"], list)
    assert isinstance(entry["detection_patterns"], list)
    assert isinstance(entry["examples"], dict)
    # The retrieval envelope rides along; the finding's vector is a seed.
    assert entry["retrieval"]["seed"] is True


def test_related_threats_are_the_fan_out(kb):
    """related_threats is the pure fan-out (the vector's ``alternatives`` edge),
    reused as the related set -- each is a propagated-only neighbour, not the seed."""
    r = plan_remediation({"threat_id": "injection_sql"})
    related_ids = [e["id"] for e in r["related_threats"]]
    assert related_ids == kb.get_threat("injection_sql")["alternatives"]
    for e in r["related_threats"]:
        assert e["retrieval"]["seed"] is False
    # The finding's own vector is NOT in its related set.
    assert "injection_sql" not in related_ids


# ===========================================================================
# cwe-only finding -> hydrates through the S0-frozen mapping (one-to-many).
# ===========================================================================

def test_cwe_only_finding_hydrates_all_mapped_vectors(kb, frozen_cwe_map):
    r = plan_remediation({"cwe": "CWE-89"})
    assert r["retrieval_state"] == "hit"
    assert r["source"] == "cwe"
    got = sorted(e["id"] for e in r["remediations"])
    assert got == frozen_cwe_map["CWE-89"]
    for e in r["remediations"]:
        assert e["remediation"] == kb.get_threat(e["id"])["remediation"]


def test_covered_island_cwes_all_hydrate_corpus_content(kb):
    """For every island CWE the corpus covers, a cwe-only finding yields the corpus
    remediation for each mapped vector -- the generic husk is gone for all of them."""
    covered = REMEDIATION_ISLAND_CWES - CWE_MISSING_FROM_CORPUS
    cwe_map = kb.cwe_to_threat_ids()
    for cwe in sorted(covered):
        r = plan_remediation({"cwe": cwe})
        assert r["retrieval_state"] == "hit", cwe
        got = sorted(e["id"] for e in r["remediations"])
        assert got == cwe_map[cwe], cwe
        for e in r["remediations"]:
            assert e["remediation"] == kb.get_threat(e["id"])["remediation"]


# ===========================================================================
# Fail-closed: DANGLING for an unresolvable reference, never a generic husk.
# ===========================================================================

def test_uncovered_cwe_is_dangling_not_a_husk():
    """The S0-recorded coverage gap: CWE-95 / CWE-352 are not in the corpus, so a
    finding carrying only them fails closed (DANGLING) -- NOT a generic-remediation
    husk. The gap is surfaced in ``dangling`` (recorded follow-up: corpus authoring
    is out of the arc)."""
    for cwe in sorted(CWE_MISSING_FROM_CORPUS):
        r = plan_remediation({"cwe": cwe})
        assert r["retrieval_state"] == "dangling", cwe
        assert r["remediations"] == []
        assert r["related_threats"] == []
        assert r["dangling"] == [cwe]


def test_absent_threat_id_is_dangling_no_cwe_fallback():
    """A threat_id with no corpus node -> DANGLING (the north star), even when a
    valid cwe rides along -- a broken finding fails closed loud, no silent fallback."""
    r = plan_remediation({"threat_id": "does_not_exist", "cwe": "CWE-89"})
    assert r["retrieval_state"] == "dangling"
    assert r["remediations"] == []
    assert r["dangling"] == ["does_not_exist"]


def test_empty_finding_is_no_match():
    r = plan_remediation({})
    assert r["retrieval_state"] == "no_match"
    assert r["remediations"] == []
    assert r["related_threats"] == []
    assert r["dangling"] == []


def test_no_generic_husk_ever_surfaces():
    """The retired _GENERIC_REMEDIATION title/steps must appear on NO abstaining
    path -- the husk is gone, not merely bypassed on the happy path."""
    for finding in ({"cwe": "CWE-95"}, {"threat_id": "nope"}, {}):
        blob = json.dumps(plan_remediation(finding)).lower()
        assert "security vulnerability" not in blob   # old generic title
        assert "review the cwe entry" not in blob     # old generic step


def test_wrong_type_finding_does_not_crash():
    r = plan_remediation("not-a-dict")
    assert r["retrieval_state"] == "no_match"
    assert r["remediations"] == []


# ===========================================================================
# Named ceiling + determinism.
# ===========================================================================

def test_caller_boundary_ceiling_is_declared():
    """plan_remediation seeds hydrate under the shared caller-boundary ceiling
    (one source of truth in _shared)."""
    assert isinstance(_MAX_MATCHED_SIGNALS, int) and _MAX_MATCHED_SIGNALS > 0


def test_oversized_repeated_cwe_list_does_bounded_work(kb, monkeypatch):
    """CWE-400 backstop: an oversized/repeated cwe list must do work bounded by the
    corpus + ceiling, NOT by the caller's input length.

    RED (pre-fix, measured): ``signal_ids_for`` was called once per RESOLVED entry and
    the resolve loop appended a vector id per REPEATED cwe, so calls scaled linearly
    with the untrusted input (``['CWE-89']*N`` -> 2N calls; N=10k = 0.6s, N=1M ~ 1min).
    GREEN: the cwe list is deduped + capped at the caller boundary before the seed
    loop, so ``signal_ids_for`` runs once per DISTINCT mapped vector regardless of N,
    and the hydrated output is identical to the single-cwe finding (dedup changes cost,
    not content)."""
    kb_singleton = _shared.get_knowledge(None)
    calls = {"n": 0}
    real = kb_singleton.signal_ids_for

    def counting(vid):
        calls["n"] += 1
        return real(vid)

    monkeypatch.setattr(kb_singleton, "signal_ids_for", counting)

    n_vectors = len(kb.cwe_to_threat_ids()["CWE-89"])  # distinct mapped vectors (2)

    calls["n"] = 0
    baseline = plan_remediation({"cwe": "CWE-89"})
    assert calls["n"] == n_vectors                      # one lookup per distinct vector

    for n in (1_000, 100_000):
        calls["n"] = 0
        r = plan_remediation({"cwe": ["CWE-89"] * n})
        assert calls["n"] == n_vectors, n              # bounded by the corpus, not by n
        assert calls["n"] <= _MAX_MATCHED_SIGNALS, n
        assert r["remediations"] == baseline["remediations"], n
        assert r["retrieval_state"] == "hit", n


def test_duplicated_cwe_list_equals_distinct_cwe_list(kb):
    """Dedup+cap changes cost, not content: a finding whose cwe list repeats/reorders
    the same distinct covered CWEs hydrates EXACTLY what the distinct list does — no
    dropped coverage, no extra vectors."""
    cwes = sorted(kb.cwe_to_threat_ids())[:3]           # three covered CWEs
    distinct = plan_remediation({"cwe": cwes})
    duped = plan_remediation({"cwe": cwes * 4 + list(reversed(cwes))})
    assert duped["remediations"] == distinct["remediations"]
    assert duped["related_threats"] == distinct["related_threats"]
    assert duped["retrieval_state"] == distinct["retrieval_state"]
    assert distinct["retrieval_state"] == "hit"


def test_output_is_deterministic():
    a = json.dumps(plan_remediation({"threat_id": "injection_sql"}), sort_keys=True)
    b = json.dumps(plan_remediation({"cwe": "CWE-89"}), sort_keys=True)
    assert a == json.dumps(plan_remediation({"threat_id": "injection_sql"}), sort_keys=True)
    assert b == json.dumps(plan_remediation({"cwe": "CWE-89"}), sort_keys=True)
