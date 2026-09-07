# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion S2 -- ONE nested get_signal_index; decision_rules dissolved; re-frozen.

Council b420a9f0 / m-73ea1894; standard m-55f6d4da (settled -- do not re-litigate).
Precedent mirrored: Themis S2 (m-a02072f9), Theia S1 (m-3b1847c6), council ae492280
(m-5a5837da) -- ONE filed nested two-view accessor, seed-drop impossible by
construction, per-stratum recall inspected INDEPENDENTLY (Theia gain-cancels-loss).

NORTH STAR: Hyperion exposes exactly ONE reachable nested accessor
``get_signal_index -> {threat_signals:[{signal_id,signal_text,vector_ids}],
agent_threat_signals:[{signal_id,signal_text,agent_threat_ids}]}`` with
decision_rules' 55 structural_signals dissolved onto the threat_vectors' own
``signals`` (content-positive, provenance kept) and ``alternatives``/
``recommended_threat`` materialized as the fan-out edge, such that per-stratum
recall@10 equals-or-beats the frozen S0 baseline INDEPENDENTLY on BOTH recognition
strata (leg1 >= 18/240, leg2 >= 55/55, combined >= 73/295; agent-threat >= 0/64 and
now on a real path), deterministic and re-frozen, empty ids -> NO_MATCH on both.

The S0 baseline (the matcher's recall on the ORIGINAL corpus) is the immovable
floor: this suite IMPORTS S0's frozen baselines + query set VERBATIM and measures
the NEW nested-accessor engine on the SAME frozen queries. The dissolve is an
IN-MEMORY load behaviour (COPY, not move): threat_vectors.json and
decision_rules.json stay byte-identical on disk (the matcher's source lives until
S6), so the frozen S0 benchmark is untouched and still green. All positive-case
signal ids are obtained from the ACCESSOR's OWN output, never hand-built
(Directive 8). Loader/testbed level only -- no live othrys.db, no re-seed.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Repo root on sys.path so the S0 module imports as a package under any invocation.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import hyperion.knowledge.loader as L
import hyperion.tools.get_signal_index as accessor_mod
from hyperion.knowledge.loader import NO_MATCH, KnowledgeLoader
from hyperion.tools.get_signal_index import get_signal_index
from tests.test_hyperion_retrofit_s0 import (
    BASELINE_A_COMBINED,
    BASELINE_A_LEG1,
    BASELINE_A_LEG2,
    BASELINE_B,
    KNOWLEDGE_DIR,
    RECALL_K,
    _load_corpus,
    build_answer_key,
    canonical,
)

_SRC = Path(L.__file__).resolve().parents[2]  # .../src

# Re-frozen S2 substrate: sha256 of the canonical nested accessor view (post-fold).
# Pinned so a corpus/fold drift fails loud -- this is the story's re-freeze.
S2_INDEX_SHA256 = "5b08fa95c7eb09f76bda2b10c41a85991a08f3453110a43542c9c9edbd41585f"


# ===========================================================================
# Fixtures + the nested-accessor recognizer (ids from the accessor's OWN output)
# ===========================================================================

@pytest.fixture()
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


@pytest.fixture()
def nested() -> dict:
    return get_signal_index()


@pytest.fixture()
def answer_key() -> dict:
    return build_answer_key(KNOWLEDGE_DIR)


def _text_to_sid(view: list[dict]) -> dict[str, str]:
    """Map signal_text -> signal_id straight from the accessor's own view."""
    out: dict[str, str] = {}
    for entry in view:
        out.setdefault(entry["signal_text"].strip(), entry["signal_id"])
    return out


def _recall(hydrate, view: list[dict], pairs: list[list[str]], k: int = RECALL_K):
    """recall@k: recognise each query against the accessor view, hydrate, check.

    Recognition = text -> signal_id via the accessor's OWN output; retrieval =
    the production hydrate path (direct votes + fan-out + top-k). Never a lookup
    that already knows the answer.
    """
    text2sid = _text_to_sid(view)
    hits = 0
    for query, answer in pairs:
        sid = text2sid.get(query.strip())
        if sid is None:
            continue
        got = [p["id"] for p in hydrate([sid], k=k).patterns]
        if answer in got:
            hits += 1
    return hits, len(pairs)


# ===========================================================================
# Accessor shape + reachability-by-construction (ONE public nested function)
# ===========================================================================

def test_accessor_returns_the_nested_two_view(nested):
    assert set(nested) == {"threat_signals", "agent_threat_signals"}
    assert nested["threat_signals"] and nested["agent_threat_signals"]
    for e in nested["threat_signals"]:
        assert set(e) == {"signal_id", "signal_text", "vector_ids"}
    for e in nested["agent_threat_signals"]:
        assert set(e) == {"signal_id", "signal_text", "agent_threat_ids"}


def test_exactly_one_public_function_filename_equals_function():
    """seed-drop impossible by construction: ONE public top-level function in the
    filed module, and filename == function (the reachability contract)."""
    public = [
        name
        for name, obj in vars(accessor_mod).items()
        if inspect.isfunction(obj)
        and obj.__module__ == accessor_mod.__name__
        and not name.startswith("_")
    ]
    assert public == ["get_signal_index"]
    assert Path(accessor_mod.__file__).stem == "get_signal_index"


# ===========================================================================
# Per-stratum recall@10 >= S0 baseline, inspected INDEPENDENTLY (never pooled).
# ===========================================================================

def test_threat_vector_recall_beats_baseline_per_leg(kb, nested, answer_key):
    """Theia gain-cancels-loss guard: leg1 AND leg2 each >= their OWN frozen floor,
    inspected independently -- a leg1 gain must not be paid for by a leg2 collapse."""
    view = nested["threat_signals"]
    leg1 = _recall(kb.hydrate, view, answer_key["stratum_A"]["leg1_vector_signals"])
    leg2 = _recall(kb.hydrate, view, answer_key["stratum_A"]["leg2_decision_rules"])
    combined = (leg1[0] + leg2[0], leg1[1] + leg2[1])
    # Independent floors (never a pooled mean).
    assert leg1[0] >= BASELINE_A_LEG1[0], (leg1, BASELINE_A_LEG1)
    assert leg2[0] >= BASELINE_A_LEG2[0], (leg2, BASELINE_A_LEG2)
    assert combined[0] >= BASELINE_A_COMBINED[0], (combined, BASELINE_A_COMBINED)
    # The dissolve's measured effect: leg1 rises to full recall, leg2 held perfect.
    assert leg1 == (240, 240)
    assert leg2 == (55, 55)
    assert combined == (295, 295)


def test_agent_threat_recall_beats_baseline_on_a_real_path(kb, nested, answer_key):
    """Stratum B was 0/64 (no path). The second view puts it on a real path."""
    view = nested["agent_threat_signals"]
    legb = _recall(kb.hydrate_agent, view, answer_key["stratum_B"]["agent_detection_signals"])
    assert legb[0] >= BASELINE_B[0], (legb, BASELINE_B)
    assert legb == (64, 64)


def test_strata_reported_separately_never_pooled(kb, nested, answer_key):
    """Three denominators, three results -- there is no shared total to average."""
    leg1 = _recall(kb.hydrate, nested["threat_signals"],
                   answer_key["stratum_A"]["leg1_vector_signals"])
    legb = _recall(kb.hydrate_agent, nested["agent_threat_signals"],
                   answer_key["stratum_B"]["agent_detection_signals"])
    assert leg1[1] != legb[1]  # 240 threat-signals vs 64 agent-signals: not poolable


# ===========================================================================
# Empty ids -> NO_MATCH on BOTH views (fail closed).
# ===========================================================================

def test_empty_ids_are_no_match_on_both_views(kb):
    assert kb.hydrate([]).state == NO_MATCH
    assert kb.hydrate_agent([]).state == NO_MATCH
    assert kb.hydrate(["sig-does-not-exist"]).state == NO_MATCH
    assert kb.hydrate_agent(["sig-does-not-exist"]).state == NO_MATCH


# ===========================================================================
# Dissolve: decision_rules onto the vectors' OWN signals (COPY, provenance kept).
# ===========================================================================

def test_decision_rules_dissolved_onto_vector_signals(kb, nested):
    """Every rule's structural_signal is recognised on the threat_signals view and
    maps to its recommended_threat vector (content-positive dissolve)."""
    _, _, rules = _load_corpus(KNOWLEDGE_DIR)
    text2entry = {e["signal_text"].strip(): e for e in nested["threat_signals"]}
    for r in rules:
        ss = (r.get("structural_signal") or "").strip()
        rt = r.get("recommended_threat", "")
        if not ss or rt not in kb._vector_index:
            continue
        assert ss in text2entry, ss
        assert rt in text2entry[ss]["vector_ids"], (ss, rt)


def test_dissolve_is_in_memory_corpus_files_unchanged():
    """COPY not move: the on-disk corpus is untouched (matcher's source lives to
    S6), so the frozen S0 benchmark stays byte-identical. The fold is a loader
    behaviour that ADDS the 43 absent structural_signals to the in-memory index."""
    vectors, _, rules = _load_corpus(KNOWLEDGE_DIR)
    on_disk = sum(len(v.get("signals", [])) for v in vectors)
    assert on_disk == 240                       # threat_vectors.json unchanged
    assert sum(1 for r in rules if r.get("structural_signal")) == 55  # rules unchanged
    kb = KnowledgeLoader()
    assert len(kb.get_signal_index()) == 283    # 240 + 43 dissolved, in-memory


def test_provenance_kept(kb):
    """provenance kept: every dissolved signal records the rule(s) and vector(s) it
    came from -- nothing is folded anonymously."""
    _, _, rules = _load_corpus(KNOWLEDGE_DIR)
    prov = kb._dissolved_provenance
    dissolved_texts = {
        (r["structural_signal"] or "").strip()
        for r in rules
        if (r.get("structural_signal") or "").strip()
        and r.get("recommended_threat") in kb._vector_index
    }
    assert set(prov) == dissolved_texts
    for text, rec in prov.items():
        assert rec["rules"] and rec["vectors"]


# ===========================================================================
# Fan-out edge materialized on the REAL corpus (the S1 seed-only state changed).
# ===========================================================================

def test_alternatives_fan_out_materialized(kb):
    """S1 measured 0/65 alternatives (seed-only). S2 materialises the edge from the
    rules' recommended_threat/alternatives, so a real seed now fans out to a
    propagated (zero-direct-vote) neighbour -- proven on the real corpus, no fixture."""
    with_alts = [v for v in kb.get_all_threats() if v.get("alternatives")]
    assert with_alts, "S2 must materialise the alternatives fan-out edge"
    fanned = False
    for v in with_alts:
        res = kb.hydrate(kb.signal_ids_for(v["id"]), k=50, fan_out=True)
        if any(not p["retrieval"]["seed"] for p in res.patterns):
            fanned = True
            # a propagated neighbour is a genuine, resolved corpus vector, never a husk
            assert res.dangling == []
            break
    assert fanned, "materialised edge must produce a propagated neighbour"


# ===========================================================================
# Disjointness from S0 still holds after the fold.
# ===========================================================================

def test_node_id_disjointness_still_holds(kb, answer_key):
    assert answer_key["disjointness"]["node_id_overlap"] == []
    assert set(kb._vector_index) & set(kb._agent_threat_index) == set()


# ===========================================================================
# Determinism + re-freeze (the S2 frozen artifact).
# ===========================================================================

def test_nested_view_deterministic_across_fresh_loaders():
    a = canonical(get_signal_index())
    b = canonical(KnowledgeLoader() and get_signal_index())
    c = canonical({
        "threat_signals": KnowledgeLoader().get_signal_index(),
        "agent_threat_signals": KnowledgeLoader().get_agent_signal_index(),
    })
    assert a == b == c
    for view in get_signal_index().values():
        assert [e["signal_id"] for e in view] == sorted(e["signal_id"] for e in view)


def test_nested_view_byte_reproducible_across_pythonhashseed():
    snippet = (
        "import json,hashlib;"
        "from hyperion.tools.get_signal_index import get_signal_index as g;"
        "print(hashlib.sha256(json.dumps(g(),sort_keys=True).encode()).hexdigest())"
    )
    env_base = {**os.environ, "PYTHONPATH": str(_SRC)}
    outs = []
    for seed in ("0", "1", "12345"):
        r = subprocess.run(
            [sys.executable, "-c", snippet],
            capture_output=True, text=True,
            env={**env_base, "PYTHONHASHSEED": seed},
        )
        assert r.returncode == 0, r.stderr
        outs.append(r.stdout.strip())
    assert len(set(outs)) == 1, f"nested index sha256 moved across PYTHONHASHSEED: {outs}"


def test_nested_view_matches_frozen_sha256():
    got = hashlib.sha256(canonical(get_signal_index()).encode("utf-8")).hexdigest()
    assert got == S2_INDEX_SHA256


# ===========================================================================
# Server wrapper delegates to the one filed accessor (testbed reachability;
# live summon() proof is the USER's post-re-seed step).
# ===========================================================================

def test_server_wrapper_delegates_to_the_filed_accessor():
    import hyperion.server as server
    assert server.get_signal_index() == get_signal_index()
