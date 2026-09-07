# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Shape-C signal-index engine — unit proof (Hyperion S1, story-e13a6ac9).

Locks the ported engine (a JUSTIFIED MIRROR of the shipped
mnemos/coeus/theia/themis ``_SignalEngine``; council b420a9f0 / m-73ea1894,
standard m-55f6d4da):

* get_signal_index is deterministic + byte-reproducible (repeat calls, a fresh
  loader, and a PYTHONHASHSEED flip) and fails CLOSED on a hash collision at load;
* hydrate returns the four-state fail-closed envelope over the ``alternatives``
  edge, deep-frozen, no husk; NO_MATCH on empty/unrecognised ids; the DANGLING
  state, the fan-out edge, and the field-short husk guard are exercised by
  CONSTRUCTED fixtures (Directive 8 — at S1 the vectors carry NO ``alternatives``
  edge (S2 materialises it), so on the real corpus every seed resolves and hydrate
  is seed-only; none of those three is naturally reachable);
* the engine lives ONCE as ``_SignalEngine`` + module free-fns, inherited by BOTH
  loaders (the graph loader delegates its read path to the JSON parent).

All ids that drive a positive case are obtained from the accessor's OWN output
(``get_signal_index`` / ``signal_ids_for``), never hand-built (Directive 8).
Proven at the loader/testbed level only — no live othrys.db, no re-seed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import hyperion.knowledge.loader as L
from hyperion.knowledge.loader import (
    DANGLING,
    HIT,
    LOW_CONFIDENCE,
    NO_MATCH,
    _CONFIDENCE_FLOOR,
    _FrozenDict,
    _NamedIndex,
    _SEED_CAP,
    _SignalEngine,
    _TOPK_CAP,
    _signal_id,
    KnowledgeLoader,
    deep_freeze,
)

_SRC = Path(L.__file__).resolve().parents[2]  # .../src


@pytest.fixture(scope="module")
def kb() -> KnowledgeLoader:
    return KnowledgeLoader()


@pytest.fixture(scope="module")
def multi_signal_vector(kb: KnowledgeLoader) -> str:
    """A vector id that owns >= 2 signals (drives a multi-vote HIT).

    Chosen from the accessor's own view, deterministically (id asc)."""
    idx = kb.get_signal_index()
    counts: dict[str, int] = {}
    for e in idx:
        for vid in e["vector_ids"]:
            counts[vid] = counts.get(vid, 0) + 1
    winners = sorted(v for v, c in counts.items() if c >= 2)
    assert winners, "expected at least one vector with >= 2 own signals"
    return winners[0]


@pytest.fixture(scope="module")
def single_owner_signal(kb: KnowledgeLoader) -> str:
    """A signal id owned by exactly ONE vector (drives a single-vote low_confidence)."""
    idx = kb.get_signal_index()
    singles = sorted(e["signal_id"] for e in idx if len(e["vector_ids"]) == 1)
    assert singles, "expected at least one signal owned by exactly one vector"
    return singles[0]


# ==========================================================================
# get_signal_index — determinism, byte-reproducibility, fail-closed collision
# ==========================================================================

class TestSignalIndex:
    def test_index_covers_all_distinct_signals(self, kb: KnowledgeLoader) -> None:
        idx = kb.get_signal_index()
        distinct = {
            s.strip()
            for v in kb.get_all_threats()
            for s in v.get("signals", [])
            if s.strip()
        }
        assert len(idx) == len(distinct)                 # every distinct vector signal
        assert all(e["signal_id"] == _signal_id(e["signal_text"]) for e in idx)
        assert all("vector_ids" in e for e in idx)       # the threat-vector corpus id-field

    def test_deterministic_and_sorted(self, kb: KnowledgeLoader) -> None:
        a = kb.get_signal_index()
        b = kb.get_signal_index()
        assert a == b
        assert [e["signal_id"] for e in a] == sorted(e["signal_id"] for e in a)
        assert all(e["vector_ids"] == sorted(e["vector_ids"]) for e in a)

    def test_byte_reproducible_fresh_loader(self) -> None:
        dumps = [
            json.dumps(KnowledgeLoader().get_signal_index(), sort_keys=True)
            for _ in range(3)
        ]
        assert len(set(dumps)) == 1

    def test_byte_reproducible_across_pythonhashseed(self) -> None:
        """A PYTHONHASHSEED flip must not move the serialised index (real proof, not
        just the by-construction argument)."""
        snippet = (
            "import json,hashlib;"
            "from hyperion.knowledge.loader import KnowledgeLoader as K;"
            "print(hashlib.sha256(json.dumps(K().get_signal_index(),"
            "sort_keys=True).encode()).hexdigest())"
        )
        import os
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
        assert len(set(outs)) == 1, f"index sha256 moved across PYTHONHASHSEED: {outs}"

    def test_no_collision_on_real_corpus(self, kb: KnowledgeLoader) -> None:
        KnowledgeLoader()  # would raise in __init__ if the frozen corpus collided
        # 283 distinct threat-vector signals post-S2 = the 240 vectors' own signals
        # plus the 43 decision_rules structural_signals dissolved in; all distinct,
        # 0 hash collisions on the real corpus (the dissolve fails closed on a clash).
        assert len(kb.get_signal_index()) == 283

    def test_fail_closed_on_hash_collision(self, monkeypatch) -> None:
        """Two distinct signal texts colliding on one sid must raise at load, never
        silently merge into a corrupted index."""
        monkeypatch.setattr(L, "_signal_id", lambda _t: "sig-collide00000")
        eng = _SignalEngine()
        index = _NamedIndex(
            name="t", node_index={
                "a": {"id": "a", "signals": ["foo shape"], "category": "c"},
                "b": {"id": "b", "signals": ["bar shape"], "category": "c"},
            },
            signal_field="signals", edge_field="alternatives",
            id_field="vector_ids", required_fields=("signals", "category"),
        )
        with pytest.raises(ValueError, match="collision"):
            eng._build_signal_index(index)


# ==========================================================================
# signal_ids_for — the seed-from-node accessor
# ==========================================================================

class TestSignalIdsFor:
    def test_returns_the_nodes_own_signal_ids(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        vid = multi_signal_vector
        vec = kb.get_threat(vid)
        expected = sorted({_signal_id(s.strip()) for s in vec["signals"] if s.strip()})
        assert kb.signal_ids_for(vid) == expected
        idx = {e["signal_id"]: e for e in kb.get_signal_index()}
        assert all(vid in idx[s]["vector_ids"] for s in kb.signal_ids_for(vid))

    def test_unknown_or_none_seed_is_empty(self, kb: KnowledgeLoader) -> None:
        assert kb.signal_ids_for("no-such-vector") == []
        assert kb.signal_ids_for("") == []

    def test_seed_hydrates_the_node(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        """Seeding hydrate with a vector's own signal ids self-votes it (HIT). The
        first multi-signal vector (id asc) carries no ``alternatives`` edge, so its
        own result is seed-only; the materialised-edge fan-out on the real corpus is
        proven in ``test_real_corpus_fans_out_after_s2`` and the constructed fixture
        below."""
        vid = multi_signal_vector
        res = kb.hydrate(kb.signal_ids_for(vid), k=_TOPK_CAP)
        assert res.state == HIT
        patterns = {p["id"]: p for p in res.patterns}
        assert vid in patterns
        assert patterns[vid]["retrieval"]["seed"]   # the seed itself is a direct vote

    def test_deterministic_and_sorted(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        a = kb.signal_ids_for(multi_signal_vector)
        assert a == kb.signal_ids_for(multi_signal_vector) == sorted(a)


# ==========================================================================
# hydrate — four-state fail-closed envelope over the ``alternatives`` edge
# ==========================================================================

class TestHydrateStates:
    def test_hit_multi_vote(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        res = kb.hydrate(kb.signal_ids_for(multi_signal_vector), k=10)
        assert res.state == HIT
        assert res.patterns[0]["retrieval"]["score"] >= _CONFIDENCE_FLOOR

    def test_low_confidence_single_vote(self, kb: KnowledgeLoader, single_owner_signal: str) -> None:
        res = kb.hydrate([single_owner_signal], k=10, fan_out=False)
        assert res.state == LOW_CONFIDENCE
        assert res.patterns                                # never an empty list narrated as an answer
        assert res.patterns[0]["retrieval"]["score"] < _CONFIDENCE_FLOOR

    def test_no_match_unrecognised_signal(self, kb: KnowledgeLoader) -> None:
        res = kb.hydrate(["sig-does-not-exist"], k=10)
        assert res.state == NO_MATCH
        assert res.patterns == []                          # fail closed, no husk
        assert res.votes == {}
        assert res.unmatched_signals == ["sig-does-not-exist"]

    def test_empty_input_is_no_match(self, kb: KnowledgeLoader) -> None:
        r = kb.hydrate([], k=10)
        assert r.state == NO_MATCH
        assert r.patterns == [] and r.unmatched_signals == []

    def test_dangling_state_constructed_fixture(self) -> None:
        """DANGLING state: EVERY hydrated id fails to resolve. Unreachable on the
        real corpus (seeds always resolve; the ``alternatives`` edge is empty at S1),
        so it is built directly (Directive 8) — an index entry pointing only at an
        absent id."""
        loader = KnowledgeLoader()
        ghost = "sig-ghost0000000"
        loader._threat_signal_index.signal_index[ghost] = {
            "signal_id": ghost, "signal_text": "ghost", "vector_ids": ["__absent_vector__"],
        }
        res = loader.hydrate([ghost], k=10)
        assert res.state == DANGLING
        assert res.patterns == []                          # no husk on DANGLING
        assert res.votes == {}
        assert "__absent_vector__" in res.dangling

    def test_fanout_over_alternatives_constructed(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        """Fan-out walks the ``alternatives`` edge. At S1 no vector carries the edge
        (S2 materialises it), so it is wired in a constructed fixture (Directive 8):
        a genuine seed with a genuine neighbour on its ``alternatives`` edge yields
        the neighbour as a PROPAGATED (zero-direct-vote) result; with fan-out off,
        only the direct seed survives."""
        loader = KnowledgeLoader()
        seed_id = multi_signal_vector
        neighbour_id = next(v["id"] for v in loader.get_all_threats() if v["id"] != seed_id)
        real = loader._vector_index[seed_id]
        loader._vector_index[seed_id] = {**real, "alternatives": [neighbour_id]}
        res = loader.hydrate(loader.signal_ids_for(seed_id), k=_TOPK_CAP, fan_out=True)
        propagated = {p["id"] for p in res.patterns if not p["retrieval"]["seed"]}
        assert neighbour_id in propagated
        res_off = loader.hydrate(loader.signal_ids_for(seed_id), k=_TOPK_CAP, fan_out=False)
        assert all(p["retrieval"]["seed"] for p in res_off.patterns)
        assert all(p["retrieval"]["propagated_votes"] == 0 for p in res_off.patterns)

    def test_real_corpus_fans_out_after_s2(self, kb: KnowledgeLoader) -> None:
        """S2 materialised the ``alternatives`` edge from decision_rules, so on the
        REAL corpus a seed that carries the edge now fans out to a PROPAGATED
        (zero-direct-vote) neighbour resolving to a genuine vector — the honest S1
        seed-only state, now changed, proven without a constructed fixture."""
        seed = next(
            v["id"] for v in sorted(kb.get_all_threats(), key=lambda x: x["id"])
            if v.get("alternatives")
        )
        res = kb.hydrate(kb.signal_ids_for(seed), k=_TOPK_CAP)
        assert res.state == HIT
        assert any(not p["retrieval"]["seed"] for p in res.patterns)  # a propagated neighbour
        assert res.dangling == []                                     # resolved, never a husk


# ==========================================================================
# Husk guard — a FIELD-SHORT node resolves to DANGLING, never a silent default
# (council b420a9f0-decision-2). Constructed fixtures (Directive 8).
# ==========================================================================

class TestHuskGuard:
    def test_field_short_seed_is_not_hydrated_as_a_husk(self) -> None:
        """A node present in the index but missing a required field (the ``{id, name}``
        husk shape the blind path produced) resolves to DANGLING, not a
        silently-defaulted node."""
        loader = KnowledgeLoader()
        husk_id = "__husk_vector__"
        loader._vector_index[husk_id] = {"id": husk_id, "name": husk_id}  # no signals/category
        sid = "sig-husk00000000"
        loader._threat_signal_index.signal_index[sid] = {
            "signal_id": sid, "signal_text": "husk", "vector_ids": [husk_id],
        }
        res = loader.hydrate([sid], k=10)
        assert res.state == DANGLING
        assert res.patterns == []                          # never emitted as a husk
        assert husk_id in res.dangling

    def test_field_short_neighbour_is_surfaced_dangling_not_propagated(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        """A field-short ``alternatives`` neighbour populates the dangling FIELD on an
        otherwise-HIT envelope — surfaced loud, never hydrated as a husk."""
        loader = KnowledgeLoader()
        seed_id = multi_signal_vector
        husk_id = "__husk_alt__"
        loader._vector_index[husk_id] = {"id": husk_id, "name": husk_id}
        real = loader._vector_index[seed_id]
        loader._vector_index[seed_id] = {**real, "alternatives": [husk_id]}
        res = loader.hydrate(loader.signal_ids_for(seed_id), k=_TOPK_CAP)
        assert res.state == HIT                            # the genuine seed still hits
        assert husk_id in res.dangling                     # the husk neighbour surfaced
        assert husk_id not in {p["id"] for p in res.patterns}   # never hydrated

    def test_genuine_node_passes_the_guard(self, kb: KnowledgeLoader) -> None:
        """The guard does not fire on the real corpus: every vector carries the
        required fields, so a real signal hydrates to a real node."""
        idx = kb.get_signal_index()
        res = kb.hydrate([idx[0]["signal_id"]], k=10)
        assert res.state in (HIT, LOW_CONFIDENCE)
        assert res.patterns and res.dangling == []


# ==========================================================================
# hydrate invariants — deep-freeze, no corpus corruption, determinism, ranking
# ==========================================================================

class TestHydrateInvariants:
    def test_deep_frozen_patterns_are_read_only(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        res = kb.hydrate(kb.signal_ids_for(multi_signal_vector), k=5)
        p = res.patterns[0]
        assert isinstance(p, _FrozenDict)
        with pytest.raises(TypeError):
            p["id"] = "tampered"
        assert isinstance(p["signals"], tuple)
        with pytest.raises(AttributeError):
            p["signals"].append("x")

    def test_hydrate_does_not_corrupt_corpus(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        vid = multi_signal_vector
        before = list(kb.get_threat(vid)["signals"])
        kb.hydrate(kb.signal_ids_for(vid), k=_TOPK_CAP)
        assert kb.get_threat(vid)["signals"] == before

    def test_ranking_deterministic(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        sigs = kb.signal_ids_for(multi_signal_vector)
        runs = [[p["id"] for p in kb.hydrate(sigs, k=10).patterns] for _ in range(5)]
        assert all(r == runs[0] for r in runs)
        fresh = [p["id"] for p in KnowledgeLoader().hydrate(sigs, k=10).patterns]
        assert fresh == runs[0]

    def test_k_bound_is_a_prefix(self, kb: KnowledgeLoader) -> None:
        """k caps the result as a prefix. Built on a constructed multi-seed set so
        there are >= 2 hydrated nodes to slice (the S1 real corpus is seed-only and a
        single vector owns all its own signals)."""
        loader = KnowledgeLoader()
        # seed several distinct single-signal vectors so >= 2 nodes hydrate
        idx = loader.get_signal_index()
        seeds: list[str] = []
        seen: set[str] = set()
        for e in idx:
            vid = e["vector_ids"][0]
            if len(e["vector_ids"]) == 1 and vid not in seen:
                seen.add(vid)
                seeds.append(e["signal_id"])
            if len(seeds) >= 4:
                break
        full = [p["id"] for p in loader.hydrate(seeds, k=_TOPK_CAP).patterns]
        assert len(full) >= 2
        k2 = [p["id"] for p in loader.hydrate(seeds, k=2).patterns]
        assert k2 == full[:2]

    def test_two_tier_seed_outranks_pure_hub_constructed(self, kb: KnowledgeLoader, multi_signal_vector: str) -> None:
        """A directly-matched seed (tier True) is never displaced by a zero-direct-vote
        fan-out neighbour even when the neighbour accumulates a HIGHER score. Built as
        a constructed fixture (Directive 8): a heavy seed S (many own signals) fans
        out to hub H; a light seed A (one own signal) is seeded too. H's propagated
        score exceeds A's direct score, yet both seeds outrank H."""
        loader = KnowledgeLoader()
        idx = loader.get_signal_index()
        counts: dict[str, int] = {}
        for e in idx:
            for v in e["vector_ids"]:
                counts[v] = counts.get(v, 0) + 1
        by_count = sorted(counts.items(), key=lambda kv: (kv[1], kv[0]))
        light = by_count[0][0]                              # fewest own signals
        heavy = by_count[-1][0]                             # most own signals
        assert counts[heavy] > counts[light], "need a heavier seed than the light one"
        hub = next(v["id"] for v in loader.get_all_threats() if v["id"] not in (heavy, light))
        real = loader._vector_index[heavy]
        loader._vector_index[heavy] = {**real, "alternatives": [hub]}
        seeds = loader.signal_ids_for(heavy) + loader.signal_ids_for(light)
        res = loader.hydrate(seeds, k=_TOPK_CAP)
        order = [p["id"] for p in res.patterns]
        assert hub in order and heavy in order and light in order
        # both seeds outrank the pure hub, though the hub's score >= the light seed's
        assert order.index(heavy) < order.index(hub)
        assert order.index(light) < order.index(hub)
        hub_node = next(p for p in res.patterns if p["id"] == hub)
        light_node = next(p for p in res.patterns if p["id"] == light)
        assert hub_node["retrieval"]["seed"] is False
        assert hub_node["retrieval"]["score"] >= light_node["retrieval"]["score"]

    def test_ceilings_unchanged(self) -> None:
        assert (_SEED_CAP, _TOPK_CAP, _CONFIDENCE_FLOOR) == (64, 50, 2)


# ==========================================================================
# Free-function primitives (deep_freeze) + facet gate (ported, DORMANT)
# ==========================================================================

class TestPrimitives:
    def test_deep_freeze_severs_references(self) -> None:
        src = {"a": [1, 2, {"b": 3}]}
        frozen = deep_freeze(src)
        assert isinstance(frozen, _FrozenDict)
        assert isinstance(frozen["a"], tuple)
        assert isinstance(frozen["a"][2], _FrozenDict)
        src["a"].append(99)                 # mutating the source must not touch the copy
        assert 99 not in frozen["a"]

    def test_facet_gate_dormant_on_threat_corpus(self, kb: KnowledgeLoader) -> None:
        """The ported facet gate is DORMANT: no threat vector carries an avoid_when
        facet dict, so is_gated is always False (the LIVE gate is filter_by_constraints)."""
        for vec in kb.get_all_threats():
            assert L.is_gated(vec, {"team_size": "1", "scale": "startup"}) is False

    def test_split_conditions_partitions_by_type(self) -> None:
        texts, facets = L.split_conditions(["free text", {"team_size": "1-5"}, "more text"])
        assert texts == ["free text", "more text"]
        assert facets == [{"team_size": "1-5"}]

    def test_parse_team_range(self) -> None:
        assert L._parse_team_range("1-5") == (1, 5)
        assert L._parse_team_range("3") == (3, 3)
        assert L._parse_team_range("50+")[0] == 50
        assert L._parse_team_range("garbage") is None


# ==========================================================================
# Dual-loader — ONE engine, both loaders inherit it (no live DB required:
# the graph loader delegates its read path to the JSON parent)
# ==========================================================================

class TestDualLoader:
    def test_both_loaders_inherit_one_engine(self) -> None:
        from hyperion.knowledge.graph_loader import GraphKnowledgeLoader
        assert issubclass(KnowledgeLoader, _SignalEngine)
        assert issubclass(GraphKnowledgeLoader, _SignalEngine)
        # the engine methods are the SAME objects on both (no duplicate engine code)
        assert KnowledgeLoader._hydrate is _SignalEngine._hydrate
        assert GraphKnowledgeLoader._hydrate is _SignalEngine._hydrate
        assert KnowledgeLoader._build_signal_index is _SignalEngine._build_signal_index
        # the public bindings are inherited unchanged by the graph loader
        assert GraphKnowledgeLoader.get_signal_index is KnowledgeLoader.get_signal_index
        assert GraphKnowledgeLoader.hydrate is KnowledgeLoader.hydrate
        assert GraphKnowledgeLoader.signal_ids_for is KnowledgeLoader.signal_ids_for
        # the S2 agent-index bindings (the second view of the nested accessor) too
        assert GraphKnowledgeLoader.get_agent_signal_index is KnowledgeLoader.get_agent_signal_index
        assert GraphKnowledgeLoader.hydrate_agent is KnowledgeLoader.hydrate_agent
        assert GraphKnowledgeLoader.agent_signal_ids_for is KnowledgeLoader.agent_signal_ids_for


# ==========================================================================
# S2 agent-threat index — the SECOND _NamedIndex, edgeless/direct-vote-only,
# reusing every _SignalEngine primitive (zero duplicated engine code).
# ==========================================================================

class TestAgentSignalIndex:
    def test_view_shape_covers_all_detection_signals(self, kb: KnowledgeLoader) -> None:
        view = kb.get_agent_signal_index()
        distinct = {
            s.strip()
            for t in kb.get_all_agent_threats()
            for s in t.get("detection_signals", [])
            if s.strip()
        }
        assert len(view) == len(distinct)
        assert all(set(e) == {"signal_id", "signal_text", "agent_threat_ids"} for e in view)
        assert all(e["signal_id"] == _signal_id(e["signal_text"]) for e in view)

    def test_deterministic_and_sorted(self, kb: KnowledgeLoader) -> None:
        a = kb.get_agent_signal_index()
        assert a == kb.get_agent_signal_index()
        assert [e["signal_id"] for e in a] == sorted(e["signal_id"] for e in a)
        assert all(e["agent_threat_ids"] == sorted(e["agent_threat_ids"]) for e in a)

    def test_signal_ids_for_round_trips_to_the_node(self, kb: KnowledgeLoader) -> None:
        aid = kb.get_agent_signal_index()[0]["agent_threat_ids"][0]
        sids = kb.agent_signal_ids_for(aid)
        assert sids and sids == sorted(sids)
        idx = {e["signal_id"]: e for e in kb.get_agent_signal_index()}
        assert all(aid in idx[s]["agent_threat_ids"] for s in sids)
        assert kb.agent_signal_ids_for("no-such-agent") == []

    def test_hydrate_agent_hits_the_seed(self, kb: KnowledgeLoader) -> None:
        aid = kb.get_agent_signal_index()[0]["agent_threat_ids"][0]
        res = kb.hydrate_agent(kb.agent_signal_ids_for(aid), k=10)
        assert res.state in (HIT, LOW_CONFIDENCE)
        assert aid in {p["id"] for p in res.patterns}

    def test_agent_index_is_edgeless_direct_vote_only(self, kb: KnowledgeLoader) -> None:
        """agent_threats carry no ``alternatives`` edge, so fan-out on/off is
        identical — the view is direct-vote-only by construction, no propagated
        neighbours and no dangling."""
        aid = kb.get_agent_signal_index()[0]["agent_threat_ids"][0]
        sids = kb.agent_signal_ids_for(aid)
        on = kb.hydrate_agent(sids, k=_TOPK_CAP, fan_out=True)
        off = kb.hydrate_agent(sids, k=_TOPK_CAP, fan_out=False)
        assert [p["id"] for p in on.patterns] == [p["id"] for p in off.patterns]
        assert all(p["retrieval"]["seed"] for p in on.patterns)
        assert on.dangling == []

    def test_empty_and_unrecognised_are_no_match(self, kb: KnowledgeLoader) -> None:
        assert kb.hydrate_agent([]).state == NO_MATCH
        assert kb.hydrate_agent(["sig-nope00000000"]).state == NO_MATCH

    def test_disjoint_from_threat_index_mis_typed_id_abstains(self, kb: KnowledgeLoader) -> None:
        """A threat-vector signal id fed to the agent view (and vice-versa) misses in
        the wrong corpus and abstains — the nested two-view routes by construction."""
        threat_sid = kb.get_signal_index()[0]["signal_id"]
        agent_sid = kb.get_agent_signal_index()[0]["signal_id"]
        assert threat_sid != agent_sid
        assert kb.hydrate_agent([threat_sid]).state == NO_MATCH
        assert kb.hydrate([agent_sid]).state == NO_MATCH


# ==========================================================================
# S2 dissolve — decision_rules folded onto the vectors' own signals (COPY),
# provenance kept; the on-disk corpus and the matcher are untouched.
# ==========================================================================

class TestDissolve:
    def test_structural_signals_recognised_on_the_threat_view(self, kb: KnowledgeLoader) -> None:
        view = {e["signal_text"].strip(): e for e in kb.get_signal_index()}
        for text, prov in kb._dissolved_provenance.items():
            assert text in view
            for vid in prov["vectors"]:
                assert vid in view[text]["vector_ids"]

    def test_provenance_kept_for_every_dissolved_signal(self, kb: KnowledgeLoader) -> None:
        assert kb._dissolved_provenance
        for text, prov in kb._dissolved_provenance.items():
            assert text.strip() == text and text
            assert prov["rules"] and prov["vectors"]

    def test_decision_rules_json_unchanged_on_disk(self, kb: KnowledgeLoader) -> None:
        """In-memory COPY, not move: the dissolve never writes the corpus, so each
        rule's structural_signal is still present verbatim in ``kb._rules`` (the
        loaded decision_rules.json). The recognition path is the accessor; the
        rules table stays the untouched provenance source."""
        assert kb._rules
        for rule in kb._rules:
            assert "structural_signal" in rule
