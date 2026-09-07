# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Decoupling firewall + semantic-parity drift test (Hyperion S1, story-e13a6ac9).

The Shape-C engine in Hyperion is a JUSTIFIED MIRROR of the shipped
mnemos/coeus/theia/themis ``_SignalEngine`` (council b420a9f0 / m-73ea1894,
standard m-55f6d4da), NOT a shared import: Hyperion runs standalone and its runtime
code MUST NOT import othrys.*/coeus.*/mnemos.*/theia.*/themis.* (the
titan-decoupling firewall, feedback_titan_decoupling_no_othrys_import). This module
proves both halves:

* ``TestImportFirewall`` — no shipping module under ``src/hyperion`` imports a
  sibling or othrys (static AST source scan);
* ``TestMirrorParity`` — the mirror stays faithful: the ported primitives are
  SEMANTICALLY identical to a shipped sibling's. Skip-guarded when no sibling is
  importable (test-only; siblings are sibling repos, never shipping deps) — the
  ONE place a drift test may reach a sibling, per the council standard. This is
  the enforcement mechanism the firewall's ban on a shared lib requires. The
  sanctioned sibling import is popped from ``sys.modules`` in teardown so it never
  leaks into the process the S0 ``sys.modules`` firewall assertion checks.
"""

from __future__ import annotations

import ast
import dataclasses as dc
import sys
from pathlib import Path

import pytest

import hyperion.knowledge.loader as t

_SRC = Path(t.__file__).resolve().parents[2]  # .../src
_FORBIDDEN = ("othrys", "coeus", "mnemos", "theia", "themis")


# ==========================================================================
# Import firewall — shipping code imports no othrys/coeus/mnemos/theia/themis
# ==========================================================================

def _forbidden_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in _FORBIDDEN:
                    bad.append(f"import {a.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in _FORBIDDEN:
                bad.append(f"from {node.module} import ...")
    return bad


class TestImportFirewall:
    def test_no_forbidden_import_in_shipping_code(self) -> None:
        offenders: dict[str, list[str]] = {}
        for py in sorted((_SRC / "hyperion").rglob("*.py")):
            bad = _forbidden_imports(py)
            if bad:
                offenders[str(py.relative_to(_SRC))] = bad
        assert not offenders, f"firewall breach — sibling imported in shipping code: {offenders}"

    def test_engine_module_imports_are_stdlib_and_local_only(self) -> None:
        """The engine module (loader.py) imports nothing from a sibling. Its docstring
        cites the mirror source by name for provenance — that is a comment, not an
        import; the AST scan is what governs."""
        assert _forbidden_imports(Path(t.__file__)) == []


# ==========================================================================
# Semantic-parity drift test (test-only, skip-guarded)
# ==========================================================================

def _load_sibling():
    """Import a sibling engine (mnemos preferred, coeus/theia/themis fallback),
    adding the sibling ``../<name>/src`` if needed. Test-only path injection — never
    a shipping dep. Returns the module or None (caller skips)."""
    repos = _SRC.parents[1]  # .../<repos>  (hyperion/src -> hyperion -> <repos>)
    for name in ("mnemos", "coeus", "theia", "themis"):
        try:
            return __import__(f"{name}.knowledge.loader", fromlist=["loader"])
        except ImportError:
            sib = repos / name / "src"
            if (sib / name / "knowledge" / "loader.py").exists():
                sys.path.insert(0, str(sib))
                try:
                    return __import__(f"{name}.knowledge.loader", fromlist=["loader"])
                except ImportError:
                    continue
    return None


class TestMirrorParity:
    @pytest.fixture(scope="class")
    def s(self):
        sib = _load_sibling()
        if sib is None:
            pytest.skip("no sibling engine importable — drift test skip-guarded")
        yield sib
        # Firewall hygiene: the sanctioned drift-test sibling import must NOT leak
        # into sys.modules, or the S0 sys.modules firewall assertion (frozen) would
        # trip when it runs later in the same session. Pop every sibling module the
        # import brought in.
        for name in list(sys.modules):
            if name.split(".")[0] in _FORBIDDEN:
                del sys.modules[name]

    def test_ceilings_and_floor_parity(self, s) -> None:
        assert (t._SEED_CAP, t._TOPK_CAP, t._CONFIDENCE_FLOOR) == \
               (s._SEED_CAP, s._TOPK_CAP, s._CONFIDENCE_FLOOR)

    def test_state_vocabulary_parity(self, s) -> None:
        assert (t.HIT, t.LOW_CONFIDENCE, t.NO_MATCH, t.DANGLING) == \
               (s.HIT, s.LOW_CONFIDENCE, s.NO_MATCH, s.DANGLING)

    def test_signal_id_hash_parity(self, s) -> None:
        for x in ["sql string concatenation", "hardcoded api key", "x", "  spaced  "]:
            assert t._signal_id(x) == s._signal_id(x)

    def test_retrieval_result_contract_parity(self, s) -> None:
        assert [f.name for f in dc.fields(t.RetrievalResult)] == \
               [f.name for f in dc.fields(s.RetrievalResult)]

    def test_deep_freeze_parity(self, s) -> None:
        src = {"a": [1, {"b": 2}], "c": "s"}
        tf, sf = t.deep_freeze(src), s.deep_freeze(src)
        assert type(tf).__name__ == type(sf).__name__ == "_FrozenDict"
        assert isinstance(tf["a"], tuple) and isinstance(sf["a"], tuple)
        for frozen in (tf, sf):
            with pytest.raises(TypeError):
                frozen["a"] = 1

    def test_facet_primitives_parity(self, s) -> None:
        cases = ["1-5", "3", "50+", "garbage", ""]
        assert [t._parse_team_range(x) for x in cases] == [s._parse_team_range(x) for x in cases]
        facet, cons = {"team_size": "1-10", "scale": "startup"}, {"team_size": "3", "scale": "startup"}
        assert t.facet_matches(facet, cons) == s.facet_matches(facet, cons) is True
        assert t.facet_matches(facet, {"team_size": "3"}) == s.facet_matches(facet, {"team_size": "3"}) is False
        mixed = ["free text", {"team_size": "1-5"}]
        assert t.split_conditions(mixed) == s.split_conditions(mixed)

    def test_hydrate_envelope_contract_parity(self, s) -> None:
        """Behavioural parity of the OUTPUT CONTRACT: the sibling's engine on its
        corpus and Hyperion's on the threat-vector corpus emit the same-shaped
        envelope (same state vocab, same retrieval-block keys, int votes, frozen
        nodes). The corpora and edges differ by design; the CONTRACT does not."""
        t_kb = t.KnowledgeLoader()
        s_kb = s.KnowledgeLoader()
        t_sig = t_kb.get_signal_index()[0]["signal_id"]
        s_sig = s_kb.get_signal_index()[0]["signal_id"]
        tr = t_kb.hydrate([t_sig], k=5)
        sr = s_kb.hydrate([s_sig], k=5)
        assert tr.state in (t.HIT, t.LOW_CONFIDENCE) and sr.state in (s.HIT, s.LOW_CONFIDENCE)
        assert type(tr).__name__ == type(sr).__name__ == "RetrievalResult"
        if tr.patterns and sr.patterns:
            assert set(tr.patterns[0]["retrieval"]) == set(sr.patterns[0]["retrieval"]) == \
                   {"score", "direct_votes", "propagated_votes", "seed"}
            assert isinstance(tr.votes[tr.patterns[0]["id"]], int)
            assert isinstance(sr.votes[sr.patterns[0]["id"]], int)
