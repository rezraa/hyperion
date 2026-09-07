# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: get_signal_index

The ONE reachable signal-index accessor for Hyperion (council b420a9f0 /
m-73ea1894; standard m-55f6d4da; nested-view precedent Theia m-3b1847c6 / council
ae492280). Returns the nested two-view over Hyperion's two disjoint,
signal-bearing corpora::

    {
      "threat_signals":       [{"signal_id", "signal_text", "vector_ids"}, ...],
      "agent_threat_signals": [{"signal_id", "signal_text", "agent_threat_ids"}, ...],
    }

Filename == function == exactly ONE public top-level function. The two views live
behind a SINGLE public function on purpose: a caller cannot reach one stratum and
drop the other, so the co-location seed-drop bug class is impossible by
construction. The id columns (``vector_ids`` / ``agent_threat_ids``) encode the
corpus, and the id-spaces are disjoint, so a mis-typed signal id simply misses in
the wrong corpus and the engine abstains via NO_MATCH — no routing code needed.

The LLM recognises a problem's signals against these two labelled surfaces and
passes the matched ids to the corpus's hydrate path (``hydrate`` for threat
vectors, ``hydrate_agent`` for agent threats). Both views are deterministic and
byte-reproducible (each sorted by ``signal_id`` with sorted id-lists), composed
from the loader's per-view bindings — the engine and both hydrate paths are the one
source of truth; this module only composes.
"""

from __future__ import annotations

from typing import Any

from hyperion.tools._shared import get_knowledge


def get_signal_index(conn: Any = None) -> dict:
    """Return the nested two-view signal index over both Hyperion corpora.

    Args:
        conn: Kuzu/LadybugDB connection for graph mode, or None for the JSON
            singleton (injected by Othrys; both loaders share one engine).

    Returns:
        ``{"threat_signals": [...], "agent_threat_signals": [...]}`` — see the
        module docstring for each entry's shape.
    """
    kb = get_knowledge(conn)
    return {
        "threat_signals": kb.get_signal_index(),
        "agent_threat_signals": kb.get_agent_signal_index(),
    }
