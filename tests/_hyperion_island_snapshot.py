# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Frozen snapshot of the deleted scan-detector islands -- the relocated test oracle.

R4 (council 49fd71da) DELETES ``scan_code``'s six in-code island lists and
``_get_patterns`` and rewires the scanner to read its detectors from the DB
(``loader.get_code_detectors``). The R2/S5/S6 proofs still need the island firing
as their reference RHS, so the island is reconstructed HERE from the byte-frozen
``tests/_hyperion_code_detectors.json`` artifact (sha256
b294846e..., R2's frozen snapshot) -- never from a live production symbol and never
from the live corpus, so this leaf remains a faithful witness even after the
production islands are gone.

DB == the original hand-written islands is a frozen historical fact (R1/b3e46ac8 +
R2 artifact), not a live re-derivable equality (Coeus's recorded reservation): this
oracle pins WHAT the islands fired at the moment R2 froze them, so a later drift in
the loader's resolution or in the corpus is caught by a parity FAILURE rather than
silently tracked. That is why the resolution below is reimplemented from the frozen
bytes and NOT imported from ``loader`` -- an oracle that reused the production
resolution could not witness a production resolution bug.
"""

from __future__ import annotations

import json
from pathlib import Path

# The byte-frozen R2 artifact -- the canonical form of code_detectors.json at the
# moment R2 pinned it. The single source this oracle reads.
_FROZEN_ARTIFACT = Path(__file__).parent / "_hyperion_code_detectors.json"

# The alias + fallback resolution the deleted islands did by hand, reimplemented
# from the frozen bytes so this oracle is independent of the production loader.
_LANGUAGE_ALIASES = {
    "py": "python",
    "js": "javascript",
    "ts": "javascript",
    "typescript": "javascript",
}


# The island tuple layout: (name, regex, severity, cwe, description, remediation).
# A migrated detector's fields project onto it in this order (R2's parity shape).
def _detector_tuple(d: dict) -> tuple[str, str, str, str, str, str]:
    """Project a code_detectors.json entry onto the island tuple's field order."""
    return (
        d["name"],
        d["regex"],
        d["base_severity"],
        d["cwe"],
        d["description"],
        d["remediation"],
    )


def _load_frozen_detectors() -> list[dict]:
    """The frozen detector list, in file order (the source of truth for the oracle)."""
    return json.loads(_FROZEN_ARTIFACT.read_text(encoding="utf-8"))["detectors"]


def _split_islands() -> tuple[list[dict], dict[str, list[dict]]]:
    """Bucket the non-agent detectors into (universal, {language: named}) in file order.

    Universal (``["*"]``) detectors fold ahead of a language's own, mirroring the
    islands' universal-then-language extend order. Agent-signal-gated detectors are
    excluded (they run only when _has_agent_signals fires).
    """
    universal: list[dict] = []
    named: dict[str, list[dict]] = {}
    for det in _load_frozen_detectors():
        if det.get("requires_agent_signals"):
            continue
        langs = det.get("languages", [])
        if "*" in langs:
            universal.append(det)
        else:
            for lang in langs:
                named.setdefault(lang, []).append(det)
    return universal, named


def island_reference(language: str) -> list[tuple[str, str, str, str, str, str]]:
    """The island firing set for *language*, projected as (name, regex, severity,
    cwe, description, remediation) tuples in the islands' iteration order.

    Resolves aliases (py -> python; js/ts/typescript -> javascript) and the
    unknown-language fallback (universal + BOTH python & js import sets, in
    universal-then-python-then-js order), case-insensitively -- exactly what the
    deleted ``_get_patterns`` did by hand. Fresh list per call.
    """
    lang = language.lower()
    lang = _LANGUAGE_ALIASES.get(lang, lang)
    universal, named = _split_islands()
    if lang == "python":
        detectors = universal + named.get("python", [])
    elif lang == "javascript":
        detectors = universal + named.get("javascript", [])
    else:
        # Unknown language: include both import sets, universal-then-python-then-js.
        detectors = universal + named.get("python", []) + named.get("javascript", [])
    return [_detector_tuple(d) for d in detectors]


# The 7 agent-signal-gated detectors, in file order (== the deleted _AGENT_THREATS).
# A tuple so an importer cannot mutate the shared reference.
ISLAND_AGENT_REFERENCE: tuple[tuple[str, str, str, str, str, str], ...] = tuple(
    _detector_tuple(d) for d in _load_frozen_detectors() if d.get("requires_agent_signals")
)
