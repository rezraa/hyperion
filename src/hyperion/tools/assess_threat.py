# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: assess_threat — wired onto the Shape-C retrieval engine (S3).

Council b420a9f0 / m-73ea1894; standard m-55f6d4da (settled — cite, do not
re-litigate). Hyperion's threat-modelling tool on the proven four-step template
(retrieve via matched_signal_ids+hydrate → optional deterministic gate → reason
over each node's OWN fields → fail-closed envelope), applied over Hyperion's TWO
disjoint, signal-bearing corpora:

1. RETRIEVE — the caller recognises a system's signals against the ONE nested
   accessor ``get_signal_index`` and passes the matched ids here. One
   ``kb.hydrate`` call resolves the threat-vector ids; one ``kb.hydrate_agent``
   call resolves the agent-threat ids. The two id-spaces are disjoint, so each
   view picks up only its own ids and abstains (NO_MATCH) on the other's — no
   routing code. This REPLACES the retired substring decision-rule island, which
   returned an EMPTY model on natural-language signals (S0 premise: leg1 18/240;
   the verbatim signal "user input concatenated into SQL query string" produced
   ``threat_model []``) — the whole reason for the retrofit.
2. GATE — the optional deterministic gate is ``kb.filter_by_constraints``
   (category / severity floor / owasp) over the hydrated threat vectors; excluded
   vectors survive as ``filtered_out`` with their reason, reasoning over each
   vector's OWN metadata. No ``environment`` multiplier, no fabricated scalar.
3. REASON — ``threat_model`` is built from each hydrated vector's OWN fields
   (cwe / owasp / mitre_attack / severity / attack_surface / remediation) and
   ``agent_risks`` from each hydrated agent_threat's OWN fields (mitigation /
   attack_patterns). No hardcoded surface table and no fabricated risk verdict:
   the tool surfaces each node's own severity AS DATA. Computing or inventing a
   risk score is Hyperion's judgment, not the tool's (out of scope, S3).
4. ENVELOPE — both view states (hit / low_confidence / no_match / dangling) are
   surfaced; a field-short/absent id is recorded ``dangling``, never emitted as a
   husk (the husk guard drops it upstream). Empty/mistyped ids → NO_MATCH with the
   ids surfaced in ``unmatched_signals``.

The retired ``structural_signals`` prose param has NO alias shim — its
replacement is a different vocabulary (matched signal ids). The inline recognition
islands (decision-rule, agent-threat-pattern, agent-signal and risk-level tables)
are DELETED from this module, the substring matcher is deleted at zero callers, and
the drifted server.py inline @mcp.tool copy now delegates to this filed body — one
source of truth, no shim. Firewall: imports only hyperion.*.
"""

from __future__ import annotations

from typing import Any

from hyperion.knowledge.loader import HIT, LOW_CONFIDENCE, NO_MATCH
from hyperion.tools._shared import (
    _MAX_MATCHED_SIGNALS,
    coerce,
    emit_event,
    get_knowledge,
    normalize_kwargs,
    project_node,
)

# Caller kwarg synonyms remapped to the canonical signature (read by
# @normalize_kwargs). ``_ALIASES`` carries ONLY genuine synonyms of a REAL current
# param: ``system``/``description`` both mean ``system_description`` (the tool's one
# text param). ``_IGNORED`` carries the RETIRED vocabulary of the deleted substring
# matcher — dropped-with-warning so an old-style caller gets the loud guidance
# envelope below instead of a raw TypeError. Retired vocab is IGNORED, never aliased
# to matched_signal_ids: it is a DIFFERENT vocabulary (prose, not ids), and aliasing
# it onto the id list would resurrect the very substring matcher S3 deleted — the
# retired prose param stays retired.
_ALIASES = {"system": "system_description", "description": "system_description"}
_IGNORED = {"structural_signals", "assets"}

# The self-correcting guidance ridden on an abstaining envelope (below). A caller
# turned away by argument shape alone — prose or a mistyped/omitted id, or a retired
# param @normalize_kwargs just dropped — otherwise gets a bare empty model with no way
# to recover, and that silent no_match also trips Othrys' reactive coverage-gap hook
# into a FALSE gap proposal for an existing signal. Naming the expected shape and the
# accessor turns the dead-end into a next step.
_GUIDANCE = (
    "No threat vectors or agent risks matched. `matched_signal_ids` must be a list "
    "of signal ids recognised against `get_signal_index` (its `threat_signals` / "
    "`agent_threat_signals` views) — not prose, a system description, or a retired "
    "param. Call `get_signal_index`, match this system's signals against it, and "
    "pass the resulting ids as `matched_signal_ids`."
)

# The threat-vector fields the model surfaces — each vector's OWN data (no table).
_THREAT_FIELDS: tuple[str, ...] = (
    "id", "name", "category", "severity", "description",
    "cwe", "owasp", "mitre_attack", "attack_surface", "remediation",
)
# The agent-threat fields the risks surface — each agent_threat's OWN data.
_AGENT_FIELDS: tuple[str, ...] = (
    "id", "name", "category", "severity", "description",
    "attack_patterns", "mitigation",
)


@normalize_kwargs
def assess_threat(
    system_description: str,
    matched_signal_ids: list[str] | None = None,
    constraints: dict | None = None,
    k: int = 10,
    conn: object = None,
) -> dict:
    """Build a threat model from signal ids the caller recognised against the index.

    Args:
        system_description: What the system does — context/telemetry only
            (retrieval is driven by ``matched_signal_ids``, not this text).
        matched_signal_ids: Signal ids the caller recognised against
            ``get_signal_index`` (both views). Threat-vector ids hydrate the
            ``threat_model``; agent-threat ids hydrate ``agent_risks``; the disjoint
            id-spaces route each id to exactly one corpus. Omitted / None / mistyped
            abstains cleanly (coerced to ``[]``) instead of raising. The retired
            ``structural_signals`` prose param has NO alias shim — it is dropped with
            a warning by ``@normalize_kwargs`` (see ``_IGNORED``), never resurrected.
        constraints: Optional dict — ``category`` / ``severity`` (floor) / ``owasp``
            drive the deterministic exclusion gate over the hydrated threat vectors.
        k: Number of ranked results per view (engine-clamped to 1..50).
        conn: Kuzu/LadybugDB connection for graph mode, or None for the JSON
            singleton (both loaders share one engine).

    Returns:
        ``threat_model`` (hydrated vectors' own fields) / ``agent_risks`` (hydrated
        agent_threats' own fields) / ``filtered_out`` / ``threat_retrieval_state`` /
        ``agent_retrieval_state`` / ``unmatched_signals`` / ``dangling``. Fail-closed:
        an abstaining envelope returns empty lists, never a husk. When nothing was
        recognised and nothing was gated out, an ADDITIVE ``guidance`` field names the
        expected shape and the accessor (never present on a hit).
    """
    # Fail-safe at the caller boundary: a malformed payload abstains cleanly.
    matched_signal_ids = coerce(matched_signal_ids, list, default=[])
    constraints = coerce(constraints, dict, default={})
    try:
        k = int(k)
    except (TypeError, ValueError):
        k = 10

    kb = get_knowledge(conn)

    # 1. RETRIEVE — one hydrate per corpus over the SAME capped id list. The
    #    caller-boundary ceiling bounds untrusted input before the engine (which
    #    bounds its own fan-out downstream); disjoint id-spaces make each view
    #    resolve only its own ids and abstain on the other's, so no routing needed.
    capped = matched_signal_ids[:_MAX_MATCHED_SIGNALS]
    tres = kb.hydrate(capped, k=k)
    ares = kb.hydrate_agent(capped, k=k)

    # 2. GATE — optional deterministic constraint exclusion over the hydrated threat
    #    vectors, reasoning over each vector's OWN category/severity/owasp; excluded
    #    vectors surface in filtered_out. Agent risks carry no owasp/attack_surface,
    #    so they pass through ungated. No fabricated scalar.
    vectors = list(tres.patterns)
    filtered_out: list[dict[str, Any]] = []
    if constraints:
        vectors, removed = kb.filter_by_constraints(vectors, constraints)
        filtered_out = [
            {
                "id": r.get("id", ""),
                "name": r.get("name", r.get("id", "")),
                "severity": r.get("severity", ""),
                "reason": r.get("filter_reason", ""),
            }
            for r in removed
        ]

    # 3. REASON — build both views from each node's OWN fields (no hardcoded table).
    threat_model = [project_node(v, _THREAT_FIELDS) for v in vectors]
    agent_risks = [project_node(a, _AGENT_FIELDS) for a in ares.patterns]

    # The surfaced threat state must describe the POST-gate model, not the raw
    # retrieval: when the constraint gate removes every hydrated vector, a
    # non-abstaining pre-gate state (hit / low_confidence) would label an empty
    # threat_model — a broken state<->data contract in the fail-closed envelope.
    # Collapse it to the existing abstaining NO_MATCH (no fifth state; the
    # four-state envelope is settled — council b420a9f0 / m-73ea1894), with
    # filtered_out naming which constraint removed what. Genuine abstentions
    # (no_match / dangling) already carry an empty model consistently.
    threat_state = tres.state
    if not vectors and threat_state in (HIT, LOW_CONFIDENCE):
        threat_state = NO_MATCH

    # 4. ENVELOPE — surface both fail-closed states + the integrity signals. The
    #    truly-unrecognised ids are those NEITHER view resolved (disjoint spaces =
    #    the intersection of the two unmatched lists); dangling is the union of any
    #    referenced id that failed to resolve to a genuine node — surfaced, not masked.
    unmatched = sorted(set(tres.unmatched_signals) & set(ares.unmatched_signals))
    dangling = sorted(set(tres.dangling) | set(ares.dangling))

    result: dict[str, Any] = {
        "threat_model": threat_model,
        "agent_risks": agent_risks,
        "filtered_out": filtered_out,
        "threat_retrieval_state": threat_state,
        "agent_retrieval_state": ares.state,
        "unmatched_signals": unmatched,
        "dangling": dangling,
    }

    # Ride the self-correcting guidance ONLY on a genuine no-recognition abstention:
    # nothing retrieved AND nothing gated out. ``filtered_out`` empty is the line
    # between "you gave me nothing I recognise" (guide the caller to the accessor)
    # and "your constraint removed a real hit" (already self-explained by
    # filtered_out) — the latter must NOT be told its ids were wrong. The field is
    # ADDITIVE: it never appears on a hit, and adds no fifth state / no *_retrieval_
    # state key, so the dual-state contract the reactive gap hook keys on is intact.
    if not threat_model and not agent_risks and not filtered_out:
        result["guidance"] = _GUIDANCE

    emit_event("assess_threat", {
        "system_description": system_description[:120] if isinstance(system_description, str) else "",
        "n_signals": len(matched_signal_ids),
        "threat_state": threat_state,
        "agent_state": ares.state,
        "threat_model_count": len(threat_model),
        "agent_risks_count": len(agent_risks),
    })

    return result
