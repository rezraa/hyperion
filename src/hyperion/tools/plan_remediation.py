# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: plan_remediation — wired onto the Shape-C retrieval engine (S4).

Council b420a9f0 / m-73ea1894; standard m-55f6d4da (settled — cite, do not
re-litigate). The SEED-FROM-NODE member of the four-step template (the same shape
Mnemos' ``suggest_refactor`` inherits): the caller already HOLDS a finding's
identity, so retrieval is seeded from THAT threat vector's OWN signals
(``kb.signal_ids_for`` -> ONE ``kb.hydrate``) — no signal-recognition step — and
hydrate's one-hop fan-out expands over the vector's ``alternatives`` edge, so the
related set IS the fan-out the corpus records.

1. RESOLVE — a finding names its vector by ``threat_id`` (preferred) or by ``cwe``,
   which maps to vector ids through the corpus-built ``kb.cwe_to_threat_ids`` bridge
   (built from each vector's OWN ``cwe`` list, so it equals the S0-frozen mapping by
   construction; one-to-many). A ``threat_id`` that is not a genuine, hydratable
   corpus node, or a ``cwe`` the corpus does not cover (e.g. CWE-95 / CWE-352), is a
   DANGLING reference — surfaced, never silently answered with a generic husk. This
   REPLACES the dead ``get_remediation(cwe)`` bridge: the loader keys remediation on
   ``threat_id`` (loader:get_remediation), so the old tool passed a CWE to a
   threat-id lookup and got ``None`` every time, then fell back to the inline
   remediation and generic-fallback islands — the whole reason for the retrofit.
   Both islands are DELETED from this module's path.
2. SEED + RETRIEVE — the resolved vectors' own signal ids drive ONE ``kb.hydrate``
   call — the proven four-state, fail-closed envelope. The resolved vectors are the
   top seeds (they own every seeded signal); hydrate's one-hop fan-out over
   ``alternatives`` supplies the related threats.
3. REASON — each remediation entry is built from its hydrated vector's OWN fields
   (remediation / examples / detection_patterns, plus cwe / severity / owasp /
   mitre_attack / attack_surface as data), never a hardcoded table. ``related_threats``
   is the pure fan-out (the propagated-only neighbours). The tool surfaces each
   vector's OWN severity AS DATA; it invents no priority/risk verdict (out of scope).
4. ENVELOPE — the four states (hit / low_confidence / no_match / dangling) are
   surfaced. A finding that references a vector absent/husk in the corpus, or a CWE
   the corpus does not cover, is ``dangling`` (fail closed, never a generic husk);
   a finding that references nothing resolvable is ``no_match``.

The retired ``language`` / ``constraints`` params (which only ever selected content
FROM the deleted islands — a language-keyed ``code_fix`` and constraint-adjusted
``steps`` / ``effort``) have NO alias shim; the corpus carries one ``remediation``
string and one ``examples`` pair per vector, and the language-agnostic corpus is the
one source of truth. The substring matcher is deleted at zero callers, and the
drifted server.py inline @mcp.tool copy now delegates to this filed body — no shim.
Firewall: imports only hyperion.*.
"""

from __future__ import annotations

from typing import Any

from hyperion.knowledge.loader import DANGLING, NO_MATCH
from hyperion.tools._shared import (
    _MAX_MATCHED_SIGNALS,
    coerce,
    emit_event,
    get_knowledge,
    project_node,
)

# The fields a remediation entry surfaces from its hydrated vector — each vector's
# OWN data (no table). ``remediation`` / ``examples`` / ``detection_patterns`` are
# the north-star content; the rest ride along as data (the vector's own severity,
# never an invented verdict). A field the vector does not carry is simply omitted.
_REMEDIATION_FIELDS: tuple[str, ...] = (
    "id", "name", "category", "severity", "cwe", "owasp", "mitre_attack",
    "attack_surface", "description", "remediation", "examples", "detection_patterns",
)
# The compact fields a related (fan-out) threat surfaces — enough to decide whether
# to pull its full remediation next, without re-emitting every field.
_RELATED_FIELDS: tuple[str, ...] = (
    "id", "name", "category", "severity", "cwe", "remediation",
)


# ---------------------------------------------------------------------------
# Priority calculation
# ---------------------------------------------------------------------------
# OUT OF SCOPE (S4): this per-CWE priority island invents a risk verdict, which the
# retrofit's tool no longer emits (it surfaces each vector's OWN severity as data).
# The story leaves the island byte-untouched and records its deletion/reconciliation
# as a follow-up — it is a SEPARATE hardcoded island the arc has not yet folded onto
# the corpus, not named by S4's AC. Retained here, dead, until that follow-up.

_SEVERITY_PRIORITY: dict[str, int] = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}

_EXPLOITABILITY_BOOST: dict[str, float] = {
    "CWE-89": 0.9,   # SQL injection -- very exploitable
    "CWE-78": 0.9,   # Command injection
    "CWE-95": 0.85,  # Code injection
    "CWE-79": 0.8,   # XSS
    "CWE-798": 0.7,  # Hardcoded creds -- easy to exploit once found
    "CWE-74": 0.85,  # Prompt injection
    "CWE-502": 0.7,  # Deserialization
    "CWE-352": 0.6,  # CSRF
    "CWE-327": 0.4,  # Weak crypto -- needs more effort
    "CWE-295": 0.5,  # Cert bypass -- needs MITM position
}


def _compute_priority(severity: str, cwe: str) -> dict[str, Any]:
    """Compute priority based on severity and exploitability."""
    base = _SEVERITY_PRIORITY.get(severity, 3)
    exploitability = _EXPLOITABILITY_BOOST.get(cwe, 0.5)

    # Lower number = higher priority
    adjusted = max(1, round(base * (1.0 - exploitability * 0.3)))

    labels = {1: "immediate", 2: "urgent", 3: "standard", 4: "low", 5: "backlog"}
    label = labels.get(adjusted, "standard")

    return {
        "priority_rank": adjusted,
        "priority_label": label,
        "exploitability": round(exploitability, 2),
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Finding -> genuine corpus threat ids
# ---------------------------------------------------------------------------

def _cwe_values(finding: dict) -> list[str]:
    """Normalise a finding's ``cwe`` (str or list) to a clean list of CWE ids."""
    raw = finding.get("cwe")
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, list):
        return [c.strip() for c in raw if isinstance(c, str) and c.strip()]
    return []


def _resolve_finding(
    kb: Any, threat_id: str, cwe_values: list[str],
) -> tuple[list[str], list[str], str]:
    """Resolve a finding to genuine, hydratable corpus threat ids (fail closed).

    Returns ``(resolved_ids, dangling_refs, source)``:

    * an explicit ``threat_id`` takes precedence; if it is not a genuine, hydratable
      corpus node it is a DANGLING reference (never a generic husk), and there is NO
      silent fall-back to the cwe — a broken finding fails closed loud;
    * otherwise each ``cwe`` maps through the corpus-built ``cwe_to_threat_ids``
      bridge; a cwe the corpus does not cover (CWE-95 / CWE-352) is a DANGLING
      reference — the coverage gap, recorded (corpus authoring is out of the arc).

    Hydratability is proven by ``signal_ids_for`` returning ids: that holds only for a
    node present in the signal index with its own signals — the exact precondition the
    seed-from-node hydrate needs — so a present-but-signal-less husk also dangles.
    """
    if threat_id:
        if kb.signal_ids_for(threat_id):
            return [threat_id], [], "threat_id"
        return [], [threat_id], "threat_id"

    # Bound the UNTRUSTED cwe list at the caller boundary, BEFORE the per-cwe cost
    # loop and the per-vector ``signal_ids_for`` loop it feeds — mirroring the sibling
    # ``assess_threat``, which caps its untrusted id list before the hydrate loop.
    # Dedup FIRST (a repeated cwe adds no coverage) so a legitimate multi-CWE finding
    # still hydrates every DISTINCT mapped vector, then cap the distinct set at the
    # shared ceiling. Without this a repeated/oversized cwe list amplifies linearly
    # into the seed loop (a CWE-400 resource-consumption path).
    distinct_cwes = list(dict.fromkeys(cwe_values))[:_MAX_MATCHED_SIGNALS]

    resolved: list[str] = []
    dangling: list[str] = []
    cwe_map = kb.cwe_to_threat_ids()
    for cwe in distinct_cwes:
        tids = cwe_map.get(cwe, [])
        if tids:
            resolved.extend(tids)
        else:
            dangling.append(cwe)
    # Distinct threat ids only: two CWEs can map to the same vector (a vector carries
    # a cwe LIST), so dedup — and re-apply the ceiling to the resolved set — before the
    # seed loop calls ``signal_ids_for`` once per vector. Work is now bounded by the
    # ceiling and the corpus, never by the caller's input length.
    resolved = list(dict.fromkeys(resolved))[:_MAX_MATCHED_SIGNALS]
    return resolved, dangling, ("cwe" if cwe_values else "none")


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

def plan_remediation(
    finding: dict,
    k: int = 10,
    conn: object = None,
) -> dict:
    """Plan the fix for a security finding, hydrated from the threat_vectors corpus.

    SEED-FROM-NODE: the finding names its vector (``threat_id`` preferred, else
    ``cwe`` via ``kb.cwe_to_threat_ids``); retrieval is seeded from that vector's OWN
    signals (``kb.signal_ids_for`` -> ``kb.hydrate``), whose one-hop fan-out over
    ``alternatives`` supplies the related threats — the caller passes no signal ids.

    Args:
        finding: Dict identifying the vulnerability. ``threat_id`` (str, a corpus
            vector id) is the preferred key; ``cwe`` (str or list) is the fallback,
            mapped to vector ids through the corpus-built bridge. ``severity`` /
            ``description`` / ``code_context`` are echoed context only. A ``threat_id``
            absent/husk in the corpus, or a ``cwe`` the corpus does not cover, yields a
            DANGLING envelope — never a generic husk.
        k: Number of ranked results (engine-clamped to 1..50).
        conn: Kuzu/LadybugDB connection for graph mode, or None for the JSON
            singleton (both loaders share one engine).

    Returns:
        ``remediations`` (each resolved vector's OWN remediation / examples /
        detection_patterns + its data fields) / ``related_threats`` (the fan-out) /
        ``retrieval_state`` / ``unmatched`` / ``dangling`` / ``source``. Fail-closed:
        an abstaining envelope returns empty lists, never a husk.
    """
    finding = coerce(finding, dict) or {}
    try:
        k = int(k)
    except (TypeError, ValueError):
        k = 10

    threat_id = finding.get("threat_id")
    threat_id = threat_id.strip() if isinstance(threat_id, str) else ""
    cwe_values = _cwe_values(finding)

    kb = get_knowledge(conn)

    # 1. RESOLVE the finding to genuine, hydratable corpus vector ids.
    resolved, dangling_refs, source = _resolve_finding(kb, threat_id, cwe_values)

    # Fail closed when nothing resolves: a referenced-but-unresolvable finding
    # (bad threat_id, or an uncovered cwe) is DANGLING; a finding that references
    # nothing resolvable is NO_MATCH. Never a silent generic husk.
    if not resolved:
        state = DANGLING if dangling_refs else NO_MATCH
        result = {
            "remediations": [],
            "related_threats": [],
            "retrieval_state": state,
            "unmatched": [],
            "dangling": sorted(dangling_refs),
            "source": source,
        }
        emit_event("plan_remediation", {
            "threat_id": threat_id,
            "cwe": cwe_values,
            "source": source,
            "state": state,
            "remediations_count": 0,
            "related_count": 0,
        })
        return result

    # 2. SEED + RETRIEVE — one hydrate over the resolved vectors' OWN signals. The
    #    untrusted finding input was already bounded at the RESOLVE step (the cwe list
    #    deduped + capped), and ``resolved`` is distinct + capped, so ``signal_ids_for``
    #    runs once per corpus vector — not once per caller-supplied cwe. The seed ids
    #    are capped again under the same ceiling before hydrate (which bounds its own
    #    fan-out downstream). The resolved vectors own every seeded signal, so they are
    #    the top seeds; their one-hop fan-out over ``alternatives`` is the related set.
    seed_signal_ids = sorted({
        sid for tid in resolved for sid in kb.signal_ids_for(tid)
    })
    res = kb.hydrate(seed_signal_ids[:_MAX_MATCHED_SIGNALS], k=k)

    # 3. REASON — remediations from each resolved vector's OWN fields; related_threats
    #    from the pure fan-out (propagated-only neighbours = the ``alternatives`` edge).
    resolved_set = set(resolved)
    remediations = [
        project_node(p, _REMEDIATION_FIELDS)
        for p in res.patterns if p["id"] in resolved_set
    ]
    related_threats = [
        project_node(p, _RELATED_FIELDS)
        for p in res.patterns if p["retrieval"]["seed"] is False
    ]

    # 4. ENVELOPE — surface the fail-closed state + integrity signals. The resolved
    #    ids are genuine and hydratable, so hydrate does not abstain over them; any
    #    dangling fan-out id the engine flagged is merged with the unresolved refs.
    dangling = sorted(set(res.dangling) | set(dangling_refs))

    result = {
        "remediations": remediations,
        "related_threats": related_threats,
        "retrieval_state": res.state,
        "unmatched": sorted(res.unmatched_signals),
        "dangling": dangling,
        "source": source,
    }

    emit_event("plan_remediation", {
        "threat_id": threat_id,
        "cwe": cwe_values,
        "source": source,
        "state": res.state,
        "remediations_count": len(remediations),
        "related_count": len(related_threats),
    })

    return result
