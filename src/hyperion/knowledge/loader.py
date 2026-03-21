# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Knowledge loader for Hyperion.

Loads threat_vectors.json, agent_threats.json, decision_rules.json, and
security_tools.json and provides pure retrieval, structural signal matching
(exact substring against decision_rules), and constraint filtering.

No fuzzy keyword matching.  No tokenization.  No Jaccard scoring.
"""

from __future__ import annotations

import json
from pathlib import Path

_KNOWLEDGE_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Severity ranking — lower index = more severe.
# ---------------------------------------------------------------------------
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class KnowledgeLoader:
    """Loads and queries the Hyperion knowledge base (threat vectors,
    agent threats, decision rules, security tools).

    All matching is structural / exact / data-driven.  No fuzzy keyword overlap.
    """

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def __init__(self, knowledge_dir: Path | None = None) -> None:
        self._dir = knowledge_dir or _KNOWLEDGE_DIR

        with open(self._dir / "threat_vectors.json", encoding="utf-8") as f:
            self._threat_vectors_data = json.load(f)

        with open(self._dir / "agent_threats.json", encoding="utf-8") as f:
            self._agent_threats_data = json.load(f)

        with open(self._dir / "decision_rules.json", encoding="utf-8") as f:
            self._decision_rules_data = json.load(f)

        with open(self._dir / "security_tools.json", encoding="utf-8") as f:
            self._security_tools_data = json.load(f)

        # Build convenience lists.
        self._vectors: list[dict] = self._threat_vectors_data["vectors"]
        self._agent_threats: list[dict] = self._agent_threats_data["threats"]
        self._rules: list[dict] = self._decision_rules_data["rules"]
        self._tools: list[dict] = self._security_tools_data["tools"]

        # Index: vector_id -> vector_dict
        self._vector_index: dict[str, dict] = {
            v["id"]: v for v in self._vectors
        }

        # Index: agent_threat_id -> threat_dict
        self._agent_threat_index: dict[str, dict] = {
            t["id"]: t for t in self._agent_threats
        }

        # Index: tool_id -> tool_dict
        self._tool_index: dict[str, dict] = {
            t["id"]: t for t in self._tools
        }

        # Build rule index: normalised structural_signal -> rule
        # Used for exact substring matching in match_structural_signals().
        self._rule_signal_index: dict[str, dict] = {}
        for rule in self._rules:
            signal = rule.get("structural_signal", "").lower().strip()
            if signal:
                self._rule_signal_index[signal] = rule

        # Build OWASP index: owasp_id -> list of vectors
        self._owasp_index: dict[str, list[dict]] = {}
        for v in self._vectors:
            owasp = v.get("owasp", "")
            if owasp:
                self._owasp_index.setdefault(owasp, []).append(v)

    # ------------------------------------------------------------------
    # Pure retrieval — threat vectors
    # ------------------------------------------------------------------

    def get_threat(self, threat_id: str) -> dict | None:
        """Get a threat vector by ID."""
        return self._vector_index.get(threat_id)

    def get_threats_by_ids(self, ids: list[str]) -> list[dict]:
        """Batch retrieval of threat vectors by ID."""
        results: list[dict] = []
        for tid in ids:
            t = self._vector_index.get(tid)
            if t is not None:
                results.append(t)
        return results

    def get_all_threats(self) -> list[dict]:
        """Get all threat vectors."""
        return list(self._vectors)

    def get_threats_by_category(self, category: str) -> list[dict]:
        """Get all threat vectors in a given category."""
        return [v for v in self._vectors if v.get("category") == category]

    def get_threats_by_severity(self, severity: str) -> list[dict]:
        """Get all threat vectors at a given severity level."""
        return [v for v in self._vectors if v.get("severity") == severity]

    def get_threats_by_owasp(self, owasp_id: str) -> list[dict]:
        """Get all threat vectors mapped to a specific OWASP category."""
        return list(self._owasp_index.get(owasp_id, []))

    # ------------------------------------------------------------------
    # Pure retrieval — agent threats
    # ------------------------------------------------------------------

    def get_agent_threat(self, threat_id: str) -> dict | None:
        """Get an agent-specific threat by ID."""
        return self._agent_threat_index.get(threat_id)

    def get_all_agent_threats(self) -> list[dict]:
        """Get all agent-specific threats."""
        return list(self._agent_threats)

    def get_agent_threats_by_category(self, category: str) -> list[dict]:
        """Get agent threats filtered by category."""
        return [t for t in self._agent_threats if t.get("category") == category]

    def get_agent_threats_by_severity(self, severity: str) -> list[dict]:
        """Get agent threats filtered by severity."""
        return [t for t in self._agent_threats if t.get("severity") == severity]

    # ------------------------------------------------------------------
    # Pure retrieval — security tools
    # ------------------------------------------------------------------

    def get_tool(self, tool_id: str) -> dict | None:
        """Get a security tool by ID."""
        return self._tool_index.get(tool_id)

    def get_all_tools(self) -> list[dict]:
        """Get all security tools."""
        return list(self._tools)

    def get_tools_by_category(self, category: str) -> list[dict]:
        """Get security tools by category (sast, dast, sca,
        secret_scanning, container, network, agent_security)."""
        return [t for t in self._tools if t.get("category") == category]

    def get_tools_by_language(self, language: str) -> list[dict]:
        """Get security tools that support a given language."""
        return [
            t for t in self._tools
            if language in t.get("languages", [])
            or "any" in t.get("languages", [])
        ]

    def get_tools_with_agent_support(self) -> list[dict]:
        """Get security tools with native or plugin agent security support."""
        return [
            t for t in self._tools
            if t.get("agent_security_support") in ("native", "plugin")
        ]

    def get_open_source_tools(self) -> list[dict]:
        """Get all open source security tools."""
        return [t for t in self._tools if t.get("open_source") is True]

    # ------------------------------------------------------------------
    # Detection patterns
    # ------------------------------------------------------------------

    def get_detection_patterns(self, threat_id: str) -> list[str]:
        """Get regex detection patterns for a given threat vector.

        Returns a list of regex pattern strings suitable for code scanning.
        """
        threat = self._vector_index.get(threat_id)
        if threat is None:
            return []
        return list(threat.get("detection_patterns", []))

    def get_all_detection_patterns(self) -> dict[str, list[str]]:
        """Get all detection patterns indexed by threat ID.

        Returns {threat_id: [pattern, ...]} for every threat that has
        detection patterns defined.
        """
        result: dict[str, list[str]] = {}
        for v in self._vectors:
            patterns = v.get("detection_patterns", [])
            if patterns:
                result[v["id"]] = list(patterns)
        return result

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    def get_remediation(self, threat_id: str) -> str | None:
        """Get the remediation guidance for a threat vector."""
        threat = self._vector_index.get(threat_id)
        if threat is None:
            return None
        return threat.get("remediation")

    def get_examples(self, threat_id: str) -> dict | None:
        """Get vulnerable and secure code examples for a threat vector."""
        threat = self._vector_index.get(threat_id)
        if threat is None:
            return None
        return threat.get("examples")

    # ------------------------------------------------------------------
    # Compact index
    # ------------------------------------------------------------------

    def get_compact_index(self) -> list[dict]:
        """Return id + name + category + severity + signals only, for each
        threat vector.

        Useful for the agent to scan available threats without pulling
        full details.
        """
        results: list[dict] = []
        for v in self._vectors:
            results.append({
                "id": v["id"],
                "name": v.get("name", v["id"]),
                "category": v.get("category", ""),
                "severity": v.get("severity", ""),
                "signals": v.get("signals", []),
            })
        return results

    def get_compact_agent_index(self) -> list[dict]:
        """Return id + name + category + severity for each agent threat.

        Compact representation for scanning without full details.
        """
        results: list[dict] = []
        for t in self._agent_threats:
            results.append({
                "id": t["id"],
                "name": t.get("name", t["id"]),
                "category": t.get("category", ""),
                "severity": t.get("severity", ""),
            })
        return results

    # ------------------------------------------------------------------
    # Structural matching — exact against decision_rules.json
    # ------------------------------------------------------------------

    def match_structural_signals(self, signals: list[str]) -> list[dict]:
        """Given structural signals identified by the agent, find matching
        decision rules.

        Matching is exact substring on the ``structural_signal`` field of
        each rule -- NOT fuzzy keyword overlap.

        Returns matching rules augmented with full threat and tool details::

            [{"rule": {...}, "recommended_threat": {...},
              "alternatives": [...]}]
        """
        if not signals:
            return []

        results: list[dict] = []
        seen_rule_ids: set[str] = set()

        for signal in signals:
            signal_lower = signal.lower().strip()
            if not signal_lower:
                continue

            for rule_signal, rule in self._rule_signal_index.items():
                if rule["id"] in seen_rule_ids:
                    continue

                # Exact substring match: the agent's signal appears in the
                # rule's structural_signal, or vice versa.
                if signal_lower in rule_signal or rule_signal in signal_lower:
                    seen_rule_ids.add(rule["id"])

                    # Resolve recommended threat
                    rec_threat_id = rule.get("recommended_threat", "")
                    rec_threat = self.get_threat(rec_threat_id)

                    # If not found in vectors, check agent threats
                    if rec_threat is None:
                        rec_threat = self.get_agent_threat(rec_threat_id)

                    # Resolve alternatives
                    alt_ids = rule.get("alternatives", [])
                    alternatives = []
                    for alt_id in alt_ids:
                        alt_threat = self.get_threat(alt_id)
                        if alt_threat is None:
                            alt_threat = self.get_agent_threat(alt_id)
                        if alt_threat:
                            alternatives.append(alt_threat)
                        else:
                            alternatives.append({"id": alt_id, "name": alt_id})

                    results.append({
                        "rule": rule,
                        "signal": signal,
                        "recommended_threat": rec_threat,
                        "alternatives": alternatives,
                    })

        return results

    # ------------------------------------------------------------------
    # Constraint filtering — data-driven from threat metadata
    # ------------------------------------------------------------------

    def filter_by_constraints(
        self,
        threats: list[dict],
        constraints: dict,
    ) -> tuple[list[dict], list[dict]]:
        """Filter threats by constraints.

        Args:
            threats: List of threat dicts.
            constraints: Dict with optional keys:
                - ``language`` (str): filter by attack surface relevance
                - ``category`` (str): target category
                - ``severity`` (str): minimum severity ("critical"/"high"/"medium"/"low")
                - ``owasp`` (str): filter by OWASP category

        Returns:
            (surviving, filtered_out) where each filtered_out entry has
            a ``filter_reason`` key explaining why it was removed.
        """
        category = constraints.get("category")
        min_severity = constraints.get("severity")
        owasp = constraints.get("owasp")

        surviving: list[dict] = []
        filtered_out: list[dict] = []

        for threat in threats:
            reason = None

            # --- category filter ---
            if category and threat.get("category") != category:
                reason = f"category '{threat.get('category')}' != '{category}'"

            # --- severity filter ---
            if reason is None and min_severity:
                threat_sev = threat.get("severity", "low")
                if _SEVERITY_RANK.get(threat_sev, 3) > _SEVERITY_RANK.get(min_severity, 3):
                    reason = f"severity '{threat_sev}' below minimum '{min_severity}'"

            # --- OWASP filter ---
            if reason is None and owasp:
                if threat.get("owasp") != owasp:
                    reason = f"owasp '{threat.get('owasp')}' != '{owasp}'"

            if reason:
                entry = dict(threat)
                entry["filter_reason"] = reason
                filtered_out.append(entry)
            else:
                surviving.append(threat)

        return surviving, filtered_out
