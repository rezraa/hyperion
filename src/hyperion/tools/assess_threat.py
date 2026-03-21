# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: assess_threat

Threat modeling tool.  Takes a system description and structural signals
identified by the LLM, matches them against decision rules, and builds
a threat model with attack surfaces, threat vectors, and risk scores.
"""

from __future__ import annotations

from typing import Any

from hyperion.tools._shared import coerce, emit_event, get_knowledge

# ---------------------------------------------------------------------------
# Agent/LLM signal keywords -- triggers agent threat analysis
# ---------------------------------------------------------------------------

_AGENT_SIGNALS: set[str] = {
    "llm-integration",
    "agent-system",
    "tool-use",
    "multi-agent",
    "prompt-handling",
    "rag-pipeline",
    "function-calling",
    "model-serving",
    "embedding-service",
    "context-window",
    "memory-persistence",
    "guardrails",
    "output-filtering",
    "mcp-server",
    "chain-of-thought",
}

# Built-in agent threat patterns -- returned when agent signals are detected
_AGENT_THREAT_PATTERNS: dict[str, dict[str, Any]] = {
    "llm-integration": {
        "threat": "prompt_injection",
        "description": "LLM integration exposes prompt injection attack surface",
        "attack_vectors": [
            "Direct prompt injection via user input",
            "Indirect prompt injection via retrieved documents",
            "Jailbreak attempts to bypass system instructions",
        ],
        "risk_level": "critical",
        "mitigations": [
            "Input sanitization and validation",
            "Prompt boundary enforcement",
            "Output validation and filtering",
            "Instruction hierarchy (system > user)",
        ],
    },
    "agent-system": {
        "threat": "agent_autonomy_abuse",
        "description": "Autonomous agent may execute unintended actions",
        "attack_vectors": [
            "Goal hijacking via crafted inputs",
            "Privilege escalation through tool chaining",
            "Resource exhaustion via infinite loops",
        ],
        "risk_level": "high",
        "mitigations": [
            "Action approval gates for destructive operations",
            "Budget/token limits per invocation",
            "Tool access scoping (least privilege)",
            "Human-in-the-loop for sensitive actions",
        ],
    },
    "tool-use": {
        "threat": "tool_abuse",
        "description": "Agent tool access creates indirect code execution pathways",
        "attack_vectors": [
            "Tool argument injection",
            "Unintended tool sequencing",
            "Tool output as injection vector",
        ],
        "risk_level": "high",
        "mitigations": [
            "Input validation on all tool arguments",
            "Tool output sanitization",
            "Allowlisted tool combinations",
            "Rate limiting per tool",
        ],
    },
    "multi-agent": {
        "threat": "inter_agent_manipulation",
        "description": "Multi-agent communication channels can be compromised",
        "attack_vectors": [
            "Agent impersonation",
            "Message tampering between agents",
            "Cascading failures from compromised agent",
            "Confused deputy through delegated authority",
        ],
        "risk_level": "high",
        "mitigations": [
            "Agent authentication and message signing",
            "Isolated execution environments",
            "Output validation at agent boundaries",
            "Blast radius containment",
        ],
    },
    "rag-pipeline": {
        "threat": "data_poisoning",
        "description": "RAG pipeline may retrieve and trust poisoned documents",
        "attack_vectors": [
            "Poisoned documents in knowledge base",
            "Indirect prompt injection via retrieved content",
            "Relevance manipulation to surface malicious docs",
        ],
        "risk_level": "high",
        "mitigations": [
            "Source verification for all documents",
            "Content scanning before indexing",
            "Retrieval result validation",
            "Provenance tracking",
        ],
    },
    "memory-persistence": {
        "threat": "memory_poisoning",
        "description": "Persistent agent memory can be corrupted to influence future behavior",
        "attack_vectors": [
            "Injecting false memories via crafted interactions",
            "Memory overflow to displace important context",
            "Gradual belief manipulation over multiple sessions",
        ],
        "risk_level": "medium",
        "mitigations": [
            "Memory integrity validation",
            "Source tagging for all memories",
            "Periodic memory auditing",
            "User-controlled memory management",
        ],
    },
    "mcp-server": {
        "threat": "mcp_protocol_abuse",
        "description": "MCP server exposes tools via protocol that may be exploited",
        "attack_vectors": [
            "Unauthorized tool invocation",
            "Parameter injection through MCP messages",
            "Server-side request forgery via tool definitions",
        ],
        "risk_level": "high",
        "mitigations": [
            "Authentication on MCP connections",
            "Parameter validation and typing",
            "Tool access control lists",
            "Rate limiting and auditing",
        ],
    },
}

# ---------------------------------------------------------------------------
# Built-in decision rules for common attack surfaces
# ---------------------------------------------------------------------------

_DECISION_RULES: dict[str, dict[str, Any]] = {
    "web-api": {
        "id": "rule-web-api",
        "description": "Web API attack surface",
        "attack_surfaces": [
            {"name": "HTTP endpoints", "risk": "high", "vectors": [
                "SQL injection", "XSS", "CSRF", "SSRF", "Authentication bypass",
            ]},
            {"name": "API authentication", "risk": "high", "vectors": [
                "Broken authentication", "Token theft", "Session fixation",
            ]},
            {"name": "Input validation", "risk": "high", "vectors": [
                "Parameter tampering", "Type confusion", "Buffer overflow",
            ]},
        ],
        "recommended_tools": ["scan_code", "monitor_threat"],
    },
    "database": {
        "id": "rule-database",
        "description": "Database attack surface",
        "attack_surfaces": [
            {"name": "Query interface", "risk": "critical", "vectors": [
                "SQL injection", "NoSQL injection", "ORM injection",
            ]},
            {"name": "Access control", "risk": "high", "vectors": [
                "Privilege escalation", "Unauthorized data access",
            ]},
            {"name": "Data storage", "risk": "high", "vectors": [
                "Data exfiltration", "Unencrypted sensitive data",
            ]},
        ],
        "recommended_tools": ["scan_code", "plan_remediation"],
    },
    "authentication": {
        "id": "rule-auth",
        "description": "Authentication system attack surface",
        "attack_surfaces": [
            {"name": "Login flow", "risk": "critical", "vectors": [
                "Credential stuffing", "Brute force", "Phishing",
            ]},
            {"name": "Session management", "risk": "high", "vectors": [
                "Session hijacking", "Session fixation", "Token leakage",
            ]},
            {"name": "Password storage", "risk": "critical", "vectors": [
                "Weak hashing", "Rainbow tables", "Credential database theft",
            ]},
        ],
        "recommended_tools": ["scan_code", "plan_remediation"],
    },
    "file-upload": {
        "id": "rule-file-upload",
        "description": "File upload handling attack surface",
        "attack_surfaces": [
            {"name": "Upload endpoint", "risk": "high", "vectors": [
                "Malicious file upload", "Path traversal", "File type bypass",
            ]},
            {"name": "File processing", "risk": "high", "vectors": [
                "Server-side code execution", "XML external entity (XXE)",
                "Zip bomb / decompression bomb",
            ]},
        ],
        "recommended_tools": ["scan_code", "monitor_threat"],
    },
    "cryptography": {
        "id": "rule-crypto",
        "description": "Cryptographic implementation attack surface",
        "attack_surfaces": [
            {"name": "Key management", "risk": "critical", "vectors": [
                "Hardcoded keys", "Weak key generation", "Key leakage",
            ]},
            {"name": "Algorithm choice", "risk": "high", "vectors": [
                "Deprecated algorithms", "Insufficient key length", "ECB mode",
            ]},
            {"name": "TLS/SSL", "risk": "high", "vectors": [
                "Downgrade attacks", "Certificate validation bypass",
            ]},
        ],
        "recommended_tools": ["scan_code"],
    },
    "container": {
        "id": "rule-container",
        "description": "Container/cloud deployment attack surface",
        "attack_surfaces": [
            {"name": "Container image", "risk": "high", "vectors": [
                "Base image vulnerabilities", "Excessive privileges",
                "Secrets in image layers",
            ]},
            {"name": "Orchestration", "risk": "high", "vectors": [
                "Network policy gaps", "RBAC misconfiguration",
                "Exposed management APIs",
            ]},
        ],
        "recommended_tools": ["scan_code", "monitor_threat"],
    },
    "network": {
        "id": "rule-network",
        "description": "Network exposure attack surface",
        "attack_surfaces": [
            {"name": "Exposed services", "risk": "high", "vectors": [
                "Port scanning", "Service enumeration", "Unpatched services",
            ]},
            {"name": "Internal communication", "risk": "medium", "vectors": [
                "Man-in-the-middle", "DNS spoofing", "ARP poisoning",
            ]},
        ],
        "recommended_tools": ["monitor_threat"],
    },
    "supply-chain": {
        "id": "rule-supply-chain",
        "description": "Software supply chain attack surface",
        "attack_surfaces": [
            {"name": "Dependencies", "risk": "high", "vectors": [
                "Typosquatting", "Dependency confusion", "Compromised packages",
            ]},
            {"name": "Build pipeline", "risk": "critical", "vectors": [
                "CI/CD poisoning", "Build artifact tampering", "Secret leakage in logs",
            ]},
        ],
        "recommended_tools": ["scan_code", "monitor_threat"],
    },
}

# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

_RISK_LEVELS: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


def _compute_surface_risk(surfaces: list[dict[str, Any]]) -> float:
    """Compute aggregate risk score (0-10) from attack surfaces."""
    if not surfaces:
        return 0.0

    total = sum(
        _RISK_LEVELS.get(s.get("risk", "medium"), 5.0)
        for s in surfaces
    )
    # Average, but boost for critical surfaces
    avg = total / len(surfaces)
    critical_count = sum(1 for s in surfaces if s.get("risk") == "critical")
    boosted = min(10.0, avg + critical_count * 0.5)
    return round(boosted, 1)


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

def assess_threat(
    system_description: str,
    structural_signals: list[str],
    assets: list[str] | None = None,
    constraints: dict | None = None,
    conn: object = None,
) -> dict:
    """Build a threat model from system description and structural signals.

    Args:
        system_description: Description of the system being assessed.
        structural_signals: LLM-identified signals, e.g.
            ["web-api", "database", "authentication", "llm-integration"].
        assets: Optional list of critical assets to protect (e.g.
            ["user credentials", "payment data", "PII"]).
        constraints: Optional dict with keys like ``environment``
            ("production"/"staging"/"development"), ``compliance``
            (list of frameworks like "SOC2", "HIPAA", "PCI-DSS").
        conn: Kuzu/LadybugDB connection for graph mode, or None for JSON.

    Returns:
        Dict with keys: matched_rules, threat_model, agent_threats,
        recommended_tools, risk_summary.
    """
    structural_signals = coerce(structural_signals, list) or []
    assets = coerce(assets, list) or []
    constraints = coerce(constraints, dict) or {}

    environment = constraints.get("environment", "production")
    compliance = constraints.get("compliance", [])

    # 1. Match signals against decision rules
    matched_rules: list[dict[str, Any]] = []
    all_surfaces: list[dict[str, Any]] = []
    recommended_tools: set[str] = set()

    for signal in structural_signals:
        sig_lower = signal.lower().strip()

        # Check built-in rules
        rule = _DECISION_RULES.get(sig_lower)
        if rule:
            matched_rules.append({
                "signal": sig_lower,
                "rule_id": rule["id"],
                "description": rule["description"],
            })
            for surface in rule["attack_surfaces"]:
                # Tag surface with source signal
                enriched = {**surface, "source_signal": sig_lower}
                all_surfaces.append(enriched)
            recommended_tools.update(rule.get("recommended_tools", []))

    # Try knowledge base for additional rules
    try:
        kb = get_knowledge(conn)
        if hasattr(kb, "match_structural_signals"):
            kb_matches = kb.match_structural_signals(structural_signals)
            for rm in kb_matches:
                rule = rm["rule"]
                rule_entry = {
                    "signal": rm["signal"],
                    "rule_id": rule["id"],
                    "description": rule.get("description", ""),
                    "source": "knowledge_base",
                }
                # Avoid duplicating built-in rules
                existing_ids = {r["rule_id"] for r in matched_rules}
                if rule["id"] not in existing_ids:
                    matched_rules.append(rule_entry)
    except Exception:
        pass

    # 2. Build threat model
    # Adjust risks based on environment
    env_multiplier = {
        "production": 1.0,
        "staging": 0.7,
        "development": 0.4,
    }.get(environment, 1.0)

    threat_model: list[dict[str, Any]] = []
    for surface in all_surfaces:
        base_risk = _RISK_LEVELS.get(surface.get("risk", "medium"), 5.0)
        adjusted_risk = round(min(10.0, base_risk * env_multiplier), 1)

        entry: dict[str, Any] = {
            "attack_surface": surface["name"],
            "risk_level": surface["risk"],
            "risk_score": adjusted_risk,
            "threat_vectors": surface.get("vectors", []),
            "source_signal": surface.get("source_signal", ""),
        }

        # If we have assets, assess impact on each
        if assets:
            impacted = []
            for asset in assets:
                # Simple heuristic: all surfaces can impact all assets
                # In production, the knowledge base would have more
                # nuanced mappings
                impacted.append({
                    "asset": asset,
                    "impact": surface.get("risk", "medium"),
                })
            entry["impacted_assets"] = impacted

        # Compliance relevance
        if compliance:
            entry["compliance_relevant"] = compliance

        threat_model.append(entry)

    # Sort by risk score descending
    threat_model.sort(key=lambda t: -t["risk_score"])

    # 3. Agent-specific threat analysis
    agent_threats: list[dict[str, Any]] = []
    detected_agent_signals: list[str] = []

    for signal in structural_signals:
        sig_lower = signal.lower().strip()
        if sig_lower in _AGENT_SIGNALS:
            detected_agent_signals.append(sig_lower)
            pattern = _AGENT_THREAT_PATTERNS.get(sig_lower)
            if pattern:
                agent_threats.append({
                    "signal": sig_lower,
                    **pattern,
                })

    # 4. Risk summary
    risk_scores = [t["risk_score"] for t in threat_model]
    agent_risk_scores = [
        _RISK_LEVELS.get(at.get("risk_level", "medium"), 5.0)
        for at in agent_threats
    ]

    all_risk_scores = risk_scores + agent_risk_scores

    risk_summary: dict[str, Any] = {
        "overall_risk_score": round(
            max(all_risk_scores) if all_risk_scores else 0.0, 1,
        ),
        "average_risk_score": round(
            sum(all_risk_scores) / len(all_risk_scores) if all_risk_scores else 0.0,
            1,
        ),
        "total_attack_surfaces": len(threat_model),
        "critical_surfaces": sum(
            1 for t in threat_model if t["risk_level"] == "critical"
        ),
        "high_surfaces": sum(
            1 for t in threat_model if t["risk_level"] == "high"
        ),
        "agent_threats_count": len(agent_threats),
        "environment": environment,
    }

    if compliance:
        risk_summary["compliance_frameworks"] = compliance

    # 5. Build result
    result: dict[str, Any] = {
        "matched_rules": matched_rules,
        "threat_model": threat_model,
        "recommended_tools": sorted(recommended_tools),
        "risk_summary": risk_summary,
    }

    if agent_threats:
        result["agent_threats"] = agent_threats
        result["agent_signals_detected"] = detected_agent_signals

    emit_event("assess_threat", {
        "system_description": system_description[:120],
        "signals": structural_signals,
        "matched_rules_count": len(matched_rules),
        "surfaces_count": len(threat_model),
        "agent_threats_count": len(agent_threats),
        "overall_risk": risk_summary["overall_risk_score"],
    })

    return result
