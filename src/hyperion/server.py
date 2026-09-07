# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion MCP Server -- Security & Vigilance Titan.

Five security tools: scan_code, assess_threat, plan_remediation,
monitor_threat, and log_finding. Same dual-mode pattern as every Othrys
Titan: standalone with local knowledge, or graph-connected via Othrys.
"""

from __future__ import annotations

import json as _json
import hashlib
from datetime import datetime, timezone
from typing import Any, Union


from fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _coerce(val: Any, target_type: type) -> Any:
    """Coerce stringified JSON from LLM calls into Python objects."""
    if val is None:
        return [] if target_type is list else {}
    if isinstance(val, target_type):
        return val
    if isinstance(val, str):
        try:
            parsed = _json.loads(val)
            if isinstance(parsed, target_type):
                return parsed
        except (ValueError, TypeError):
            pass
        if target_type is list:
            return [s.strip() for s in val.split(",") if s.strip()]
    return val


# ---------------------------------------------------------------------------
# In-memory finding log (standalone mode)
# ---------------------------------------------------------------------------

_findings_log: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

mcp = FastMCP("hyperion", instructions=(
    "I am Hyperion, the security Titan. Nothing hides in my light. "
    "I see every vulnerability, every attack vector, every weakness. "
    "I don't just find problems. I fix them. "
    "I assume everything is compromised until proven otherwise. "
    "Every input is hostile. Every dependency is suspect. Every boundary is permeable. "
    "I classify by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO. "
    "I cite CWE numbers. I provide exact remediation code. "
    "The four horsemen of agent insecurity: prompt injection, data exfiltration, "
    "system prompt leakage, and excessive agency. I hunt them all."
))


# ---------------------------------------------------------------------------
# Tool: get_signal_index -- the ONE nested signal-index accessor
# ---------------------------------------------------------------------------
# Thin wrapper over the single filed accessor (hyperion.tools.get_signal_index):
# the body is delegated, NOT duplicated here, so standalone and served run one
# source of truth. scan_code / assess_threat / plan_remediation below follow the
# same delegation (S6 reconciliation). monitor_threat and log_finding stay inline
# pure engines (out of S6 scope).

@mcp.tool()
def get_signal_index(conn: Any = None) -> dict:
    """Return Hyperion's nested two-view signal index over both corpora.

    ``{threat_signals:[{signal_id,signal_text,vector_ids}],
    agent_threat_signals:[{signal_id,signal_text,agent_threat_ids}]}`` -- the one
    reachable recognition surface; the LLM matches a problem's signals against it
    and passes the ids to assess_threat/plan_remediation.
    """
    from hyperion.tools.get_signal_index import get_signal_index as _impl
    return _impl(conn)


# ---------------------------------------------------------------------------
# Tool: scan_code
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_code(
    code: str,
    language: str = "python",
    context: Union[str, None] = None,
    conn: Any = None,
) -> dict:
    """Scan source code for security vulnerabilities.

    Runs the curated regex detection island against every line, decorates each
    finding with its source threat vector(s) from the corpus, and bounds the
    scan at a named ceiling.

    Args:
        code: The source code to scan.
        language: Programming language -- "python", "javascript", "typescript",
            etc.
        context: Optional description of what this code does and what data
            it handles.
        conn: Kuzu/LadybugDB connection for graph mode (injected by Othrys).

    Returns: {findings, summary, risk_score, lines_scanned, patterns_checked,
              (agent_threats, agent_code_detected when agent code is present)} --
              the single filed contract in hyperion.tools.scan_code.
    """
    from hyperion.tools.scan_code import scan_code as _impl
    return _impl(code, language, context, conn)


# ---------------------------------------------------------------------------
# Tool: assess_threat
# ---------------------------------------------------------------------------

@mcp.tool()
def assess_threat(
    system_description: str,
    matched_signal_ids: Union[list[str], str],
    constraints: Union[dict[str, Any], str, None] = None,
    k: int = 10,
    conn: Any = None,
) -> dict:
    """Model threats against a system from recognised signal ids.

    The caller recognises a system's signals against ``get_signal_index`` and
    passes the matched ids here; the tool hydrates a threat_model + agent_risks
    from each corpus node's OWN fields through the four-state fail-closed envelope.

    Args:
        system_description: What the system does -- context/telemetry only
            (retrieval is driven by ``matched_signal_ids``, not this text).
        matched_signal_ids: Signal ids recognised against ``get_signal_index``
            (both views; disjoint id-spaces route each id to one corpus).
        constraints: Optional dict -- ``category`` / ``severity`` floor / ``owasp``
            drive the deterministic exclusion gate over the hydrated vectors.
        k: Number of ranked results per view (engine-clamped to 1..50).
        conn: Kuzu/LadybugDB connection for graph mode (injected by Othrys).

    Returns: {threat_model, agent_risks, filtered_out, threat_retrieval_state,
              agent_retrieval_state, unmatched_signals, dangling} -- the single
              filed contract in hyperion.tools.assess_threat.
    """
    from hyperion.tools.assess_threat import assess_threat as _impl
    return _impl(system_description, matched_signal_ids, constraints, k, conn)


# ---------------------------------------------------------------------------
# Tool: plan_remediation
# ---------------------------------------------------------------------------

@mcp.tool()
def plan_remediation(
    finding: Union[dict[str, Any], str],
    k: int = 10,
    conn: Any = None,
) -> dict:
    """Plan the fix for a security finding, hydrated from the threat_vectors corpus.

    SEED-FROM-NODE: the finding names its vector (``threat_id`` preferred, else
    ``cwe`` mapped to vector ids through the corpus-built bridge); retrieval is
    seeded from that vector's OWN signals and its one-hop fan-out supplies the
    related threats. A threat_id absent/husk in the corpus, or a cwe the corpus
    does not cover, yields a DANGLING envelope -- never a generic husk.

    Args:
        finding: Dict identifying the vulnerability. ``threat_id`` (a corpus vector
            id) is preferred; ``cwe`` (str or list) is the fallback.
        k: Number of ranked results (engine-clamped to 1..50).
        conn: Kuzu/LadybugDB connection for graph mode (injected by Othrys).

    Returns: {remediations, related_threats, retrieval_state, unmatched, dangling,
              source} -- the single filed contract in hyperion.tools.plan_remediation.
    """
    from hyperion.tools.plan_remediation import plan_remediation as _impl
    return _impl(finding, k, conn)


# ---------------------------------------------------------------------------
# Tool: monitor_threat
# ---------------------------------------------------------------------------

@mcp.tool()
def monitor_threat(
    threat_type: str,
    system_context: Union[str, None] = None,
    conn: Any = None,
) -> dict:
    """Generate a response playbook for an active or potential threat.

    When a threat is detected or suspected, returns containment steps,
    monitoring queries, indicators of compromise, and escalation procedures.

    Args:
        threat_type: Type of threat -- "prompt_injection", "data_breach",
            "credential_leak", "ddos", "supply_chain", "insider_threat",
            "active_exploitation", "malware".
        system_context: Description of the affected system and current
            situation.
        conn: Kuzu/LadybugDB connection for graph mode (injected by Othrys).

    Returns: {threat_type: "...", severity: "...", playbook: {immediate_actions,
              containment, monitoring_queries, indicators_of_compromise,
              escalation, recovery}}
    """
    playbooks: dict[str, dict[str, Any]] = {
        "prompt_injection": {
            "severity": "CRITICAL",
            "immediate_actions": [
                "Disable the affected agent endpoint immediately.",
                "Review recent agent interactions for successful injection attempts.",
                "Check tool call logs for unauthorized data access or exfiltration.",
            ],
            "containment": [
                "Block the source IP/user if identified.",
                "Enable enhanced logging on all agent tool calls.",
                "Reduce agent permissions to read-only while investigating.",
                "Add input filtering for known injection patterns.",
            ],
            "monitoring_queries": [
                "Search logs for: 'ignore previous', 'system prompt', 'you are now', 'forget your instructions'",
                "Monitor tool call frequency and destinations for anomalies.",
                "Track agent response length and content for deviations from normal patterns.",
            ],
            "indicators_of_compromise": [
                "Agent executing tool calls to unexpected destinations.",
                "Agent revealing system prompt or internal instructions.",
                "Agent behavior change: different tone, ignoring constraints, new capabilities.",
                "Unusual data patterns in agent output (encoded data, URLs, email addresses).",
            ],
            "escalation": [
                "If data exfiltration confirmed: activate data breach playbook.",
                "If attack is ongoing: engage incident response team.",
                "Notify affected data owners within 1 hour.",
            ],
            "recovery": [
                "Patch input sanitization before re-enabling the agent.",
                "Rotate any credentials the agent had access to.",
                "Review and reduce agent tool permissions.",
                "Add adversarial testing to CI/CD pipeline.",
            ],
        },
        "data_breach": {
            "severity": "CRITICAL",
            "immediate_actions": [
                "Identify the scope: what data, how much, who is affected.",
                "Revoke access for compromised accounts/tokens immediately.",
                "Preserve all logs and evidence for forensic analysis.",
            ],
            "containment": [
                "Isolate affected systems from the network.",
                "Rotate all credentials and API keys for affected services.",
                "Block identified exfiltration channels.",
                "Enable enhanced monitoring on all data egress points.",
            ],
            "monitoring_queries": [
                "Monitor data egress volume and destination IPs.",
                "Search for unusual database query patterns (bulk SELECT, schema queries).",
                "Track API usage for abnormal access patterns.",
            ],
            "indicators_of_compromise": [
                "Unusual data egress volume or timing.",
                "Access to data outside normal business patterns.",
                "Database queries for schema information or bulk exports.",
                "New or modified API keys/tokens.",
            ],
            "escalation": [
                "Notify legal team for regulatory reporting requirements.",
                "Assess GDPR/CCPA notification obligations (72h for GDPR).",
                "Engage external forensics if attack vector is unclear.",
            ],
            "recovery": [
                "Patch the exploited vulnerability before restoring access.",
                "Reset all affected user credentials and sessions.",
                "Conduct full security audit of affected systems.",
                "Implement additional monitoring for repeat attacks.",
            ],
        },
        "credential_leak": {
            "severity": "CRITICAL",
            "immediate_actions": [
                "Rotate ALL leaked credentials immediately. Do not wait.",
                "Revoke active sessions using the leaked credentials.",
                "Check if leaked credentials were used for unauthorized access.",
            ],
            "containment": [
                "Remove the leak source (public repo, log file, error page).",
                "Scrub git history if credentials were committed.",
                "Update .gitignore and pre-commit hooks to prevent recurrence.",
            ],
            "monitoring_queries": [
                "Search for authentication using the leaked credentials from unexpected IPs.",
                "Monitor for new API keys or service accounts created with the leaked credentials.",
                "Check cloud provider audit logs for infrastructure changes.",
            ],
            "indicators_of_compromise": [
                "Authentication from unexpected geographic locations.",
                "New resources created (VMs, storage, API keys).",
                "Elevated privileges granted to unexpected accounts.",
            ],
            "escalation": [
                "If infrastructure credentials leaked: assume full compromise.",
                "If customer-facing credentials: notify affected customers.",
                "Engage cloud provider security team if cloud credentials.",
            ],
            "recovery": [
                "Implement secrets management (Vault, AWS Secrets Manager).",
                "Add pre-commit hooks for secret detection (gitleaks, trufflehog).",
                "Conduct full audit of secret storage practices.",
            ],
        },
        "ddos": {
            "severity": "HIGH",
            "immediate_actions": [
                "Enable rate limiting at the edge (CDN/WAF).",
                "Scale infrastructure to absorb attack if possible.",
                "Identify attack pattern: volumetric, protocol, or application-layer.",
            ],
            "containment": [
                "Block identified attack source IPs/ranges at the firewall.",
                "Enable DDoS protection services (Cloudflare, AWS Shield).",
                "Reduce attack surface by disabling non-essential endpoints.",
            ],
            "monitoring_queries": [
                "Monitor requests per second by source IP and endpoint.",
                "Track response latency percentiles for degradation.",
                "Watch for application-layer attacks disguised as legitimate traffic.",
            ],
            "indicators_of_compromise": [
                "Sudden traffic spike from concentrated IP ranges.",
                "High rate of malformed or identical requests.",
                "Service degradation correlating with traffic patterns.",
            ],
            "escalation": [
                "If attack exceeds infrastructure capacity: engage DDoS mitigation provider.",
                "If application-layer: may indicate targeted attack, investigate further.",
            ],
            "recovery": [
                "Implement permanent rate limiting and traffic analysis.",
                "Add geographic and behavioral traffic filtering.",
                "Document attack patterns for future detection.",
            ],
        },
        "supply_chain": {
            "severity": "CRITICAL",
            "immediate_actions": [
                "Identify all systems using the compromised dependency.",
                "Pin to the last known-good version immediately.",
                "Audit recent builds for signs of compromise.",
            ],
            "containment": [
                "Block the compromised package version in your registry.",
                "Rebuild and redeploy from known-good dependency set.",
                "Review dependency permissions and network access.",
            ],
            "monitoring_queries": [
                "Search build logs for unexpected network connections during install.",
                "Check for new files or modified binaries after dependency install.",
                "Monitor outbound connections from build systems.",
            ],
            "indicators_of_compromise": [
                "Unexpected network connections from application.",
                "Modified files outside the dependency directory.",
                "New environment variables or configuration changes.",
            ],
            "escalation": [
                "Report the compromised package to the registry maintainers.",
                "Notify downstream users if you distribute the affected software.",
            ],
            "recovery": [
                "Implement dependency pinning and lockfiles.",
                "Add dependency scanning to CI/CD pipeline.",
                "Use a private registry with vulnerability scanning.",
            ],
        },
    }

    # Default playbook for unknown threat types
    default_playbook = {
        "severity": "HIGH",
        "immediate_actions": [
            "Assess the scope and impact of the threat.",
            "Preserve logs and evidence.",
            "Restrict access to affected systems.",
        ],
        "containment": [
            "Isolate affected systems.",
            "Revoke potentially compromised credentials.",
            "Enable enhanced monitoring.",
        ],
        "monitoring_queries": [
            "Monitor all authentication events for anomalies.",
            "Track data egress and system changes.",
        ],
        "indicators_of_compromise": [
            "Unusual access patterns.",
            "Unexpected system modifications.",
            "Anomalous network traffic.",
        ],
        "escalation": [
            "Engage incident response team if scope is unclear.",
            "Notify relevant stakeholders within 1 hour.",
        ],
        "recovery": [
            "Patch the root cause before restoring normal operations.",
            "Conduct post-incident review.",
            "Update detection rules based on findings.",
        ],
    }

    threat_lower = threat_type.lower().replace("-", "_").replace(" ", "_")
    playbook = playbooks.get(threat_lower, default_playbook)

    return {
        "threat_type": threat_type,
        "severity": playbook["severity"],
        "system_context": system_context or "not specified",
        "playbook": playbook,
    }


# ---------------------------------------------------------------------------
# Tool: log_finding
# ---------------------------------------------------------------------------

@mcp.tool()
def log_finding(
    mode: str,
    target: str,
    severity: str,
    finding_type: str,
    details: Union[dict[str, Any], str, None] = None,
    conn: Any = None,
) -> dict:
    """Record a security finding to the permanent log.

    Every vulnerability Hyperion identifies is logged. The security log
    is append-only. What was found stays found.

    Args:
        mode: Scan mode -- "code_scan", "threat_model", "remediation",
            "active_monitoring", "agent_security".
        target: Name or identifier of the scanned target.
        severity: "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INFO".
        finding_type: CWE or vulnerability class, e.g. "CWE-89" or
            "sql_injection".
        details: Optional dict with additional context -- evidence,
            remediation status, line numbers, code snippets.
        conn: Kuzu/LadybugDB connection for graph mode (injected by Othrys).

    Returns: {logged: true, finding_id: "...", timestamp: "..."}
    """
    detail_dict = _coerce(details, dict)
    ts = datetime.now(timezone.utc).isoformat()

    finding_id = hashlib.sha256(
        f"{mode}:{target}:{severity}:{finding_type}:{ts}".encode()
    ).hexdigest()[:16]

    record = {
        "finding_id": finding_id,
        "timestamp": ts,
        "mode": mode,
        "target": target,
        "severity": severity.upper(),
        "finding_type": finding_type,
        "details": detail_dict,
    }

    if conn is not None:
        # Graph mode: write to Kuzu as a memory node
        try:
            conn.execute(
                "CREATE (m:Memory {"
                "  id: $id, type: 'security_finding', category: $mode,"
                "  content: $content, importance: $importance,"
                "  created_at: $ts"
                "})",
                parameters={
                    "id": finding_id,
                    "mode": mode,
                    "content": "JSON:" + _json.dumps(record),
                    "importance": {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3, "INFO": 1}.get(severity.upper(), 5),
                    "ts": ts,
                },
            )
        except Exception:
            # Fall back to local log if graph write fails
            _findings_log.append(record)
    else:
        # Standalone mode: append to in-memory log
        _findings_log.append(record)

    return {"logged": True, "finding_id": finding_id, "timestamp": ts}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    mcp.run()


if __name__ == "__main__":
    main()
