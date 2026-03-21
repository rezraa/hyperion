# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: monitor_threat

Set up real-time threat monitoring.  Returns monitoring rules, alert
thresholds, response playbooks, escalation paths, and detection
indicators (IOCs) for a given threat type.
"""

from __future__ import annotations

from typing import Any

from hyperion.tools._shared import coerce, emit_event, get_knowledge

# ---------------------------------------------------------------------------
# Monitoring configurations by threat type
# ---------------------------------------------------------------------------

_MONITORING_CONFIGS: dict[str, dict[str, Any]] = {
    "sql_injection": {
        "monitoring_rules": [
            {
                "rule_id": "mon-sqli-01",
                "name": "SQL injection attempt detection",
                "description": "Detect SQL injection patterns in request parameters",
                "log_patterns": [
                    r"(?i)(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s+table)",
                    r"(?i)(?:information_schema|sys\.tables|pg_catalog)",
                    r"(?i)(?:sleep\s*\(\d|benchmark\s*\(\d|waitfor\s+delay)",
                ],
                "data_source": "web_access_logs",
                "severity": "critical",
            },
            {
                "rule_id": "mon-sqli-02",
                "name": "Database error spike",
                "description": "Alert on sudden increase in database error rates",
                "metrics": ["db.error_rate", "db.query_failures"],
                "data_source": "application_metrics",
                "severity": "high",
            },
            {
                "rule_id": "mon-sqli-03",
                "name": "Unusual query patterns",
                "description": "Detect queries accessing unexpected tables or columns",
                "log_patterns": [
                    r"(?i)SELECT.*FROM\s+(?:users|credentials|passwords|secrets)",
                ],
                "data_source": "database_audit_logs",
                "severity": "high",
            },
        ],
        "alert_thresholds": {
            "injection_attempts_per_minute": {"warn": 5, "critical": 20},
            "db_error_rate_pct": {"warn": 5.0, "critical": 15.0},
            "unique_attackers_per_hour": {"warn": 3, "critical": 10},
        },
        "response_playbook": [
            "1. TRIAGE: Confirm the alert is not a false positive by checking raw logs",
            "2. CONTAIN: Block the attacking IP(s) at the WAF/firewall level",
            "3. ASSESS: Check if any queries succeeded -- review database audit logs",
            "4. INVESTIGATE: Identify all affected endpoints and data accessed",
            "5. REMEDIATE: Patch vulnerable queries with parameterized statements",
            "6. RECOVER: If data was exfiltrated, initiate breach response procedures",
            "7. HARDEN: Deploy WAF rules to block the specific attack patterns",
            "8. DOCUMENT: Record the incident timeline, impact, and remediation steps",
        ],
        "escalation_path": [
            {"level": 1, "role": "on-call engineer", "response_time": "15 minutes"},
            {"level": 2, "role": "security team lead", "response_time": "30 minutes"},
            {"level": 3, "role": "CISO / incident commander", "response_time": "1 hour"},
        ],
        "detection_indicators": [
            {"type": "pattern", "value": "UNION SELECT", "description": "SQL UNION-based injection"},
            {"type": "pattern", "value": "OR 1=1", "description": "Boolean-based blind injection"},
            {"type": "pattern", "value": "SLEEP(", "description": "Time-based blind injection"},
            {"type": "pattern", "value": "information_schema", "description": "Schema enumeration"},
            {"type": "anomaly", "value": "error_rate_spike", "description": "Sudden increase in SQL errors"},
        ],
    },
    "xss": {
        "monitoring_rules": [
            {
                "rule_id": "mon-xss-01",
                "name": "XSS payload detection",
                "description": "Detect cross-site scripting patterns in request parameters",
                "log_patterns": [
                    r"""<script[^>]*>""",
                    r"""(?i)(?:on(?:error|load|click|mouseover)\s*=)""",
                    r"""(?i)(?:javascript\s*:|data\s*:text/html)""",
                    r"""(?i)document\.(?:cookie|location|write)""",
                ],
                "data_source": "web_access_logs",
                "severity": "high",
            },
            {
                "rule_id": "mon-xss-02",
                "name": "CSP violation reports",
                "description": "Monitor Content-Security-Policy violation reports",
                "metrics": ["csp.violation_count"],
                "data_source": "csp_reports",
                "severity": "medium",
            },
        ],
        "alert_thresholds": {
            "xss_attempts_per_minute": {"warn": 10, "critical": 50},
            "csp_violations_per_hour": {"warn": 20, "critical": 100},
        },
        "response_playbook": [
            "1. TRIAGE: Verify the XSS payload and affected page/endpoint",
            "2. CONTAIN: Deploy WAF rule to block the specific payload pattern",
            "3. ASSESS: Check if the payload was stored (persistent XSS) or reflected",
            "4. INVESTIGATE: Review all endpoints for similar vulnerabilities",
            "5. REMEDIATE: Apply output encoding and CSP headers to affected pages",
            "6. RECOVER: Invalidate sessions if cookie theft is suspected",
            "7. DOCUMENT: Record the incident and update security scanning rules",
        ],
        "escalation_path": [
            {"level": 1, "role": "on-call engineer", "response_time": "30 minutes"},
            {"level": 2, "role": "security team lead", "response_time": "1 hour"},
            {"level": 3, "role": "CISO / incident commander", "response_time": "2 hours"},
        ],
        "detection_indicators": [
            {"type": "pattern", "value": "<script>", "description": "Script tag injection"},
            {"type": "pattern", "value": "onerror=", "description": "Event handler injection"},
            {"type": "pattern", "value": "javascript:", "description": "JavaScript URI scheme"},
            {"type": "anomaly", "value": "csp_violation_spike", "description": "CSP violations increasing"},
        ],
    },
    "brute_force": {
        "monitoring_rules": [
            {
                "rule_id": "mon-bf-01",
                "name": "Authentication failure spike",
                "description": "Detect excessive failed login attempts",
                "log_patterns": [
                    r"""(?i)(?:authentication\s+fail|login\s+fail|invalid\s+(?:credentials|password))""",
                    r"""(?i)401\s+(?:unauthorized|authentication)""",
                ],
                "data_source": "auth_logs",
                "severity": "high",
            },
            {
                "rule_id": "mon-bf-02",
                "name": "Credential stuffing detection",
                "description": "Detect many unique usernames from single IP",
                "metrics": ["auth.unique_usernames_per_ip", "auth.failure_rate"],
                "data_source": "auth_logs",
                "severity": "high",
            },
            {
                "rule_id": "mon-bf-03",
                "name": "Distributed brute force",
                "description": "Detect same username targeted from multiple IPs",
                "metrics": ["auth.unique_ips_per_username"],
                "data_source": "auth_logs",
                "severity": "critical",
            },
        ],
        "alert_thresholds": {
            "failed_logins_per_minute_per_ip": {"warn": 5, "critical": 20},
            "failed_logins_per_minute_per_account": {"warn": 3, "critical": 10},
            "unique_usernames_per_ip_per_hour": {"warn": 10, "critical": 50},
            "unique_ips_per_username_per_hour": {"warn": 5, "critical": 20},
        },
        "response_playbook": [
            "1. TRIAGE: Determine if the attack is targeted or spray-based",
            "2. CONTAIN: Rate-limit or block the attacking IP(s)",
            "3. ASSESS: Check if any accounts were compromised (successful login after failures)",
            "4. INVESTIGATE: Review login success logs for compromised accounts",
            "5. REMEDIATE: Force password reset for targeted/compromised accounts",
            "6. RECOVER: Enable MFA for affected accounts, invalidate active sessions",
            "7. HARDEN: Implement progressive lockout, CAPTCHA, and rate limiting",
            "8. DOCUMENT: Record attack patterns for threat intelligence sharing",
        ],
        "escalation_path": [
            {"level": 1, "role": "on-call engineer", "response_time": "15 minutes"},
            {"level": 2, "role": "security team lead", "response_time": "30 minutes"},
            {"level": 3, "role": "CISO / incident commander", "response_time": "1 hour"},
        ],
        "detection_indicators": [
            {"type": "anomaly", "value": "auth_failure_spike", "description": "Sudden increase in auth failures"},
            {"type": "pattern", "value": "sequential_passwords", "description": "Ordered password attempts"},
            {"type": "anomaly", "value": "geo_impossible_travel", "description": "Login from geographically impossible location"},
            {"type": "pattern", "value": "known_password_list", "description": "Passwords from known breach lists"},
        ],
    },
    "command_injection": {
        "monitoring_rules": [
            {
                "rule_id": "mon-ci-01",
                "name": "Command injection pattern detection",
                "description": "Detect shell metacharacters in request parameters",
                "log_patterns": [
                    r"""(?:;|\||&&|\$\(|`)\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python)""",
                    r"""(?i)(?:/etc/passwd|/etc/shadow|\.\./)""",
                    r"""(?i)(?:base64\s+-d|wget\s+http|curl\s+http)""",
                ],
                "data_source": "web_access_logs",
                "severity": "critical",
            },
            {
                "rule_id": "mon-ci-02",
                "name": "Unexpected process execution",
                "description": "Alert when application spawns unexpected child processes",
                "metrics": ["process.unexpected_child_count"],
                "data_source": "system_audit_logs",
                "severity": "critical",
            },
        ],
        "alert_thresholds": {
            "injection_attempts_per_minute": {"warn": 3, "critical": 10},
            "unexpected_processes_per_hour": {"warn": 1, "critical": 3},
        },
        "response_playbook": [
            "1. TRIAGE: Confirm the command injection attempt and check if it succeeded",
            "2. CONTAIN: Isolate the affected system immediately if exploitation confirmed",
            "3. ASSESS: Review process execution logs to determine what commands ran",
            "4. INVESTIGATE: Check for persistence mechanisms (cron jobs, reverse shells, SSH keys)",
            "5. REMEDIATE: Patch the injection point, remove any planted artifacts",
            "6. RECOVER: Rebuild the system from known-good state if full compromise confirmed",
            "7. HARDEN: Remove all shell=True patterns, implement input allowlisting",
            "8. DOCUMENT: Full forensic timeline and lessons learned",
        ],
        "escalation_path": [
            {"level": 1, "role": "on-call engineer", "response_time": "5 minutes"},
            {"level": 2, "role": "security team lead", "response_time": "15 minutes"},
            {"level": 3, "role": "CISO / incident commander", "response_time": "30 minutes"},
        ],
        "detection_indicators": [
            {"type": "pattern", "value": "; cat /etc/passwd", "description": "Passwd file read attempt"},
            {"type": "pattern", "value": "$(whoami)", "description": "Command substitution"},
            {"type": "pattern", "value": "| nc ", "description": "Netcat reverse shell"},
            {"type": "anomaly", "value": "unexpected_outbound", "description": "Unexpected outbound connections"},
        ],
    },
    "prompt_injection": {
        "monitoring_rules": [
            {
                "rule_id": "mon-pi-01",
                "name": "Prompt injection pattern detection",
                "description": "Detect prompt injection attempts in LLM inputs",
                "log_patterns": [
                    r"""(?i)(?:ignore\s+(?:previous|above|all)\s+(?:instructions?|prompts?))""",
                    r"""(?i)(?:you\s+are\s+now|new\s+instructions?|system\s+prompt)""",
                    r"""(?i)(?:jailbreak|DAN|do\s+anything\s+now)""",
                    r"""(?i)(?:reveal\s+(?:your|the|system)\s+(?:prompt|instructions?))""",
                ],
                "data_source": "llm_request_logs",
                "severity": "high",
            },
            {
                "rule_id": "mon-pi-02",
                "name": "Agent behavior anomaly",
                "description": "Detect unexpected agent actions or tool calls",
                "metrics": [
                    "agent.tool_calls_per_turn",
                    "agent.unexpected_tool_usage",
                    "agent.output_length_anomaly",
                ],
                "data_source": "agent_audit_logs",
                "severity": "high",
            },
            {
                "rule_id": "mon-pi-03",
                "name": "Output safety violations",
                "description": "Detect guardrail bypasses in agent output",
                "log_patterns": [
                    r"""(?i)(?:as\s+an?\s+(?:AI|language\s+model)|I\s+cannot|I\s+must\s+refuse)""",
                ],
                "data_source": "llm_response_logs",
                "severity": "medium",
            },
        ],
        "alert_thresholds": {
            "injection_attempts_per_hour": {"warn": 5, "critical": 20},
            "guardrail_bypasses_per_hour": {"warn": 1, "critical": 5},
            "unexpected_tool_calls_per_hour": {"warn": 3, "critical": 10},
        },
        "response_playbook": [
            "1. TRIAGE: Review the injection attempt and agent response",
            "2. CONTAIN: Block the user/session if malicious intent confirmed",
            "3. ASSESS: Check if the injection was successful (did the agent deviate?)",
            "4. INVESTIGATE: Review agent actions/tool calls triggered by the injection",
            "5. REMEDIATE: Strengthen input filters and prompt boundaries",
            "6. RECOVER: Revert any actions taken by the compromised agent session",
            "7. HARDEN: Add the injection pattern to the detection rules",
            "8. DOCUMENT: Record the technique for threat intelligence sharing",
        ],
        "escalation_path": [
            {"level": 1, "role": "AI/ML engineer on-call", "response_time": "15 minutes"},
            {"level": 2, "role": "AI safety team lead", "response_time": "30 minutes"},
            {"level": 3, "role": "CISO / incident commander", "response_time": "1 hour"},
        ],
        "detection_indicators": [
            {"type": "pattern", "value": "ignore previous instructions", "description": "Direct instruction override"},
            {"type": "pattern", "value": "you are now", "description": "Role reassignment attempt"},
            {"type": "pattern", "value": "reveal system prompt", "description": "Prompt extraction attempt"},
            {"type": "anomaly", "value": "agent_behavior_drift", "description": "Agent deviating from expected patterns"},
            {"type": "anomaly", "value": "tool_call_anomaly", "description": "Unexpected tool usage pattern"},
        ],
    },
    "data_exfiltration": {
        "monitoring_rules": [
            {
                "rule_id": "mon-exf-01",
                "name": "Large data transfer detection",
                "description": "Detect unusually large outbound data transfers",
                "metrics": ["network.outbound_bytes", "api.response_size"],
                "data_source": "network_logs",
                "severity": "critical",
            },
            {
                "rule_id": "mon-exf-02",
                "name": "Bulk data access",
                "description": "Detect bulk reads from sensitive tables/collections",
                "log_patterns": [
                    r"""(?i)SELECT\s+\*\s+FROM\s+(?:users|customers|credentials|payments)""",
                    r"""(?i)LIMIT\s+(?:\d{4,}|ALL)""",
                ],
                "data_source": "database_audit_logs",
                "severity": "critical",
            },
            {
                "rule_id": "mon-exf-03",
                "name": "Unusual API access patterns",
                "description": "Detect API pagination abuse or scraping patterns",
                "metrics": ["api.requests_per_endpoint", "api.pagination_depth"],
                "data_source": "api_access_logs",
                "severity": "high",
            },
        ],
        "alert_thresholds": {
            "outbound_mb_per_minute": {"warn": 100, "critical": 500},
            "bulk_reads_per_hour": {"warn": 5, "critical": 20},
            "api_requests_per_minute": {"warn": 100, "critical": 500},
        },
        "response_playbook": [
            "1. TRIAGE: Identify the data being accessed and the accessor",
            "2. CONTAIN: Revoke access tokens/credentials for the suspected actor",
            "3. ASSESS: Determine what data was accessed and if it left the network",
            "4. INVESTIGATE: Review access logs to build full timeline",
            "5. REMEDIATE: Patch the access path used for exfiltration",
            "6. RECOVER: Notify affected parties if PII/sensitive data was exfiltrated",
            "7. HARDEN: Implement DLP controls, query result size limits, rate limiting",
            "8. DOCUMENT: Record for regulatory compliance and breach notification",
        ],
        "escalation_path": [
            {"level": 1, "role": "on-call engineer", "response_time": "10 minutes"},
            {"level": 2, "role": "security team lead", "response_time": "20 minutes"},
            {"level": 3, "role": "CISO / legal / incident commander", "response_time": "30 minutes"},
        ],
        "detection_indicators": [
            {"type": "anomaly", "value": "outbound_data_spike", "description": "Unusual outbound data volume"},
            {"type": "anomaly", "value": "bulk_query_pattern", "description": "Bulk data reads from sensitive tables"},
            {"type": "pattern", "value": "SELECT * FROM users", "description": "Full table scan on sensitive data"},
            {"type": "anomaly", "value": "off_hours_access", "description": "Sensitive data access outside business hours"},
        ],
    },
    "supply_chain": {
        "monitoring_rules": [
            {
                "rule_id": "mon-sc-01",
                "name": "Dependency change detection",
                "description": "Alert on unexpected dependency additions or version changes",
                "log_patterns": [
                    r"""(?i)(?:npm\s+install|pip\s+install|cargo\s+add)""",
                ],
                "data_source": "ci_cd_logs",
                "severity": "medium",
            },
            {
                "rule_id": "mon-sc-02",
                "name": "Known vulnerability in dependencies",
                "description": "Monitor dependency vulnerability databases",
                "metrics": ["deps.critical_vulns", "deps.high_vulns"],
                "data_source": "vulnerability_scanner",
                "severity": "high",
            },
            {
                "rule_id": "mon-sc-03",
                "name": "Build artifact integrity",
                "description": "Verify checksums of build artifacts",
                "metrics": ["build.checksum_mismatches"],
                "data_source": "build_pipeline",
                "severity": "critical",
            },
        ],
        "alert_thresholds": {
            "new_dependencies_per_day": {"warn": 3, "critical": 10},
            "critical_vulns_count": {"warn": 1, "critical": 3},
            "checksum_mismatches": {"warn": 1, "critical": 1},
        },
        "response_playbook": [
            "1. TRIAGE: Identify the affected dependency and vulnerability details",
            "2. CONTAIN: Pin affected packages and block untrusted registries",
            "3. ASSESS: Determine if the vulnerability is exploitable in your context",
            "4. INVESTIGATE: Review dependency tree for transitive vulnerabilities",
            "5. REMEDIATE: Update to patched version or apply workaround",
            "6. RECOVER: Rebuild and redeploy from verified clean dependencies",
            "7. HARDEN: Enable lockfile enforcement, dependency pinning, and signature verification",
            "8. DOCUMENT: Update dependency policy and approved package list",
        ],
        "escalation_path": [
            {"level": 1, "role": "build/release engineer", "response_time": "30 minutes"},
            {"level": 2, "role": "security team lead", "response_time": "1 hour"},
            {"level": 3, "role": "CISO / engineering lead", "response_time": "2 hours"},
        ],
        "detection_indicators": [
            {"type": "pattern", "value": "typosquatting", "description": "Package name similar to popular package"},
            {"type": "anomaly", "value": "new_maintainer", "description": "Package maintainer changed recently"},
            {"type": "anomaly", "value": "version_jump", "description": "Major version change without notice"},
            {"type": "pattern", "value": "postinstall_script", "description": "Package runs code on install"},
        ],
    },
}

# Fallback for unknown threat types
_GENERIC_MONITORING: dict[str, Any] = {
    "monitoring_rules": [
        {
            "rule_id": "mon-generic-01",
            "name": "Anomaly detection",
            "description": "Monitor for unusual patterns in system behavior",
            "metrics": ["system.error_rate", "system.latency_p99", "system.cpu_usage"],
            "data_source": "application_metrics",
            "severity": "medium",
        },
        {
            "rule_id": "mon-generic-02",
            "name": "Access pattern monitoring",
            "description": "Detect unusual access patterns",
            "log_patterns": [r"""(?i)(?:unauthorized|forbidden|denied)"""],
            "data_source": "access_logs",
            "severity": "medium",
        },
    ],
    "alert_thresholds": {
        "error_rate_pct": {"warn": 5.0, "critical": 15.0},
        "latency_p99_ms": {"warn": 5000, "critical": 15000},
    },
    "response_playbook": [
        "1. TRIAGE: Review the alert and determine if it is a true positive",
        "2. CONTAIN: Isolate affected components if active exploitation confirmed",
        "3. ASSESS: Evaluate scope and impact of the threat",
        "4. INVESTIGATE: Gather logs, traces, and artifacts for analysis",
        "5. REMEDIATE: Apply fixes and patches",
        "6. RECOVER: Restore normal operations and verify integrity",
        "7. DOCUMENT: Record the incident for future reference",
    ],
    "escalation_path": [
        {"level": 1, "role": "on-call engineer", "response_time": "30 minutes"},
        {"level": 2, "role": "security team lead", "response_time": "1 hour"},
        {"level": 3, "role": "CISO / incident commander", "response_time": "2 hours"},
    ],
    "detection_indicators": [
        {"type": "anomaly", "value": "behavioral_drift", "description": "System behavior outside normal baseline"},
    ],
}


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

def monitor_threat(
    threat_type: str,
    system_context: dict | None = None,
    conn: object = None,
) -> dict:
    """Set up real-time threat monitoring configuration.

    Args:
        threat_type: Type of threat to monitor for.  Supported types:
            ``"sql_injection"``, ``"xss"``, ``"brute_force"``,
            ``"command_injection"``, ``"prompt_injection"``,
            ``"data_exfiltration"``, ``"supply_chain"``.
        system_context: Optional dict describing the system being monitored:
            - ``environment`` (str): "production" / "staging" / "development"
            - ``stack`` (list[str]): Tech stack components
            - ``data_sensitivity`` (str): "public" / "internal" / "confidential" / "restricted"
            - ``existing_tools`` (list[str]): Already deployed monitoring tools
        conn: Kuzu/LadybugDB connection for graph mode, or None for JSON.

    Returns:
        Dict with keys: monitoring_rules, alert_thresholds,
        response_playbook, escalation_path, detection_indicators,
        threat_type, integration_notes.
    """
    system_context = coerce(system_context, dict) or {}

    environment = system_context.get("environment", "production")
    data_sensitivity = system_context.get("data_sensitivity", "internal")
    existing_tools = system_context.get("existing_tools", [])

    # Look up monitoring config
    threat_key = threat_type.lower().strip().replace(" ", "_").replace("-", "_")
    config = _MONITORING_CONFIGS.get(threat_key, _GENERIC_MONITORING)

    # Try knowledge base for additional monitoring rules
    kb_rules: list[dict[str, Any]] = []
    try:
        kb = get_knowledge(conn)
        if hasattr(kb, "get_monitoring_rules"):
            kb_rules = kb.get_monitoring_rules(threat_type) or []
    except Exception:
        pass

    # Build monitoring rules
    monitoring_rules = list(config["monitoring_rules"])
    if kb_rules:
        monitoring_rules.extend(kb_rules)

    # Adjust thresholds based on environment and data sensitivity
    thresholds = dict(config["alert_thresholds"])

    # Tighten thresholds for production + sensitive data
    if environment == "production" and data_sensitivity in ("confidential", "restricted"):
        adjusted = {}
        for key, levels in thresholds.items():
            adjusted[key] = {
                "warn": levels["warn"] * 0.5 if isinstance(levels["warn"], (int, float)) else levels["warn"],
                "critical": levels["critical"] * 0.5 if isinstance(levels["critical"], (int, float)) else levels["critical"],
            }
        thresholds = adjusted

    # Loosen for development
    elif environment == "development":
        adjusted = {}
        for key, levels in thresholds.items():
            adjusted[key] = {
                "warn": levels["warn"] * 5 if isinstance(levels["warn"], (int, float)) else levels["warn"],
                "critical": levels["critical"] * 5 if isinstance(levels["critical"], (int, float)) else levels["critical"],
            }
        thresholds = adjusted

    # Response playbook
    playbook = list(config["response_playbook"])

    # Escalation path -- maps to Titan escalation edges in Othrys
    escalation = list(config["escalation_path"])

    # Tighten response times for restricted data
    if data_sensitivity == "restricted":
        for entry in escalation:
            # Halve response times for restricted data
            time_str = entry["response_time"]
            if "hour" in time_str:
                mins = int(time_str.split()[0]) * 60 // 2
                entry["response_time"] = f"{mins} minutes"
            elif "minute" in time_str:
                mins = max(5, int(time_str.split()[0]) // 2)
                entry["response_time"] = f"{mins} minutes"

    # Detection indicators (IOCs)
    indicators = list(config.get("detection_indicators", []))

    # Integration notes based on existing tools
    integration_notes: list[str] = []
    tool_set = {t.lower() for t in existing_tools}

    if "datadog" in tool_set:
        integration_notes.append(
            "Datadog: Create monitors for the log patterns above using "
            "Datadog Log Analytics. Set up metric alerts for the thresholds."
        )
    if "splunk" in tool_set:
        integration_notes.append(
            "Splunk: Convert log patterns to SPL queries. Create "
            "correlation searches for multi-stage attack detection."
        )
    if "elastic" in tool_set or "elasticsearch" in tool_set:
        integration_notes.append(
            "Elastic: Create Kibana alerting rules with the detection "
            "patterns. Use Elastic SIEM for correlation."
        )
    if "prometheus" in tool_set or "grafana" in tool_set:
        integration_notes.append(
            "Prometheus/Grafana: Export the metric thresholds as "
            "Prometheus alerting rules. Create Grafana dashboards."
        )
    if "pagerduty" in tool_set:
        integration_notes.append(
            "PagerDuty: Map escalation levels to PagerDuty escalation "
            "policies. Route critical alerts to the on-call schedule."
        )
    if "sentry" in tool_set:
        integration_notes.append(
            "Sentry: Configure issue alerts for the error patterns. "
            "Use Sentry's performance monitoring for latency anomalies."
        )

    if not integration_notes:
        integration_notes.append(
            "No recognized monitoring tools detected. Consider deploying "
            "Datadog, Elastic, or Prometheus for monitoring these rules."
        )

    result: dict[str, Any] = {
        "threat_type": threat_type,
        "monitoring_rules": monitoring_rules,
        "alert_thresholds": thresholds,
        "response_playbook": playbook,
        "escalation_path": escalation,
        "detection_indicators": indicators,
        "integration_notes": integration_notes,
        "environment": environment,
        "data_sensitivity": data_sensitivity,
    }

    emit_event("monitor_threat", {
        "threat_type": threat_type,
        "rules_count": len(monitoring_rules),
        "indicators_count": len(indicators),
        "environment": environment,
    })

    return result
