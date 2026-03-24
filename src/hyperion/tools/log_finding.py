# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: log_finding

Record security findings to persistent storage.  Dual-mode: conn=None
writes to local JSONL (~/.hyperion/data/findings.jsonl), conn provided
writes to Kuzu graph memories table (memory_type="security_finding").
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from hyperion.tools._shared import append_finding, coerce, emit_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid modes and severities
# ---------------------------------------------------------------------------

_VALID_MODES = {"scan", "assessment", "audit", "incident", "remediation"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


# ---------------------------------------------------------------------------
# Graph-mode storage
# ---------------------------------------------------------------------------

def _write_to_graph(
    conn: Any,
    mode: str,
    target: str,
    severity: str,
    finding_type: str,
    details: dict[str, Any],
    timestamp: str,
) -> str:
    """Write a finding record to the Kuzu graph memories table.

    Uses the same schema convention as Mnemos/Themis: a 'memories' node
    table with memory_type, content (JSON), and timestamp fields.

    Returns the finding_id.
    """
    import hashlib
    import json

    record = {
        "memory_type": "security_finding",
        "mode": mode,
        "target": target,
        "severity": severity,
        "finding_type": finding_type,
        "details": details,
        "timestamp": timestamp,
    }

    raw = json.dumps(record, sort_keys=True)
    finding_id = "f-" + hashlib.sha256(raw.encode()).hexdigest()[:12]

    content_json = json.dumps(record)

    conn.execute(
        "CREATE (m:memories {"
        "  id: $id,"
        "  content: $content,"
        "  memory_type: $type,"
        "  status: $status,"
        "  outcome: $outcome,"
        "  agent: $agent,"
        "  project: $project,"
        "  confidence: $confidence,"
        "  timestamp: $ts"
        "})",
        parameters={
            "id": finding_id,
            "content": content_json,
            "type": "security_finding",
            "status": "active",
            "outcome": severity,
            "agent": "hyperion",
            "project": f"hyperion:{mode}",
            "confidence": 1.0,
            "ts": timestamp,
        },
    )

    return finding_id


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

def log_finding(
    mode: str,
    target: str,
    severity: str,
    finding_type: str,
    details: dict | None = None,
    conn: object = None,
) -> dict:
    """Record a security finding to persistent storage.

    Args:
        mode: Context of the finding -- one of ``"scan"``, ``"assessment"``,
            ``"audit"``, ``"incident"``, ``"remediation"``.
        target: Identifier for the scanned target (file path, system name,
            endpoint URL, etc.).
        severity: Finding severity -- one of ``"critical"``, ``"high"``,
            ``"medium"``, ``"low"``, ``"info"``.
        finding_type: Category of finding (e.g. ``"hardcoded_secret"``,
            ``"sql_injection"``, ``"prompt_injection"``,
            ``"missing_csrf"``, ``"weak_crypto"``).
        details: Optional dict with additional context.  Typical keys:
            - ``cwe`` (str): CWE identifier.
            - ``line_number`` (int): Line where the finding was detected.
            - ``matched_text`` (str): The matched code/pattern.
            - ``remediation`` (str): Recommended fix.
            - ``risk_score`` (float): Computed risk score.
            - ``tool_used`` (str): Which Hyperion tool found this.
            - ``false_positive`` (bool): If triaged as false positive.
            - ``status`` (str): "open", "in_progress", "resolved", "wont_fix".
        conn: Kuzu/LadybugDB connection for graph mode, or None for JSON.

    Returns:
        Dict with keys: logged, finding_id, mode, target, severity,
        finding_type, timestamp, storage_mode.
    """
    details = coerce(details, dict) or {}

    # Validate mode
    effective_mode = mode.lower().strip()
    if effective_mode not in _VALID_MODES:
        logger.warning(
            "Unknown mode '%s', accepting anyway (valid: %s)",
            mode, _VALID_MODES,
        )
        effective_mode = mode  # accept non-standard modes gracefully

    # Validate severity
    effective_severity = severity.lower().strip()
    if effective_severity not in _VALID_SEVERITIES:
        logger.warning(
            "Unknown severity '%s', accepting anyway (valid: %s)",
            severity, _VALID_SEVERITIES,
        )
        effective_severity = severity

    timestamp = datetime.now(timezone.utc).isoformat()

    # Enrich details with computed fields
    enriched_details = dict(details)

    # Add status if not present
    if "status" not in enriched_details:
        enriched_details["status"] = "open"

    # Compute a default risk score from severity if not provided
    if "risk_score" not in enriched_details:
        severity_scores = {
            "critical": 9.5, "high": 7.5, "medium": 5.0,
            "low": 2.5, "info": 0.5,
        }
        enriched_details["risk_score"] = severity_scores.get(
            effective_severity, 5.0,
        )

    if conn is not None:
        # Graph mode -- write to Kuzu
        storage_mode = "graph"
        finding_id = _write_to_graph(
            conn, effective_mode, target, effective_severity,
            finding_type, enriched_details, timestamp,
        )
    else:
        # Standalone mode -- write to local JSONL
        storage_mode = "json"
        record = {
            "mode": effective_mode,
            "target": target,
            "severity": effective_severity,
            "finding_type": finding_type,
            "details": enriched_details,
        }
        finding_id = append_finding(record)

    result: dict[str, Any] = {
        "logged": True,
        "finding_id": finding_id,
        "mode": effective_mode,
        "target": target,
        "severity": effective_severity,
        "finding_type": finding_type,
        "timestamp": timestamp,
        "storage_mode": storage_mode,
    }

    emit_event("finding_logged", {
        "finding_id": finding_id,
        "mode": effective_mode,
        "target": target,
        "severity": effective_severity,
        "finding_type": finding_type,
        "storage_mode": storage_mode,
    })

    return result
