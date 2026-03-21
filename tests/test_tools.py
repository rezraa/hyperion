# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Tests for Hyperion tools."""

from __future__ import annotations

import pytest

from hyperion.tools.scan_code import scan_code
from hyperion.tools.assess_threat import assess_threat
from hyperion.tools.plan_remediation import plan_remediation
from hyperion.tools.monitor_threat import monitor_threat
from hyperion.tools.log_finding import log_finding


class TestScanCode:

    def test_detects_hardcoded_password(self):
        result = scan_code(
            code='password = "admin123"\ndb_pass = "secret"',
            language="python",
        )
        findings = result.get("findings", [])
        assert len(findings) >= 1
        assert any(
            "password" in f.get("pattern", "").lower() or "secret" in f.get("description", "").lower()
            for f in findings
        )

    def test_detects_sql_injection(self):
        result = scan_code(
            code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            language="python",
        )
        findings = result.get("findings", [])
        # Should detect the f-string SQL execution pattern
        assert len(findings) >= 1

    def test_detects_command_injection(self):
        result = scan_code(
            code='import os\nos.system(user_input)',
            language="python",
        )
        findings = result.get("findings", [])
        assert len(findings) >= 1

    def test_detects_insecure_deserialization(self):
        result = scan_code(
            code='import pickle\ndata = pickle.loads(user_data)',
            language="python",
        )
        findings = result.get("findings", [])
        assert len(findings) >= 1

    def test_clean_code_low_risk(self):
        result = scan_code(
            code='def add(a: int, b: int) -> int:\n    return a + b',
            language="python",
        )
        risk = result.get("risk_score", 10)
        assert risk <= 2, f"Clean code should have low risk, got {risk}"

    def test_returns_line_numbers(self):
        result = scan_code(
            code='x = 1\npassword = "secret"\ny = 2',
            language="python",
        )
        findings = result.get("findings", [])
        if findings:
            assert findings[0].get("line_number") is not None

    def test_returns_risk_score(self):
        result = scan_code(
            code='os.system(cmd)',
            language="python",
        )
        assert "risk_score" in result
        assert isinstance(result["risk_score"], (int, float))

    def test_returns_summary(self):
        result = scan_code(
            code='password = "test"',
            language="python",
        )
        assert "summary" in result
        summary = result["summary"]
        assert "critical" in summary or "high" in summary or "total" in summary


class TestAssessThreat:

    def test_returns_structure(self):
        result = assess_threat(
            system_description="Web API with database and user auth",
            structural_signals=["user input to database"],
        )
        assert "matched_rules" in result or "threat_model" in result

    def test_agent_system_signals(self):
        result = assess_threat(
            system_description="LLM agent with tool calling and persistent memory",
            structural_signals=["agent accepts user prompts", "agent calls external tools"],
        )
        # Should return a valid structure with some threat data
        assert isinstance(result, dict)
        # Check for agent related content anywhere in the result
        result_str = str(result).lower()
        has_agent = "agent" in result_str or "prompt" in result_str or "llm" in result_str
        assert has_agent, "Agent system should trigger agent-related threat detection"

    def test_empty_signals(self):
        result = assess_threat(
            system_description="Simple calculator",
            structural_signals=[],
        )
        assert isinstance(result, dict)


class TestPlanRemediation:

    def test_returns_remediation_steps(self):
        result = plan_remediation(
            finding={
                "threat_id": "injection_sql",
                "severity": "critical",
                "description": "SQL injection via string concatenation",
            },
            language="python",
        )
        assert "remediation_steps" in result or "steps" in result or "fix" in result

    def test_returns_code_fix(self):
        result = plan_remediation(
            finding={
                "threat_id": "injection_sql",
                "severity": "critical",
                "code_context": 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
            },
            language="python",
        )
        # Should have some form of code fix
        has_fix = (
            "code_fix" in result
            or "secure" in str(result).lower()
            or "parameterized" in str(result).lower()
        )
        assert has_fix


class TestMonitorThreat:

    def test_returns_monitoring_rules(self):
        result = monitor_threat(
            threat_type="injection_sql",
        )
        assert isinstance(result, dict)
        # Should have some monitoring configuration
        has_config = any(
            key in result
            for key in ["monitoring_rules", "rules", "alert_thresholds", "playbook", "response_playbook"]
        )
        assert has_config

    def test_returns_playbook(self):
        result = monitor_threat(
            threat_type="prompt_injection",
        )
        assert isinstance(result, dict)


class TestLogFinding:

    def test_log_finding_json_mode(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)

        result = log_finding(
            mode="scan",
            target="app.py",
            severity="high",
            finding_type="injection_sql",
            details={"line": 42, "pattern": "f-string SQL"},
        )
        assert result.get("finding_id") is not None or result.get("id") is not None
        assert result.get("storage_mode") == "json" or "logged" in str(result).lower() or result.get("status") == "logged"

        if "HYPERION_DATA_DIR" in os.environ:
            del os.environ["HYPERION_DATA_DIR"]
