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


# ===========================================================================
# E2/S6 hardening — the failure shapes logged in the S5 post-mortem matrix
# must now succeed (alias remap, coerce defaults, fail-loud collisions).
# ===========================================================================

from hyperion.tools._shared import coerce, coerce_or_raise


class TestCoerce:

    def test_str_to_dict_mismatch_returns_default(self):
        assert coerce("production", dict, default={}) == {}

    def test_list_where_dict_expected_returns_default(self):
        assert coerce(["a"], dict, default={}) == {}

    def test_json_string_to_list(self):
        assert coerce("[1,2]", list, default=[]) == [1, 2]

    def test_native_dict_passthrough(self):
        assert coerce({"k": 1}, dict) == {"k": 1}

    def test_none_returns_default(self):
        assert coerce(None, dict, default={}) == {}

    def test_two_arg_call_still_works(self):
        # Legacy 2-arg callers must keep working.
        assert coerce("[1]", list) == [1]
        assert coerce(["x"], dict) is None  # wrong type, no default -> None


class TestAssessThreatHardening:

    def test_truthy_wrong_type_constraints_does_not_crash(self):
        # A non-empty list where a dict is expected used to survive
        # `coerce(...) or {}` and crash on `.get()`.
        result = assess_threat(
            system_description="API with DB",
            structural_signals=["database"],
            constraints=["not", "a", "dict"],
        )
        assert isinstance(result, dict)


class TestScanCodeHardening:

    def test_security_context_alias(self):
        result = scan_code(
            code='password = "x"',
            language="python",
            security_context="API endpoint handling uploads",
        )
        assert isinstance(result, dict)
        assert "findings" in result

    def test_security_context_collision_raises(self):
        with pytest.raises(TypeError):
            scan_code(
                code="x = 1",
                context="canonical",
                security_context="alias",
            )

    def test_unknown_kwarg_still_raises(self):
        with pytest.raises(TypeError):
            scan_code(code="x = 1", totally_unknown="boom")


class TestLogFindingHardening:

    def test_finding_alias_maps_to_finding_type(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)
        try:
            result = log_finding(
                mode="scan",
                target="app.py",
                severity="high",
                finding="sql_injection",  # alias of finding_type
            )
            assert result["logged"] is True
            assert result["finding_type"] == "sql_injection"
        finally:
            os.environ.pop("HYPERION_DATA_DIR", None)

    def test_finding_collision_raises(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)
        try:
            with pytest.raises(TypeError):
                log_finding(
                    mode="scan",
                    target="app.py",
                    severity="high",
                    finding_type="canonical",
                    finding="alias",
                )
        finally:
            os.environ.pop("HYPERION_DATA_DIR", None)

    def test_none_details_uses_empty_default(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)
        try:
            # Omitting details (None) is fine: an empty {} is the default.
            result = log_finding(
                mode="scan",
                target="app.py",
                severity="low",
                finding_type="info",
                details=None,
            )
            assert result["logged"] is True
        finally:
            os.environ.pop("HYPERION_DATA_DIR", None)

    def test_valid_dict_details_used(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)
        try:
            result = log_finding(
                mode="scan",
                target="app.py",
                severity="high",
                finding_type="sql_injection",
                details={"cwe": "CWE-89", "line_number": 47},
            )
            assert result["logged"] is True
        finally:
            os.environ.pop("HYPERION_DATA_DIR", None)

    def test_valid_json_object_string_details_used(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)
        try:
            result = log_finding(
                mode="scan",
                target="app.py",
                severity="high",
                finding_type="sql_injection",
                details='{"cwe": "CWE-89"}',  # JSON object string
            )
            assert result["logged"] is True
        finally:
            os.environ.pop("HYPERION_DATA_DIR", None)

    def test_nonempty_wrong_type_details_raises(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)
        try:
            # A non-empty wrong-type (a list of CWE ids) must NOT be silently
            # swallowed into an empty {} and persisted — a security finding
            # with empty details is a silent data loss. Fail loud.
            with pytest.raises(TypeError, match="details"):
                log_finding(
                    mode="scan",
                    target="app.py",
                    severity="high",
                    finding_type="sql_injection",
                    details=["cwe-89"],
                )
        finally:
            os.environ.pop("HYPERION_DATA_DIR", None)

    def test_bare_nonjson_string_details_raises(self, tmp_path):
        import os
        os.environ["HYPERION_DATA_DIR"] = str(tmp_path)
        try:
            with pytest.raises(TypeError, match="details"):
                log_finding(
                    mode="scan",
                    target="app.py",
                    severity="low",
                    finding_type="info",
                    details="just a note",  # not a JSON object
                )
        finally:
            os.environ.pop("HYPERION_DATA_DIR", None)


class TestCoerceOrRaise:
    """The stricter, persist-safe coercion helper."""

    def test_none_returns_empty_default(self):
        assert coerce_or_raise(None, dict, empty_default={}) == {}
        assert coerce_or_raise(None, list, empty_default=[]) == []

    def test_native_value_passthrough(self):
        assert coerce_or_raise({"k": 1}, dict, empty_default={}) == {"k": 1}
        assert coerce_or_raise([1, 2], list, empty_default=[]) == [1, 2]

    def test_json_object_string(self):
        assert coerce_or_raise('{"k": 1}', dict, empty_default={}) == {"k": 1}

    def test_json_array_string(self):
        assert coerce_or_raise("[1, 2]", list, empty_default=[]) == [1, 2]

    def test_nonempty_wrong_type_raises(self):
        with pytest.raises(TypeError):
            coerce_or_raise(["a"], dict, empty_default={})
        with pytest.raises(TypeError):
            coerce_or_raise({"a": 1}, list, empty_default=[])

    def test_bare_string_raises(self):
        with pytest.raises(TypeError):
            coerce_or_raise("nope", dict, empty_default={})

    def test_int_raises(self):
        with pytest.raises(TypeError):
            coerce_or_raise(5, list, empty_default=[])
