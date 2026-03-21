# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Tests for Hyperion knowledge base."""

from __future__ import annotations

import pytest

from hyperion.knowledge.loader import KnowledgeLoader


@pytest.fixture(scope="module")
def kb():
    return KnowledgeLoader()


class TestKnowledgeLoading:

    def test_threats_loaded(self, kb):
        threats = kb.get_all_threats()
        assert len(threats) >= 50, f"Expected 50+ threats, got {len(threats)}"

    def test_agent_threats_loaded(self, kb):
        threats = kb.get_all_agent_threats()
        assert len(threats) >= 12, f"Expected 12+ agent threats, got {len(threats)}"

    def test_decision_rules_loaded(self, kb):
        assert len(kb._rules) >= 40, f"Expected 40+ rules, got {len(kb._rules)}"

    def test_security_tools_loaded(self, kb):
        tools = kb.get_all_tools()
        assert len(tools) >= 20, f"Expected 20+ tools, got {len(tools)}"

    def test_threats_have_required_fields(self, kb):
        for t in kb.get_all_threats():
            assert "id" in t, f"Threat missing id"
            assert "name" in t, f"Threat missing name: {t.get('id')}"
            assert "category" in t, f"Threat missing category: {t.get('id')}"
            assert "severity" in t, f"Threat missing severity: {t.get('id')}"

    def test_agent_threats_have_required_fields(self, kb):
        for t in kb.get_all_agent_threats():
            assert "id" in t
            assert "name" in t
            assert "severity" in t


class TestThreatRetrieval:

    def test_get_threat_by_id(self, kb):
        t = kb.get_threat("injection_sql")
        assert t is not None
        assert t["severity"] == "critical"
        assert "CWE-89" in t.get("cwe", [])

    def test_get_threats_by_category(self, kb):
        injection = kb.get_threats_by_category("injection")
        assert len(injection) >= 5
        for t in injection:
            assert t["category"] == "injection"

    def test_get_threats_by_severity(self, kb):
        critical = kb.get_threats_by_severity("critical")
        assert len(critical) >= 5
        for t in critical:
            assert t["severity"] == "critical"

    def test_get_agent_threats(self, kb):
        agent = kb.get_all_agent_threats()
        assert len(agent) >= 12
        ids = [t["id"] for t in agent]
        assert "prompt_injection_direct" in ids

    def test_all_categories_present(self, kb):
        categories = {t["category"] for t in kb.get_all_threats()}
        expected = {"injection", "authentication", "authorization", "input_validation", "agent_security"}
        assert expected.issubset(categories), f"Missing: {expected - categories}"


class TestSecurityTools:

    def test_get_tool_by_id(self, kb):
        t = kb.get_tool("semgrep")
        assert t is not None
        assert "sast" in t.get("category", "").lower() or t.get("category") == "sast"

    def test_get_tools_by_category(self, kb):
        sast = kb.get_tools_by_category("sast")
        assert len(sast) >= 3

    def test_get_tools_with_agent_support(self, kb):
        agent_tools = kb.get_tools_with_agent_support()
        assert len(agent_tools) >= 3


class TestSignalMatching:

    def test_exact_signal_match(self, kb):
        matches = kb.match_structural_signals(
            ["user input concatenated into query string"]
        )
        assert len(matches) >= 1

    def test_no_match_for_gibberish(self, kb):
        matches = kb.match_structural_signals(["xyzzy foobar"])
        assert len(matches) == 0

    def test_multiple_signals(self, kb):
        matches = kb.match_structural_signals([
            "user input concatenated into query",
            "session token stored in cookie without secure flag",
        ])
        assert len(matches) >= 1


class TestDetectionPatterns:

    def test_sql_injection_has_patterns(self, kb):
        t = kb.get_threat("injection_sql")
        assert t is not None
        patterns = t.get("detection_patterns", [])
        assert len(patterns) >= 3

    def test_patterns_are_valid_regex(self, kb):
        import re
        for t in kb.get_all_threats():
            for pat in t.get("detection_patterns", []):
                try:
                    re.compile(pat)
                except re.error:
                    pytest.fail(f"Invalid regex in {t['id']}: {pat}")
