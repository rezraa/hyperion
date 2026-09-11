# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Tests for Hyperion tools."""

from __future__ import annotations

import pytest

from hyperion.tools.scan_code import scan_code
from hyperion.tools.assess_threat import assess_threat
from hyperion.tools.get_signal_index import get_signal_index
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
    # S3 retrofit: assess_threat retrieves via matched_signal_ids recognised
    # against get_signal_index; deep coverage lives in test_hyperion_retrofit_s3.

    def test_returns_threat_model_from_matched_ids(self):
        view = get_signal_index()["threat_signals"]
        sid = next(
            e["signal_id"] for e in view
            if e["signal_text"] == "user input concatenated into SQL query string"
        )
        result = assess_threat("Web API with a database", [sid])
        assert "threat_model" in result
        assert result["threat_model"]

    def test_agent_signals_hydrate_agent_risks(self):
        sid = get_signal_index()["agent_threat_signals"][0]["signal_id"]
        result = assess_threat("LLM agent with tool calling", [sid])
        assert isinstance(result, dict)
        assert result["agent_risks"], "an agent detection signal must yield agent_risks"

    def test_empty_signals(self):
        result = assess_threat("Simple calculator", [])
        assert isinstance(result, dict)
        assert result["threat_model"] == []
        assert result["threat_retrieval_state"] == "no_match"


class TestPlanRemediation:
    # Migrated to the S4 contract: remediation is HYDRATED from the corpus vector
    # (seed-from-node by threat_id / cwe), no inline island, no language-keyed
    # code_fix. The old ``language``/``constraints``/``steps``/``code_fix`` shape is
    # retired with the islands (no shim) -- these tests bind the new contract.

    def test_hydrates_corpus_remediation(self):
        result = plan_remediation(
            finding={
                "threat_id": "injection_sql",
                "severity": "critical",
                "description": "SQL injection via string concatenation",
            },
        )
        assert result["retrieval_state"] == "hit"
        entry = next(e for e in result["remediations"] if e["id"] == "injection_sql")
        assert entry["remediation"]                     # the corpus remediation string
        assert "parameterized" in entry["remediation"].lower()

    def test_surfaces_corpus_examples(self):
        result = plan_remediation(
            finding={"threat_id": "injection_sql", "severity": "critical"},
        )
        entry = next(e for e in result["remediations"] if e["id"] == "injection_sql")
        # The corpus vector's own vulnerable/secure examples, not an island code_fix.
        assert "secure" in entry["examples"]
        assert "vulnerable" in entry["examples"]


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


def _sql_sid() -> str:
    """The real threat-signal id for the injection_sql detection signal, taken
    from the accessor's OWN output (never hand-built)."""
    view = get_signal_index()["threat_signals"]
    return next(
        e["signal_id"] for e in view
        if e["signal_text"] == "user input concatenated into SQL query string"
    )


def _agent_hit_ids() -> list[str]:
    """Two DISTINCT agent-threat signal ids that BOTH resolve to the SAME agent
    threat, taken from the accessor's OWN output (never hand-built, Directive 8).

    Two votes on one agent_threat clear the confidence floor, so hydrate_agent
    reaches a genuine ``hit`` — a real agent-threat recognition, not an abstention.
    The ids live only in the agent id-space (disjoint from the threat vectors), so
    the threat view abstains (no_match) on them: the AGENT-ONLY-HIT shape.
    """
    by_threat: dict[str, list[str]] = {}
    for e in get_signal_index()["agent_threat_signals"]:
        for tid in e["agent_threat_ids"]:
            by_threat.setdefault(tid, []).append(e["signal_id"])
    sigs = next(s for s in by_threat.values() if len(s) >= 2)
    return sigs[:2]


class TestAssessThreatHardening:

    def test_truthy_wrong_type_constraints_does_not_crash(self):
        # A non-empty list where a dict is expected must coerce to {}, not survive
        # `coerce(...) or {}` and crash on `.get()`.
        result = assess_threat(
            system_description="API with DB",
            matched_signal_ids=[],
            constraints=["not", "a", "dict"],
        )
        assert isinstance(result, dict)

    # --- S-TOOLFIX1: never turned away by argument shape alone --------------

    def test_prose_in_matched_signal_ids_returns_guidance_envelope(self):
        # The proven premise: the SAME words that hit as a sig-id return a bare
        # empty no_match when passed as prose. Now the abstention must carry a
        # self-correcting guidance field, not a silent empty.
        result = assess_threat(
            "web api with a sql database",
            ["user input concatenated into SQL query string"],
        )
        assert result["threat_model"] == []
        assert result["threat_retrieval_state"] == "no_match"
        assert "guidance" in result, "abstention must name the expected shape"
        assert "get_signal_index" in result["guidance"]
        assert "matched_signal_ids" in result["guidance"]

    def test_retired_structural_signals_dropped_not_typeerror(self):
        # The retired prose param must drop-with-warning and abstain with
        # guidance, NOT raise a raw TypeError. It is NOT aliased to
        # matched_signal_ids (that would resurrect the deleted matcher).
        result = assess_threat(
            "web api",
            structural_signals="user input concatenated into SQL query string",
        )
        assert isinstance(result, dict)
        assert result["threat_model"] == []
        assert "guidance" in result

    def test_retired_assets_dropped_not_typeerror(self):
        result = assess_threat("web api", assets=["customer database"])
        assert isinstance(result, dict)
        assert "guidance" in result

    def test_omitted_matched_signal_ids_abstains_non_raising(self):
        # An omitted matched_signal_ids must abstain cleanly (coerce None -> []),
        # not raise a raw TypeError on the missing positional.
        result = assess_threat("web api")
        assert isinstance(result, dict)
        assert result["threat_model"] == []
        assert "guidance" in result

    def test_system_alias_maps_to_system_description(self):
        # `system` is a genuine synonym of the real param; a clean HIT through it
        # is unchanged and carries NO guidance.
        result = assess_threat(system="web api", matched_signal_ids=[_sql_sid()])
        assert result["threat_model"], "the alias must reach the real param"
        assert "guidance" not in result

    def test_description_alias_maps_to_system_description(self):
        result = assess_threat(description="web api", matched_signal_ids=[_sql_sid()])
        assert result["threat_model"]
        assert "guidance" not in result

    def test_clean_hit_is_unchanged_no_guidance(self):
        result = assess_threat("web api", [_sql_sid()])
        assert result["threat_model"]
        assert result["threat_retrieval_state"] in ("hit", "low_confidence")
        assert "guidance" not in result, "guidance must never ride a HIT"
        # The dual-state envelope the reactive gap hook keys on is preserved.
        assert "threat_retrieval_state" in result
        assert "agent_retrieval_state" in result

    def test_constraint_gated_hit_carries_no_guidance(self):
        # The load-bearing suppression: a caller whose ids WERE recognised but whose
        # vectors are all removed by a constraint gate must NOT be told their ids were
        # wrong. guidance rides ONLY a genuine no-recognition abstention (filtered_out
        # empty) — never a gated hit (filtered_out non-empty), even though threat_model
        # and agent_risks are both empty. Binds the `not filtered_out` guard: without it
        # a recognized-then-filtered caller is falsely handed the accessor guidance.
        result = assess_threat(
            "web api",
            [_sql_sid(), _sql_sid()],
            constraints={"category": "no-such-category"},
        )
        assert result["threat_model"] == []
        assert result["filtered_out"], "the gate must record the excluded vectors"
        assert "guidance" not in result, "guidance must never ride a constraint-gated hit"

    def test_agent_only_hit_carries_no_guidance(self):
        # Binds the `not agent_risks` conjunct of the guidance guard (council
        # b92aabfe surviving mutant). AGENT-ONLY hit: the ids resolve ONLY in the
        # agent id-space, so the threat view abstains (threat_model == [],
        # no_match) while the agent view genuinely recognises the threat
        # (agent_risks non-empty, agent_retrieval_state == "hit"). With
        # filtered_out empty, guidance must STILL be suppressed — the caller was
        # recognised (as an agent threat), not turned away. Drop `not agent_risks`
        # and this recognised caller is falsely handed the accessor guidance:
        # not threat_model (True) and not filtered_out (True) => guidance rides a hit.
        result = assess_threat("LLM agent with tool calling", _agent_hit_ids())
        assert result["threat_model"] == []
        assert result["threat_retrieval_state"] == "no_match"
        assert result["agent_risks"], "an agent-threat hit must yield agent_risks"
        assert result["agent_retrieval_state"] == "hit", "a genuine agent recognition, not an abstention"
        assert result["filtered_out"] == []
        assert "guidance" not in result, "guidance must never ride an agent-only hit"

    def test_retired_param_dropped_but_valid_ids_still_hit(self):
        # A retired param passed ALONGSIDE valid ids is dropped; the valid ids
        # still resolve to a full model (retired vocab is ignored, not aliased
        # onto matched_signal_ids, which would corrupt the id list).
        result = assess_threat(
            "web api",
            matched_signal_ids=[_sql_sid()],
            structural_signals="ignored prose",
        )
        assert result["threat_model"]
        assert "guidance" not in result

    def test_unknown_kwarg_still_raises(self):
        # A genuine typo is NOT swallowed — normalize_kwargs leaves it to the
        # wrapped signature's standard TypeError.
        with pytest.raises(TypeError):
            assess_threat("web api", [], totally_unknown="boom")


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
