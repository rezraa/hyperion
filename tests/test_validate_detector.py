# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""validate_detector — the promote-gate for a PROPOSED code-detector regex (S4).

NORTH STAR: a proposed detector regex may be admitted only if it clears the SAME
guards the shipped detector set passes — the load-time static ReDoS quarantine
(loader.static_redos_reason) AND the runtime per-match deadline scan_code enforces
— else it is rejected with the reason (fail closed).
"""

from __future__ import annotations

from hyperion.tools.scan_code import _MAX_LINE_LENGTH
from hyperion.tools.validate_detector import _probes, validate_detector


def test_clean_regex_is_ok():
    v = validate_detector(r"password\s*=\s*\S+")
    assert v["ok"] is True
    assert v["reason"] == ""


def test_redos_regex_is_rejected_by_static_quarantine():
    """A classic nested-quantifier bomb is quarantined before it can fire."""
    v = validate_detector("(a+)+$")
    assert v["ok"] is False
    assert "ReDoS" in v["reason"] or "quarantine" in v["reason"], v["reason"]


def test_overlapping_alternation_bomb_is_rejected():
    v = validate_detector("(a|a)*$")
    assert v["ok"] is False
    assert "quarantine" in v["reason"], v["reason"]


def test_uncompilable_regex_is_rejected():
    v = validate_detector("(")
    assert v["ok"] is False
    assert "uncompilable" in v["reason"] or "quarantine" in v["reason"], v["reason"]


def test_empty_and_non_string_fail_closed():
    assert validate_detector("")["ok"] is False
    assert validate_detector(None)["ok"] is False
    assert validate_detector(123)["ok"] is False


def test_regex_alias_is_accepted():
    """The caller may pass the proposed pattern as ``regex=`` (aliased to pattern)."""
    v = validate_detector(regex=r"api[_-]?key")
    assert v["ok"] is True


def test_probes_are_bounded_at_the_scan_line_ceiling():
    """Every adversarial probe is bounded at scan_code's per-line ceiling, so the
    test-fire never reads unbounded input."""
    probes = _probes()
    assert probes  # non-empty
    assert all(len(p) <= _MAX_LINE_LENGTH for p in probes)
