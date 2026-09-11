# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: validate_detector -- the promote-gate for a PROPOSED code detector.

Before a proposed regex may be admitted as a ``scan_code`` detector it must clear
the SAME two ReDoS guards the shipped detector set already passes through:

  1. the LOAD-TIME static quarantine (``loader.static_redos_reason``) -- a
     compile-or-quarantine plus a static AST walk for the exponential
     backtracking shapes (CWE-1333), and
  2. the RUNTIME per-match deadline ``scan_code`` enforces
     (``scan_code._MATCH_TIMEOUT_SECONDS``) -- the belt to (1)'s suspenders, for a
     backtracker the finite static shape-set did not model.

This tool wraps BOTH so an OFFLINE promote pipeline can hold a proposed detector
to the exact bar a live detector meets, reached through the summon/TitanSession
seam -- the caller (Othrys) never imports Hyperion. The two guards are reused, not
reimplemented, so there is one source of truth for each: ``static_redos_reason``
lives in ``knowledge.loader`` and the deadline/line ceiling are imported straight
from ``scan_code``.

FAIL CLOSED: an uncompilable, statically-quarantined, or timing-out regex -- or
any error analysing the untrusted pattern -- returns ``{ok: False, reason: ...}``.
"""

from __future__ import annotations

import regex

from hyperion.knowledge.loader import static_redos_reason
from hyperion.tools._shared import coerce, normalize_kwargs
from hyperion.tools.scan_code import _MATCH_TIMEOUT_SECONDS, _MAX_LINE_LENGTH

# Caller kwarg synonyms remapped to the canonical ``pattern`` param. A caller who
# passes ``regex=`` or ``detector_regex=`` still reaches the one signature; the
# names are wrapper-level strings, so they never shadow the ``regex`` module above.
_ALIASES = {"regex": "pattern", "detector_regex": "pattern"}
_IGNORED: set[str] = set()


def _probes() -> list[str]:
    """Bounded adversarial inputs for the runtime backstop test-fire.

    Each probe is bounded at ``scan_code``'s per-line ceiling (``_MAX_LINE_LENGTH``)
    -- the same ceiling the live scanner truncates untrusted lines to -- and is
    fired under the same per-match deadline, so a detector is stress-tested exactly
    as the live scan engine would run it on one worst-case line. A long homogeneous
    run followed by a single non-matching sentinel is the classic trigger for a
    ``(x+)+$``-shape catastrophic backtracker: it forces the engine to try every
    partition of the run before it can fail the anchor.
    """
    n = _MAX_LINE_LENGTH
    half = n // 2
    # Each probe is bounded at ``n`` (truncate-then-sentinel), so the test-fire
    # reads no more than the live scanner would see on one truncated line.
    return [
        "a" * n,
        "a" * (n - 1) + "!",
        "0" * (n - 1) + "!",
        " " * (n - 1) + "X",
        ("ab" * n)[: n - 1] + "!",
        (("a" * half) + ("1" * n))[: n - 1] + "!",
    ]


@normalize_kwargs
def validate_detector(pattern: str, conn: object = None) -> dict:
    """Validate a PROPOSED detector regex against Hyperion's ReDoS guards.

    Args:
        pattern: The proposed detector regex, as a string. ``regex`` and
            ``detector_regex`` are accepted aliases.
        conn: Unused; accepted for served-mode signature parity (the summon seam
            injects a GuardedConnection when the signature declares ``conn``).

    Returns:
        ``{ok, reason}``. ``ok`` is True ONLY when the pattern is a non-empty
        string that (a) clears the static ReDoS quarantine, (b) compiles under the
        ``regex`` engine ``scan_code`` runs, and (c) survives the bounded
        adversarial test-fire under the per-match deadline. On any failure ``ok``
        is False and ``reason`` names the guard that rejected it.
    """
    pattern = coerce(pattern, str)
    if not isinstance(pattern, str) or not pattern:
        return {"ok": False, "reason": "no regex string to validate"}

    # 1. Load-time static quarantine: compile-or-quarantine (stdlib ``re``) plus the
    #    AST walk for the exponential shapes. The single source of truth for the
    #    quarantine the live loader applies -- reused, never reimplemented.
    reason = static_redos_reason(pattern)
    if reason is not None:
        return {"ok": False, "reason": f"static ReDoS quarantine: {reason}"}

    # 2. Compile under the ENGINE scan_code actually runs (the third-party ``regex``
    #    module). ``static_redos_reason`` compiles with stdlib ``re``, which can
    #    accept or reject a pattern the scan engine would not -- so a proposed
    #    detector must also compile here or it can never fire.
    try:
        compiled = regex.compile(pattern)
    except regex.error as exc:
        return {"ok": False, "reason": f"uncompilable under scan engine: {exc}"}

    # 3. Runtime backstop: fire against bounded adversarial inputs under the SAME
    #    per-match deadline scan_code enforces. A catastrophic backtracker the
    #    finite static shape-set did not model is cut here -- fail closed on the
    #    deadline, and fail closed on any other match-time error over the untrusted
    #    pattern.
    for probe in _probes():
        try:
            compiled.search(probe, timeout=_MATCH_TIMEOUT_SECONDS)
        except TimeoutError:
            return {
                "ok": False,
                "reason": (
                    f"regex exceeded the {_MATCH_TIMEOUT_SECONDS}s per-match "
                    f"deadline on a bounded adversarial input (runtime ReDoS)"
                ),
            }
        except Exception as exc:  # noqa: BLE001 - untrusted pattern: fail closed
            return {"ok": False, "reason": f"match-time error: {exc}"}

    return {"ok": True, "reason": ""}
