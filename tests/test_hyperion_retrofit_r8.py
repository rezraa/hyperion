# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion R8 -- runtime ReDoS timeout (cross-platform) + LOUD, RESUMABLE
partial-scan reporting (story-c7c9af49, council 11441dbb).

NORTH STAR: scan_code can NEVER hang on a catastrophic-backtracking match,
IDENTICALLY on macOS AND Windows; and any partial scan (a per-match TIMEOUT or a
ceiling TRUNCATION) tells the caller LOUDLY and exactly WHERE it stopped, so the
caller can fetch the next batch from that point.

MECHANISM (STEP-0 spike, settled -- cite, do not re-litigate): the ``regex`` PyPI
module's ``timeout=`` -- a real mid-match deadline checked inside the C match loop,
so it interrupts an in-flight backtracking match on BOTH platforms (a wall-clock
check, never an OS interrupt timer, which is POSIX-only and cannot interrupt a stuck
match anyway). re2 fires byte-identically on all 41 current detectors AND ships
Mac+Windows wheels, but it REJECTS lookaround / backreferences -- which the R3
static guard explicitly supports -- so it would silently drop a future authored
lookaround detector; the council's zero-detector-loss primary (regex) stands.

The load-time STATIC quarantine (R3, loader.static_redos_reason) removes the KNOWN
catastrophic shapes; this runtime deadline is the belt to that suspenders for a
shape the static walker did not model. The bombs below are TEST-LOCAL strings only,
injected past the loader (via ``_scan_detectors`` directly or a stub loader), never
added to the byte-frozen corpus.

Cross-platform BY CONSTRUCTION: the deadline is a wall-clock arg, not an OS signal
(asserted by grep below), and the RED floor test runs the match in a SUBPROCESS
under a hard kill-timeout, so a regression that fails to interrupt is killed by the
watchdog rather than wedging the suite (~8h hang before the fix).

Scope: tool + loader level. No live othrys.db, no corpus write. Firewall: scan_code
imports only hyperion.* (+ the ``regex`` dep).
"""

from __future__ import annotations

import ast
import subprocess
import sys
import time
from pathlib import Path

import pytest

# Repo root on sys.path so ``tests`` imports as a package under any invocation.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from hyperion.tools.scan_code import (  # noqa: E402
    _MATCH_TIMEOUT_SECONDS,
    _MAX_LINE_LENGTH,
    _MAX_SCAN_LINES,
    _RESUME_OVERLAP,
    _scan_detectors,
    scan_code,
)

# The real module object (the import name resolves to the re-exported function).
sc_mod = sys.modules["hyperion.tools.scan_code"]

# A regex the ``regex`` engine backtracks on EXPONENTIALLY (overlapping alternation
# under a quantifier). Measured: ~2x per input char (len 16 -> 0.03s, len 24 -> 7.7s),
# so at the adversarial lengths below it would run for hours without the deadline.
_BOMB_REGEX = r"(a|a)+$"
_ADVERSARIAL = "a" * 64 + "!"   # 2**64 partitions; forces the deadline to fire

# Watchdog budgets for the floor test. The scan returns at the per-match deadline
# (~_MATCH_TIMEOUT_SECONDS) plus interpreter startup; the hard kill is the backstop
# that fires ONLY if the deadline regressed.
_FLOOR_SECONDS = 15.0          # the whole scan must return well under this
_HARD_KILL_SECONDS = 60.0      # watchdog: kills a wedged child instead of hanging CI


def _bomb_detector(name: str = "redos_bomb", regex: str = _BOMB_REGEX) -> dict:
    """A synthetic catastrophic detector (test-local; never enters the corpus)."""
    return {
        "name": name,
        "regex": regex,
        "base_severity": "high",
        "cwe": "CWE-1333",
        "description": "synthetic ReDoS (test only)",
        "remediation": "n/a",
    }


class _StubKB:
    """A minimal KnowledgeLoader stand-in that hands scan_code an injected detector
    set, BYPASSING the load-time quarantine -- so a bomb the static guard would have
    removed still reaches the runtime match, exercising the runtime deadline."""

    def __init__(self, detectors: list[dict]) -> None:
        self._d = detectors

    def get_code_detectors(self, language: str) -> list[dict]:
        return list(self._d)

    def get_agent_code_detectors(self) -> list[dict]:
        return []

    def cwe_to_threat_ids(self) -> dict[str, list[str]]:
        return {}

    def get_threat(self, tid: str) -> dict | None:
        return None


# ===========================================================================
# The ONE honesty predicate -- driven by the real-state tests AND the mutation arm,
# so the mutation arm proves the very check the honesty tests rely on has teeth.
# ===========================================================================

def _assert_honest(result: dict) -> None:
    """The binding invariant: ``incomplete`` is True IFF a timeout, a skipped
    (uncompilable) detector, or a ceiling truncation occurred, and a partial scan names
    at least one concrete gap."""
    timed = result.get("timed_out", [])
    skipped = result.get("skipped", [])
    trunc_present = "truncated" in result
    expected_incomplete = bool(timed or skipped or trunc_present)
    assert result.get("incomplete") == expected_incomplete, (
        result.get("incomplete"), expected_incomplete,
    )
    if expected_incomplete:
        assert timed or skipped or trunc_present   # loud: a real gap, not just a flag
    else:
        assert timed == []
        assert skipped == []
        assert not trunc_present


# ===========================================================================
# (1) FLOOR (RED-first, process-watchdog): a catastrophic regex + adversarial input
#     RETURNS instead of hanging. This is the RED that hangs ~8h without the deadline.
# ===========================================================================

# Run the match in a child that mirrors the parent's sys.path, so `import hyperion`
# resolves regardless of how the suite was launched. If the deadline regressed the
# child wedges and the parent's subprocess timeout KILLS it (watchdog), rather than
# the assertion never being reached.
_CHILD = """
import sys, time
sys.path[:] = {paths!r}
from hyperion.tools.scan_code import _scan_detectors
bomb = {{"name": "redos_bomb", "regex": {regex!r}, "base_severity": "high",
        "cwe": "CWE-1333", "description": "", "remediation": ""}}
seen = set(); timed_out = []
t0 = time.perf_counter()
findings = _scan_detectors([bomb], [{adv!r}], seen, timed_out)
dt = time.perf_counter() - t0
assert timed_out == [{{"detector": "redos_bomb", "line": 1}}], timed_out
assert findings == []
print("RETURNED", dt)
"""


def test_catastrophic_match_returns_not_hangs_under_watchdog():
    """A known ReDoS bomb + adversarial input is interrupted by the per-match deadline
    and the scan RETURNS; a regression that fails to interrupt is killed by the
    subprocess watchdog (never wedges the suite)."""
    child = _CHILD.format(paths=list(sys.path), regex=_BOMB_REGEX, adv=_ADVERSARIAL)
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, "-c", child],
            capture_output=True, text=True, timeout=_HARD_KILL_SECONDS,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"scan hung > {_HARD_KILL_SECONDS}s -- the per-match ReDoS deadline did "
            "NOT interrupt the match (watchdog killed the child)"
        )
    elapsed = time.perf_counter() - t0
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
    assert "RETURNED" in proc.stdout, (proc.stdout, proc.stderr)
    assert elapsed < _FLOOR_SECONDS, f"returned but too slow: {elapsed:.2f}s"


def test_scan_detectors_timeout_is_fail_open_and_loud():
    """In-process control for the floor: a timed-out (detector, line) is SKIPPED
    (fail-open, no finding) and RECORDED in timed_out (fail-loud)."""
    seen: set[str] = set()
    timed_out: list[dict] = []
    t0 = time.perf_counter()
    findings = _scan_detectors([_bomb_detector()], [_ADVERSARIAL], seen, timed_out)
    elapsed = time.perf_counter() - t0
    assert findings == []
    assert timed_out == [{"detector": "redos_bomb", "line": 1}]
    # bounded by the deadline (one match), with generous slack for a loaded CI box
    assert elapsed < _MATCH_TIMEOUT_SECONDS + 5.0, elapsed


# ===========================================================================
# (2) PROPERTY / FUZZ: bounded wall-clock for generated inputs -- the deadline caps
#     the bomb regardless of input length, and benign inputs never falsely time out.
# ===========================================================================

def test_property_bomb_bounded_regardless_of_length():
    """The per-match time stays bounded (~the deadline) as the adversarial input GROWS
    -- proof the deadline, not backtracking, governs the wall-clock."""
    for n in (48, 64, 96):
        seen: set[str] = set()
        timed_out: list[dict] = []
        t0 = time.perf_counter()
        _scan_detectors([_bomb_detector()], ["a" * n + "!"], seen, timed_out)
        elapsed = time.perf_counter() - t0
        assert timed_out == [{"detector": "redos_bomb", "line": 1}], n
        # NOT exponential in n: every length lands near the same deadline.
        assert elapsed < _MATCH_TIMEOUT_SECONDS + 5.0, (n, elapsed)


def test_property_benign_inputs_never_falsely_timeout():
    """Generated benign lines complete under the deadline against the bomb regex --
    no false positive (the deadline must not fire on a non-catastrophic input)."""
    benign = [
        "hello world",
        "def f(x): return x + 1",
        "a" * 100,                 # a plain run: linear, no ambiguous split
        "the quick brown fox " * 20,
        "",
    ]
    for line in benign:
        seen: set[str] = set()
        timed_out: list[dict] = []
        _scan_detectors([_bomb_detector()], [line], seen, timed_out)
        assert timed_out == [], repr(line[:40])


# ===========================================================================
# (3) HONESTY: a timeout sets incomplete + timed_out; a ceiling hit sets
#     truncated{last_line, char_offset}; a clean scan sets incomplete=false + neither.
# ===========================================================================

def test_timeout_sets_incomplete_and_timed_out(monkeypatch):
    """A per-match timeout (bomb injected past the quarantine) sets incomplete=True and
    names the skipped (detector, line) -- and does NOT set truncated (not a ceiling)."""
    monkeypatch.setattr(sc_mod, "get_knowledge", lambda conn=None: _StubKB([_bomb_detector()]))
    result = sc_mod.scan_code(_ADVERSARIAL, "python")
    assert result["incomplete"] is True
    assert result["timed_out"] == [{"detector": "redos_bomb", "line": 1}]
    assert "truncated" not in result
    assert result["findings"] == []       # fail-open on the timed-out match
    _assert_honest(result)


def test_timeout_is_fail_open_other_findings_survive(monkeypatch):
    """One detector timing out does not abort the scan: a DIFFERENT detector's finding
    on another line still returns (fail-open on the match, not on the scan)."""
    real = {
        "name": "md5_usage", "regex": r"(?i)md5\s*[.(]", "base_severity": "high",
        "cwe": "CWE-328", "description": "", "remediation": "",
    }
    monkeypatch.setattr(
        sc_mod, "get_knowledge", lambda conn=None: _StubKB([_bomb_detector(), real])
    )
    code = _ADVERSARIAL + "\n" + "hashlib.md5(x)"
    result = sc_mod.scan_code(code, "python")
    assert result["incomplete"] is True
    assert {"detector": "redos_bomb", "line": 1} in result["timed_out"]
    assert any(f["pattern"] == "md5_usage" for f in result["findings"])
    _assert_honest(result)


def test_ceiling_line_count_sets_truncated_resume_point():
    """A code with more than _MAX_SCAN_LINES lines sets incomplete + a truncated
    descriptor whose last_line is the resume anchor -- the fix for TODAY's SILENT
    ceiling truncation (lines_scanned existed, but no incomplete/truncated flag)."""
    over = _MAX_SCAN_LINES + 100
    body = "\n".join(["x = 1"] * over)
    result = scan_code(body, "python")
    assert result["lines_scanned"] == _MAX_SCAN_LINES
    assert result["incomplete"] is True
    assert result["timed_out"] == []          # a ceiling hit, not a timeout
    tr = result["truncated"]
    assert tr["last_line"] == _MAX_SCAN_LINES  # resume from last_line + 1
    assert tr["line_count_truncated"] is True
    assert tr["total_lines"] == over
    _assert_honest(result)


def test_ceiling_line_length_sets_truncated_char_offset():
    """A single over-long line sets truncated with the char_offset resume point and
    names the cut line -- a mid-line resume anchor, not a silent character drop."""
    long_line = "# " + "a" * (_MAX_LINE_LENGTH + 500)
    result = scan_code(long_line, "python")
    assert result["lines_scanned"] == 1
    assert result["incomplete"] is True
    assert result["timed_out"] == []
    tr = result["truncated"]
    assert tr["char_offset"] == _MAX_LINE_LENGTH   # resume the line's tail from here
    # the OVERLAP hint: re-scan from char_offset - resume_overlap, never bare char_offset
    assert tr["resume_overlap"] == _RESUME_OVERLAP
    assert 0 < tr["resume_overlap"] < _MAX_LINE_LENGTH  # advances yet guards the straddle
    assert tr["truncated_lines"] == [1]
    assert tr["last_line"] == 1
    assert tr["line_count_truncated"] is False
    _assert_honest(result)


def test_clean_scan_is_complete_with_neither_list(safe_python_code):
    """A clean scan: incomplete=False, timed_out empty, no truncated descriptor."""
    result = scan_code(safe_python_code, "python")
    assert result["incomplete"] is False
    assert result["timed_out"] == []
    assert "truncated" not in result
    _assert_honest(result)


def test_findings_present_but_scan_complete():
    """A scan WITH findings but no timeout/truncation is still complete: incomplete is
    keyed on partial-scan gaps, not on whether anything fired."""
    result = scan_code('cursor.execute(f"SELECT * FROM t WHERE id={x}")', "python")
    assert result["findings"]
    assert result["incomplete"] is False
    assert result["timed_out"] == []
    assert "truncated" not in result
    _assert_honest(result)


# ===========================================================================
# (4) MUTATION: kill any mutant that reports COMPLETE on a timeout or a truncation.
#     Drives the SAME _assert_honest predicate the real-state tests use.
# ===========================================================================

def test_mutation_complete_on_timeout_is_killed():
    """A mutant claiming incomplete=False despite a recorded timeout is rejected."""
    mutant = {"incomplete": False, "timed_out": [{"detector": "x", "line": 1}]}
    with pytest.raises(AssertionError):
        _assert_honest(mutant)


def test_mutation_complete_on_truncation_is_killed():
    """A mutant claiming incomplete=False despite a truncation descriptor is rejected."""
    mutant = {"incomplete": False, "timed_out": [], "truncated": {"last_line": 5}}
    with pytest.raises(AssertionError):
        _assert_honest(mutant)


def test_mutation_silent_partial_flag_is_killed():
    """A mutant that flips incomplete=True but names NO gap (an empty, silent partial)
    is rejected -- a partial scan must be LOUD about where it stopped."""
    mutant = {"incomplete": True, "timed_out": []}   # no truncated, no timed_out
    with pytest.raises(AssertionError):
        _assert_honest(mutant)


# ===========================================================================
# (5) CROSS-PLATFORM BY CONSTRUCTION: no OS-signal timeout anywhere in scan_code.
# ===========================================================================

def test_no_signal_based_timeout_used():
    """scan_code uses a wall-clock deadline, NOT an OS signal timer (which is
    POSIX-only and cannot interrupt a stuck match). Proven by: (a) the ``signal``
    module is never imported (AST), and (b) no signal-timer token appears in source."""
    src = Path(sc_mod.__file__).read_text(encoding="utf-8")

    tree = ast.parse(src)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {n.name.split(".")[0] for n in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "signal" not in imported, imported

    for banned in ("import signal", "SIGALRM", "setitimer", ".alarm("):
        assert banned not in src, banned


def test_scan_code_module_firewall_intact():
    """scan_code imports only hyperion.* (+ the regex dep) -- the standalone firewall."""
    src = Path(sc_mod.__file__).read_text(encoding="utf-8")
    for root in ("othrys", "coeus", "mnemos", "theia", "themis"):
        assert f"import {root}" not in src
        assert f"from {root}" not in src


# ===========================================================================
# (6) HONESTY BELT -- an UNCOMPILABLE detector is skipped LOUDLY (never silent).
#     UNREACHABLE via the loader (it quarantines uncompilable detectors first);
#     exercised here by injecting a bad regex PAST it, so the contract "a partial scan
#     can never look clean" holds even if the load-time and scan-time engines diverged.
# ===========================================================================

def _bad_regex_detector() -> dict:
    """A detector whose regex will not compile ('(' is an unbalanced group)."""
    return {
        "name": "bad_regex", "regex": "(", "base_severity": "high",
        "cwe": "CWE-000", "description": "", "remediation": "",
    }


def test_uncompilable_detector_is_recorded_not_silent():
    """In-process: an uncompilable detector is SKIPPED (fail-open, no finding) and
    RECORDED in the shared *skipped* accumulator (fail-loud) -- not silently dropped."""
    seen: set = set()
    timed_out: list = []
    skipped: list = []
    findings = _scan_detectors(
        [_bad_regex_detector()], ["anything"], seen, timed_out, skipped=skipped,
    )
    assert findings == []
    assert timed_out == []
    assert skipped == [{"detector": "bad_regex", "reason": "uncompilable"}]


def test_uncompilable_detector_flips_incomplete(monkeypatch):
    """End-to-end: a scan whose only detector will not compile reports incomplete=True
    and names the skipped detector -- the honesty invariant holds on a compile gap."""
    monkeypatch.setattr(
        sc_mod, "get_knowledge", lambda conn=None: _StubKB([_bad_regex_detector()]),
    )
    result = sc_mod.scan_code("anything at all", "python")
    assert result["incomplete"] is True
    assert result["skipped"] == [{"detector": "bad_regex", "reason": "uncompilable"}]
    assert result["timed_out"] == []
    assert "truncated" not in result
    assert result["findings"] == []
    _assert_honest(result)


def test_mutation_complete_on_skipped_is_killed():
    """A mutant claiming incomplete=False despite a recorded skipped detector is
    rejected -- an uncompilable detector must never leave the scan looking clean."""
    mutant = {"incomplete": False, "timed_out": [],
              "skipped": [{"detector": "x", "reason": "uncompilable"}]}
    with pytest.raises(AssertionError):
        _assert_honest(mutant)


# ===========================================================================
# (7) E2E RESUME -- re-scan from the published resume point and RECOVER a planted vuln.
#     Binds the resume MATH (both axes) against future edits: a line-count cut needs no
#     overlap; a char cut needs char_offset - resume_overlap to catch the straddle.
# ===========================================================================

def test_e2e_resume_recovers_vuln_past_line_ceiling():
    """A real vuln planted PAST _MAX_SCAN_LINES is not seen in batch 1 (ceiling cut it);
    re-scanning ``raw_lines[last_line:]`` (resume from last_line+1, NO overlap) RECOVERS
    it -- proof the line-count resume point is correct and per-line matching needs no
    overlap across a line boundary."""
    vuln = "os.system(user_input)"                 # os_system, CWE-78
    raw_lines = ["x = 1"] * (_MAX_SCAN_LINES + 50) + [vuln]
    body = "\n".join(raw_lines)

    first = scan_code(body, "python")
    assert first["lines_scanned"] == _MAX_SCAN_LINES
    assert first["incomplete"] is True
    assert not any(f["pattern"] == "os_system" for f in first["findings"])  # cut off
    last_line = first["truncated"]["last_line"]
    assert last_line == _MAX_SCAN_LINES
    _assert_honest(first)

    # RESUME: last_line is a 1-based COUNT, so the first UNSCANNED line is the 0-based
    # slice raw_lines[last_line:] (== resume from line last_line + 1). No overlap.
    tail = "\n".join(raw_lines[last_line:])
    second = scan_code(tail, "python")
    assert any(f["pattern"] == "os_system" for f in second["findings"])


def test_e2e_resume_recovers_straddling_vuln_via_overlap():
    """A vuln whose match STRADDLES the char cut is missed in batch 1 AND by a BARE
    ``char_offset`` resume, but RECOVERED by re-scanning from
    ``char_offset - resume_overlap`` -- proving the overlap hint (finding c) actually
    closes the straddle, not just documents it."""
    start = 3900                                    # 'token' begins here: in [cut-overlap, cut)
    prefix = "# " + "p" * (start - 2)               # a comment; 'token = ' lands at `start`
    value = "A" * 200                               # long enough the closing quote is past cut
    line = prefix + "token = '" + value + "'"
    # sanity: the opening quote is before the cut, the closing quote is past it (straddle).
    assert line.index("token = '") == start
    assert start < _MAX_LINE_LENGTH <= line.rindex("'")
    assert start >= _MAX_LINE_LENGTH - _RESUME_OVERLAP   # within the overlap window

    first = scan_code(line, "python")
    assert first["incomplete"] is True
    assert not any(f["pattern"] == "hardcoded_token" for f in first["findings"])  # cut
    tr = first["truncated"]
    off, overlap = tr["char_offset"], tr["resume_overlap"]
    _assert_honest(first)

    # BARE char_offset resume MISSES the straddle -- proof the overlap is NECESSARY.
    bare = scan_code(line[off:], "python")
    assert not any(f["pattern"] == "hardcoded_token" for f in bare["findings"])

    # OVERLAP resume (char_offset - resume_overlap) RECOVERS it.
    resumed = scan_code(line[off - overlap:], "python")
    assert any(f["pattern"] == "hardcoded_token" for f in resumed["findings"])
