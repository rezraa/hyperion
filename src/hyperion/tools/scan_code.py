# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: scan_code

Static security analysis tool.  Hyperion's main weapon.

Takes a code snippet and language, runs regex-based detection patterns
against it, identifies hardcoded secrets, insecure imports, missing
security headers, weak crypto, and agent-specific threats.  Returns
findings with severity, CWE, line numbers, and remediation guidance.

The detectors are the single source of truth in ``knowledge/code_detectors.json``,
read through ``loader.get_code_detectors(language)`` (per-language scan set) and
``loader.get_agent_code_detectors()`` (the agent-signal-gated set).
"""

from __future__ import annotations

import logging
from typing import Any

import regex

from hyperion.tools._shared import coerce, emit_event, get_knowledge, normalize_kwargs

_log = logging.getLogger(__name__)

# Caller kwarg synonyms remapped to the canonical signature.
_ALIASES = {"security_context": "context"}
_IGNORED: set[str] = set()


# ---------------------------------------------------------------------------
# Scan ceiling -- bounded brute-force over UNTRUSTED code (CWE-400 bulkhead)
# ---------------------------------------------------------------------------
# scan_code runs one regex search per (detector, line) over attacker-controlled ``code``;
# total work is detectors x lines x line-length. Both the line count and the per-line
# length come from untrusted input, so the product is unbounded without a named
# ceiling. These bound each untrusted factor where the per-(detector x line) cost is
# incurred -- applied INSIDE scan_code as the untrusted ``code`` is read, before the
# scan loop. A code SCANNER is meant for snippets, not whole repositories: beyond
# these bounds the scan is truncated -- reported LOUDLY (``incomplete`` plus the
# ``truncated`` resume point below, not only ``lines_scanned``) so a caller can fetch
# the next batch, and the work can never grow with hostile input.
_MAX_SCAN_LINES = 20_000       # max lines scanned from untrusted ``code``
_MAX_LINE_LENGTH = 4_000       # max chars per line fed to the match engine


# ---------------------------------------------------------------------------
# Char-truncation resume overlap -- CWE-400 resume CORRECTNESS (not a new ceiling)
# ---------------------------------------------------------------------------
# A per-line match can STRADDLE the _MAX_LINE_LENGTH cut: its start sits in batch 1
# (chars ``[0:_MAX_LINE_LENGTH]``) but a required suffix -- a closing quote, a ``$``
# anchor -- sits past the cut, so batch 1 never fires it. A caller that resumes a
# truncated long line at the BARE ``char_offset`` (== _MAX_LINE_LENGTH) also misses it,
# because the match's start is BEFORE that offset. So the ``truncated`` descriptor
# publishes this overlap and the RESUME CONTRACT is: re-scan a truncated long line from
# ``char_offset - resume_overlap``, never bare ``char_offset``. Sized ABOVE the longest
# secret/token match a detector realistically produces on ONE line (long JWTs / base64
# keys run a few hundred chars) and FAR below _MAX_LINE_LENGTH, so the resumed batch
# still advances past the cut. RESIDUAL (stated honestly): a single match whose pre-cut
# visible prefix EXCEEDS this overlap without yet firing is pathological on real source
# and belongs to the deferred global total-scan-budget story, not this per-line resume.
# A line-COUNT resume needs NO overlap -- matching is per line, so no match straddles a
# line boundary; resume from ``last_line + 1`` with zero overlap.
_RESUME_OVERLAP = 512          # chars to re-scan BEFORE char_offset on a long-line resume


# ---------------------------------------------------------------------------
# Per-match ReDoS deadline -- runtime backstop for CWE-1333 (cross-platform)
# ---------------------------------------------------------------------------
# The load-time static quarantine (loader.static_redos_reason) removes the KNOWN
# catastrophic shapes before a detector enters the active set, but static analysis is
# an over-approximation of a finite modelled shape set -- it cannot prove the absence
# of every catastrophic backtracker. This is the runtime belt to that suspenders: NO
# single match may hang scan_code, even on a pattern the static walker did not model.
# Enforced by the ``regex`` module's ``timeout=`` -- a real mid-match deadline checked
# inside the C match loop, so it interrupts an in-flight backtracking match IDENTICALLY
# on macOS and Windows. It is a wall-clock check, NOT an OS interrupt timer -- an OS
# timer is POSIX-only and cannot interrupt a stuck match anyway. The budget sits ~2000x
# above the
# slowest legitimate match over a _MAX_LINE_LENGTH line (measured ~0.5ms), so a real
# detector never trips it; a catastrophic backtracker is cut here and surfaced LOUDLY
# in ``timed_out`` (fail-open on the match, fail-loud on the report).
_MATCH_TIMEOUT_SECONDS = 1.0


# ---------------------------------------------------------------------------
# Line context extraction
# ---------------------------------------------------------------------------

def _get_line_context(
    lines: list[str], line_idx: int, context_window: int = 2,
) -> list[dict[str, Any]]:
    """Return the matched line and surrounding context lines."""
    result: list[dict[str, Any]] = []
    start = max(0, line_idx - context_window)
    end = min(len(lines), line_idx + context_window + 1)

    for i in range(start, end):
        result.append({
            "line_number": i + 1,
            "content": lines[i],
            "is_match": i == line_idx,
        })
    return result


# ---------------------------------------------------------------------------
# Detector sweep -- one source of truth for both the language and the agent paths
# ---------------------------------------------------------------------------

def _scan_detectors(
    detectors: list[dict[str, Any]],
    lines: list[str],
    seen: set[str],
    timed_out: list[dict[str, Any]],
    dedup_prefix: str = "",
    skipped: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Run each detector's regex against every line and return the findings.

    Each finding is built from the detector's OWN fields: ``base_severity`` remaps to
    the finding's ``severity`` and ``name`` to ``pattern``; ``regex`` / ``cwe`` /
    ``description`` / ``remediation`` map straight through. Findings are de-duplicated
    on ``(dedup_prefix, detector name, line)`` against the shared *seen* set, so the
    language and agent sweeps never double-report the same detector on a line while
    staying independent across the two paths.

    Every match runs under the per-match ReDoS deadline (``_MATCH_TIMEOUT_SECONDS``):
    a catastrophic backtracker is interrupted at the deadline (cross-platform, no
    signal) instead of hanging. A timed-out ``(detector, line)`` is SKIPPED (fail-open
    on the match) and appended to the shared *timed_out* accumulator (fail-loud on the
    report), so the caller can never miss the gap.

    A detector whose ``regex`` will not compile is SKIPPED the same honest way: it is
    appended to the shared *skipped* accumulator (fail-open on the detector, fail-loud
    on the report) so a partial scan can never look clean. This arm is UNREACHABLE
    today -- the loader compiles and quarantines every detector before scan_code sees
    it -- but it holds the honesty contract even if the load-time and scan-time engines
    ever diverged.
    """
    out: list[dict[str, Any]] = []
    if skipped is None:
        skipped = []
    for det in detectors:
        try:
            compiled = regex.compile(det["regex"])
        except regex.error:
            skipped.append({"detector": det["name"], "reason": "uncompilable"})
            continue

        for line_idx, line in enumerate(lines):
            try:
                match = compiled.search(line, timeout=_MATCH_TIMEOUT_SECONDS)
            except TimeoutError:
                timed_out.append({"detector": det["name"], "line": line_idx + 1})
                continue
            if not match:
                continue
            dedup_key = f"{dedup_prefix}{det['name']}:{line_idx}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            out.append({
                "pattern": det["name"],
                "severity": det["base_severity"],
                "cwe": det["cwe"],
                "description": det["description"],
                "remediation": det["remediation"],
                "line_number": line_idx + 1,
                "matched_text": match.group(0),
                "line_content": line.rstrip(),
                "context_lines": _get_line_context(lines, line_idx),
            })
    return out


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

_SEVERITY_SCORE: dict[str, float] = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
    "info": 0.1,
}


def _compute_risk_score(findings: list[dict[str, Any]]) -> float:
    """Compute a 0-10 risk score from findings list."""
    if not findings:
        return 0.0

    raw = sum(_SEVERITY_SCORE.get(f["severity"], 0.5) for f in findings)

    # Logarithmic scaling -- many findings increase score but with diminishing returns
    import math
    score = min(10.0, 2.0 * math.log1p(raw))

    return round(score, 1)


# ---------------------------------------------------------------------------
# Agent threat detection
# ---------------------------------------------------------------------------

_AGENT_SIGNAL_KEYWORDS: set[str] = {
    "llm", "agent", "openai", "anthropic", "langchain", "langgraph",
    "autogen", "crew", "tool_call", "function_call", "chat_completion",
    "prompt", "system_message", "assistant", "model", "gpt", "claude",
    "completion", "embedding", "vector", "rag", "retrieval",
    "mcp", "fastmcp", "tool_use",
}


def _has_agent_signals(code: str) -> bool:
    """Return True if the code contains LLM/agent system indicators."""
    code_lower = code.lower()
    matches = sum(1 for kw in _AGENT_SIGNAL_KEYWORDS if kw in code_lower)
    return matches >= 2  # require at least 2 signals to avoid false positives


# ---------------------------------------------------------------------------
# Corpus source-vector enrichment (S5, mid-story council REVISE path (a))
# ---------------------------------------------------------------------------
# The fields a finding surfaces from its SOURCE threat vector — each vector's OWN
# data (no hardcoded table). name / severity / remediation are the north-star
# content; cwe rides along so a caller can confirm the mapping; id identifies which
# vector. A field the vector does not carry is simply omitted.
_SOURCE_VECTOR_FIELDS: tuple[str, ...] = (
    "id", "name", "severity", "cwe", "remediation",
)


def _source_vectors(
    kb: Any, cwe_map: dict[str, list[str]], cwe: str,
) -> list[dict[str, Any]]:
    """Project the corpus vector(s) a finding's CWE maps to onto their OWN fields.

    The S5 enrichment bridge: a finding's CWE resolves through the S4
    ``cwe_to_threat_ids`` mapping to its SOURCE threat vector(s); each is surfaced as
    its OWN name / severity / remediation / cwe (never a hardcoded table),
    deterministically ordered by the mapping's sorted ids. This is a direct
    seed-from-a-known-id lookup, NOT signal recognition — scan_code has no caller
    signals and stays a code scanner. A CWE the corpus does not cover (e.g. CWE-95)
    yields ``[]`` — the recorded coverage gap (corpus authoring is out of the arc),
    fail-open, never a fabricated husk. Copies each list value so the shared
    singleton corpus is never aliased by the tool's mutable output.
    """
    if not kb or not cwe:
        return []
    out: list[dict[str, Any]] = []
    for tid in cwe_map.get(cwe, []):
        vec = kb.get_threat(tid)
        if vec is None:
            continue
        out.append({
            f: (list(vec[f]) if isinstance(vec.get(f), list) else vec[f])
            for f in _SOURCE_VECTOR_FIELDS
            if vec.get(f) is not None
        })
    return out


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

@normalize_kwargs
def scan_code(
    code: str,
    language: str = "python",
    context: str | None = None,
    conn: object = None,
) -> dict:
    """Scan code for security vulnerabilities using regex-based detection.

    Args:
        code: The source code snippet to analyse.
        language: Programming language -- "python", "javascript", "typescript",
            "go", "java", "ruby", etc.
        context: Optional description of where this code runs (e.g. "API
            endpoint handling user uploads") to inform severity weighting.
        conn: Kuzu/LadybugDB connection for graph mode, or None for JSON.

    Returns:
        Dict with keys: findings (list), summary (severity counts),
        risk_score (0-10), agent_threats (list, if applicable),
        lines_scanned, patterns_checked, incomplete (bool), timed_out
        (list of ``{detector, line}`` the per-match ReDoS deadline skipped) and
        skipped (list of ``{detector, reason}`` a detector that would not compile);
        plus, when the CWE-400 ceiling cut the input, truncated (the RESUME
        POINT). ``truncated`` carries ``last_line`` (resume a line-count cut from
        ``last_line + 1`` -- NO overlap, matching is per line) and, for a mid-line
        cut, ``char_offset`` with ``resume_overlap`` and ``truncated_lines``:
        re-scan a truncated long line from ``char_offset - resume_overlap`` (NOT
        bare ``char_offset``, which would drop a match straddling the cut). When
        ``incomplete`` is True the risk_score and summary are a LOWER BOUND --
        unscanned code may hold more.
    """
    context = coerce(context, str)

    kb = get_knowledge(conn)
    detectors = kb.get_code_detectors(language)
    # Bound the untrusted input where the detectors x lines cost is incurred (CWE-400):
    # cap the scanned line count and truncate each line before the scan loop below, so
    # the product detectors x lines x chars can never grow with hostile ``code``. Every
    # cut is reported LOUDLY below (the ``truncated`` descriptor) with a resume point, so
    # a caller can fetch the next batch from exactly where the ceiling stopped -- never a
    # silent drop.
    raw_lines = code.splitlines()
    scanned_raw = raw_lines[:_MAX_SCAN_LINES]
    lines = [ln[:_MAX_LINE_LENGTH] for ln in scanned_raw]
    # Which untrusted factor(s) the ceiling actually cut (the resume point, below):
    line_count_truncated = len(raw_lines) > _MAX_SCAN_LINES
    long_lines = [
        i + 1 for i, ln in enumerate(scanned_raw) if len(ln) > _MAX_LINE_LENGTH
    ]

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()  # deduplicate: (prefix, pattern_name, line_number)
    # Partial-scan accumulators, shared across the language and agent sweeps so no gap
    # is lost between them: ``timed_out`` holds each ``{detector, line}`` the per-match
    # ReDoS deadline SKIPPED; ``skipped`` holds each ``{detector, reason}`` whose regex
    # would not compile. Both are fail-open on the item, fail-loud on the report below.
    timed_out: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    # Run every language detector against every line (the DB is the sole detector).
    findings.extend(_scan_detectors(detectors, lines, seen, timed_out, skipped=skipped))

    # Check for agent-specific threats. The agent-signal gate (_has_agent_signals /
    # _AGENT_SIGNAL_KEYWORDS) is control logic, not a detector, so it stays here; the
    # agent detectors themselves come from the DB.
    agent_threats: list[dict[str, Any]] = []
    if _has_agent_signals(code):
        agent_threats = _scan_detectors(
            kb.get_agent_code_detectors(), lines, seen, timed_out, "agent:", skipped=skipped,
        )
        # Agent threats also go in the main findings.
        findings.extend(agent_threats)

    # Compute summary counts
    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1

    risk_score = _compute_risk_score(findings)

    # Enrich each finding with its SOURCE vector(s) from the corpus (S5, mid-story
    # council REVISE path (a)). The DB detector set read above stays the SOLE detector
    # — the finding SET is unchanged; each finding is only DECORATED with the corpus
    # vector(s) its CWE maps to, so the corpus content (each vector's OWN
    # name / severity / remediation) reaches the scanner's output. This REPLACES the
    # dead ``get_detection_patterns(LANGUAGE)`` bridge: the loader keys
    # detection_patterns on threat_id, so language lookups returned 0/316 reachable —
    # and materialising those 316 patterns AS detectors floods 60 corpus-authoring
    # false positives (secure examples 62/65 fire), so it is DEFERRED behind a
    # corpus-authoring prerequisite epic. No corpus regex is admitted as a detector,
    # so ``patterns_checked`` stays the true detector count and summary / risk_score
    # (computed above) are final.
    #
    # Bounded by the scan ceiling above: the fan-out per CWE is corpus-fixed (a small,
    # constant set of vectors), and the loop is over the findings, whose count is
    # bounded by the _MAX_SCAN_LINES x detectors scan above -- so the enrichment reads
    # no unbounded input. Best-effort: if the CWE mapping is unavailable the findings
    # stay undecorated (empty ``source_vectors``); the DB detectors still ran.
    cwe_map: dict[str, list[str]] = {}
    try:
        cwe_map = kb.cwe_to_threat_ids()
    except Exception:
        cwe_map = {}
    for f in findings:
        f["source_vectors"] = _source_vectors(kb, cwe_map, f.get("cwe", ""))

    # Sort findings by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 5), f["line_number"]))

    # LOUD, RESUMABLE partial-scan reporting -- CWE-1333 (per-match timeout) and
    # CWE-400 (input ceiling), plus an uncompilable detector (``skipped``). A scan is
    # INCOMPLETE if any match timed out, any detector was skipped, OR the ceiling cut
    # the input; when incomplete, ``risk_score`` / ``summary`` are a LOWER BOUND -- the
    # unscanned code may hold more findings. ``truncated`` carries the RESUME POINT so a
    # caller can fetch the next batch from exactly where the scan stopped:
    #   * ``last_line`` is the last line scanned. On a line-count cut resume from
    #     ``last_line + 1`` with NO overlap -- matching is per line, so no match
    #     straddles a line boundary.
    #   * ``char_offset`` / ``truncated_lines`` name the lines cut MID-LINE. Re-scan
    #     each from ``char_offset - resume_overlap`` (NOT bare ``char_offset``): a match
    #     can straddle the cut -- start before ``char_offset`` yet need a suffix past it
    #     -- so a bare-offset resume would silently drop it. ``resume_overlap`` is the
    #     re-entry guard published for exactly that hazard.
    truncated: dict[str, Any] = {}
    if line_count_truncated or long_lines:
        truncated["last_line"] = len(lines)
        truncated["line_count_truncated"] = line_count_truncated
        truncated["total_lines"] = len(raw_lines)
        truncated["max_scan_lines"] = _MAX_SCAN_LINES
        if long_lines:
            truncated["char_offset"] = _MAX_LINE_LENGTH
            truncated["resume_overlap"] = _RESUME_OVERLAP
            truncated["truncated_lines"] = long_lines

    incomplete = bool(timed_out or skipped or truncated)

    result: dict[str, Any] = {
        "findings": findings,
        "summary": summary,
        "risk_score": risk_score,
        "lines_scanned": len(lines),
        "patterns_checked": len(detectors),
        "incomplete": incomplete,
        "timed_out": timed_out,
        "skipped": skipped,
    }
    if truncated:
        result["truncated"] = truncated

    if incomplete:
        _log.warning(
            "scan_code partial scan -- results are a LOWER BOUND: "
            "%d match timeout(s), %d skipped detector(s), truncated=%s",
            len(timed_out), len(skipped), truncated or None,
        )

    if agent_threats:
        result["agent_threats"] = agent_threats
        result["agent_code_detected"] = True

    emit_event("scan_code", {
        "language": language,
        "lines_scanned": len(lines),
        "findings_count": len(findings),
        "risk_score": risk_score,
        "summary": summary,
        "agent_code_detected": bool(agent_threats),
        "incomplete": incomplete,
        "timed_out_count": len(timed_out),
        "skipped_count": len(skipped),
        "truncated": bool(truncated),
    })

    return result
