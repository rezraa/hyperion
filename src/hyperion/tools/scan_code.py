# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: scan_code

Static security analysis tool.  Hyperion's main weapon.

Takes a code snippet and language, runs regex-based detection patterns
against it, identifies hardcoded secrets, insecure imports, missing
security headers, weak crypto, and agent-specific threats.  Returns
findings with severity, CWE, line numbers, and remediation guidance.
"""

from __future__ import annotations

import re
from typing import Any

from hyperion.tools._shared import coerce, emit_event, get_knowledge

# ---------------------------------------------------------------------------
# Detection patterns -- real regex-based security scanners
# ---------------------------------------------------------------------------

# Each pattern: (name, regex, severity, cwe, description, remediation)
_HARDCODED_SECRETS: list[tuple[str, str, str, str, str, str]] = [
    (
        "hardcoded_api_key",
        r"""(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]""",
        "high",
        "CWE-798",
        "Hardcoded API key detected",
        "Move API keys to environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).",
    ),
    (
        "hardcoded_password",
        r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]""",
        "critical",
        "CWE-798",
        "Hardcoded password detected",
        "Never embed passwords in source code. Use environment variables or a secrets manager.",
    ),
    (
        "hardcoded_token",
        r"""(?i)(?:token|bearer|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-/.]{16,}['"]""",
        "high",
        "CWE-798",
        "Hardcoded authentication token detected",
        "Store tokens in environment variables or a secrets manager. Rotate immediately if committed.",
    ),
    (
        "aws_access_key",
        r"""(?:^|['"\s])(?:AKIA[0-9A-Z]{16})(?:['"\s]|$)""",
        "critical",
        "CWE-798",
        "AWS access key ID detected",
        "Remove AWS credentials from source code. Use IAM roles, instance profiles, or AWS Secrets Manager.",
    ),
    (
        "private_key_block",
        r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----""",
        "critical",
        "CWE-321",
        "Private key embedded in source code",
        "Never embed private keys in source. Store in a secrets manager or use a key management service.",
    ),
    (
        "generic_secret",
        r"""(?i)(?:secret|credential)\s*[:=]\s*['"][A-Za-z0-9_\-/.+]{8,}['"]""",
        "high",
        "CWE-798",
        "Hardcoded secret/credential detected",
        "Move secrets to environment variables or a dedicated secrets manager.",
    ),
    (
        "connection_string_password",
        r"""(?i)(?:mongodb|postgres|mysql|redis|amqp)(?:ql)?://[^:]+:[^@\s]+@""",
        "critical",
        "CWE-798",
        "Database connection string with embedded credentials",
        "Use environment variables for connection strings. Never embed credentials in URIs.",
    ),
]

_INSECURE_IMPORTS_PYTHON: list[tuple[str, str, str, str, str, str]] = [
    (
        "eval_usage",
        r"""\beval\s*\(""",
        "critical",
        "CWE-95",
        "Use of eval() -- arbitrary code execution risk",
        "Replace eval() with ast.literal_eval() for data parsing, or use a safe expression evaluator.",
    ),
    (
        "exec_usage",
        r"""\bexec\s*\(""",
        "critical",
        "CWE-95",
        "Use of exec() -- arbitrary code execution risk",
        "Avoid exec(). Use structured dispatch, importlib, or a sandbox if dynamic execution is required.",
    ),
    (
        "subprocess_shell",
        r"""subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True""",
        "high",
        "CWE-78",
        "subprocess with shell=True -- command injection risk",
        "Use shell=False (default) and pass arguments as a list. Sanitise all user input.",
    ),
    (
        "pickle_loads",
        r"""pickle\.(?:loads?|Unpickler)\s*\(""",
        "high",
        "CWE-502",
        "pickle deserialization -- arbitrary code execution via crafted payloads",
        "Use json, msgpack, or another safe serialization format. Never unpickle untrusted data.",
    ),
    (
        "yaml_unsafe_load",
        r"""yaml\.(?:load|unsafe_load)\s*\([^)]*(?:Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader|FullLoader))?""",
        "high",
        "CWE-502",
        "Unsafe YAML loading -- arbitrary code execution risk",
        "Use yaml.safe_load() instead of yaml.load(). Never use yaml.UnsafeLoader.",
    ),
    (
        "marshal_loads",
        r"""marshal\.loads?\s*\(""",
        "high",
        "CWE-502",
        "marshal deserialization -- code execution risk from untrusted data",
        "Avoid deserializing untrusted data with marshal. Use JSON or another safe format.",
    ),
    (
        "os_system",
        r"""os\.system\s*\(""",
        "high",
        "CWE-78",
        "os.system() -- command injection risk",
        "Use subprocess.run() with shell=False and argument lists instead of os.system().",
    ),
    (
        "tempfile_insecure",
        r"""(?:tempfile\.)?mktemp\s*\(""",
        "medium",
        "CWE-377",
        "Insecure temporary file creation -- race condition risk",
        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() for secure temp file creation.",
    ),
    (
        "assert_security",
        r"""assert\s+.*(?:auth|permission|role|admin|allowed|valid)""",
        "medium",
        "CWE-617",
        "Security check using assert -- stripped in optimized mode (-O)",
        "Replace assert with explicit if/raise for security-critical checks. Assert is for debugging only.",
    ),
]

_INSECURE_IMPORTS_JS: list[tuple[str, str, str, str, str, str]] = [
    (
        "eval_usage",
        r"""\beval\s*\(""",
        "critical",
        "CWE-95",
        "Use of eval() -- arbitrary code execution risk",
        "Use JSON.parse() for data, or a sandboxed evaluator. Never eval untrusted input.",
    ),
    (
        "innerhtml_xss",
        r"""\.innerHTML\s*=""",
        "high",
        "CWE-79",
        "Direct innerHTML assignment -- cross-site scripting (XSS) risk",
        "Use textContent for plain text, or sanitize with DOMPurify before setting innerHTML.",
    ),
    (
        "document_write",
        r"""document\.write\s*\(""",
        "high",
        "CWE-79",
        "document.write() -- XSS risk and performance issues",
        "Use DOM manipulation methods (createElement, appendChild) instead of document.write().",
    ),
    (
        "child_process_exec",
        r"""(?:child_process|exec|execSync|spawn)\s*\(""",
        "high",
        "CWE-78",
        "Command execution -- injection risk if input is unsanitized",
        "Use execFile() with argument arrays. Never interpolate user input into shell commands.",
    ),
    (
        "new_function",
        r"""new\s+Function\s*\(""",
        "high",
        "CWE-95",
        "new Function() constructor -- equivalent to eval()",
        "Avoid dynamic function creation. Use predefined functions or a safe dispatch pattern.",
    ),
]

_INSECURE_CRYPTO: list[tuple[str, str, str, str, str, str]] = [
    (
        "md5_usage",
        r"""(?i)(?:md5|MD5)\s*[.(]""",
        "high",
        "CWE-328",
        "MD5 hash function -- cryptographically broken",
        "Use SHA-256/SHA-3 for integrity checks, bcrypt/argon2 for passwords. MD5 is broken.",
    ),
    (
        "sha1_password",
        r"""(?i)(?:sha1|SHA1)\s*[.(]""",
        "medium",
        "CWE-328",
        "SHA-1 hash function -- weak for security purposes",
        "Use SHA-256/SHA-3 for integrity, bcrypt/argon2/scrypt for passwords.",
    ),
    (
        "des_usage",
        r"""(?i)\b(?:DES|3DES|TripleDES)\b""",
        "high",
        "CWE-327",
        "DES/3DES encryption -- deprecated and weak",
        "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption.",
    ),
    (
        "ecb_mode",
        r"""(?i)(?:ECB|MODE_ECB|AES\.ECB)""",
        "high",
        "CWE-327",
        "ECB block cipher mode -- leaks data patterns",
        "Use GCM, CBC with HMAC, or CTR mode. Never use ECB for anything beyond single-block encryption.",
    ),
    (
        "weak_rsa_key",
        r"""(?:generate|rsa).*?(?:1024|512)\b""",
        "high",
        "CWE-326",
        "Weak RSA key size (512/1024 bits)",
        "Use RSA-2048 minimum, RSA-4096 recommended. Consider switching to Ed25519.",
    ),
    (
        "random_not_secure",
        r"""(?:Math\.random|random\.random|random\.randint)\s*\(""",
        "medium",
        "CWE-338",
        "Non-cryptographic random number generator used",
        "Use secrets module (Python) or crypto.getRandomValues() (JS) for security-sensitive randomness.",
    ),
]

_WEB_SECURITY: list[tuple[str, str, str, str, str, str]] = [
    (
        "debug_mode",
        r"""(?i)(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|'true'|"true")""",
        "high",
        "CWE-489",
        "Debug mode enabled -- exposes internals in production",
        "Set DEBUG=False in production. Use environment variables to control debug state.",
    ),
    (
        "cors_wildcard",
        r"""(?i)(?:Access-Control-Allow-Origin|cors.*origin)\s*[:=]\s*['"]\*['"]""",
        "high",
        "CWE-942",
        "CORS wildcard origin -- allows any domain to make requests",
        "Restrict CORS origins to specific trusted domains. Never use '*' in production.",
    ),
    (
        "sql_format_string",
        r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['"]|['"].*%|['"].*\.format)""",
        "critical",
        "CWE-89",
        "SQL query built with string formatting -- SQL injection risk",
        "Use parameterized queries (placeholders). Never interpolate user input into SQL strings.",
    ),
    (
        "disable_ssl_verify",
        r"""(?i)verify\s*=\s*False|SSL_VERIFY\s*[:=]\s*(?:False|false|0)|CERT_NONE|check_hostname\s*=\s*False""",
        "high",
        "CWE-295",
        "SSL/TLS certificate verification disabled -- MITM attack risk",
        "Always verify SSL certificates. Fix the root cause (expired cert, wrong CA) instead of disabling verification.",
    ),
    (
        "hardcoded_ip",
        r"""\b(?:0\.0\.0\.0|127\.0\.0\.1)\s*[,:]""",
        "low",
        "CWE-200",
        "Hardcoded IP address -- may expose services unintentionally",
        "Use configuration files or environment variables for host bindings. Bind to 127.0.0.1 not 0.0.0.0 in dev.",
    ),
    (
        "verbose_errors",
        r"""(?i)(?:traceback|stack_trace|print_exc|stacktrace)\s*[=(]""",
        "medium",
        "CWE-209",
        "Verbose error output -- may leak internal details to attackers",
        "Log full tracebacks server-side. Return generic error messages to clients.",
    ),
    (
        "no_csrf",
        r"""(?i)(?:csrf_exempt|disable_csrf|WTF_CSRF_ENABLED\s*=\s*False)""",
        "high",
        "CWE-352",
        "CSRF protection disabled",
        "Enable CSRF protection. Use framework-provided CSRF tokens for all state-changing requests.",
    ),
]

# ---------------------------------------------------------------------------
# Agent / LLM specific threats
# ---------------------------------------------------------------------------

_AGENT_THREATS: list[tuple[str, str, str, str, str, str]] = [
    (
        "prompt_injection_risk",
        r"""(?i)(?:system_prompt|system_message|instructions)\s*[:=]\s*.*(?:user|input|request)""",
        "critical",
        "CWE-74",
        "Potential prompt injection -- user input mixed into system prompt",
        "Sanitize and validate all user input before including in prompts. Use structured prompt templates with clear boundaries.",
    ),
    (
        "unrestricted_tool_access",
        r"""(?i)(?:tools?\s*[:=]\s*\[.*(?:all|any|\*))""",
        "high",
        "CWE-269",
        "Unrestricted tool access for agent -- excessive privilege",
        "Apply least-privilege: only expose the specific tools the agent needs. Use allowlists, not denylists.",
    ),
    (
        "unvalidated_tool_output",
        r"""(?i)(?:tool_result|function_result|tool_output)\s*.*(?:exec|eval|execute|run)""",
        "high",
        "CWE-20",
        "Tool output used without validation -- injection via tool results",
        "Validate and sanitize all tool outputs before using them in prompts or executing them.",
    ),
    (
        "context_overflow",
        r"""(?i)(?:max_tokens|context_length|token_limit)\s*[:=]\s*(?:\d{6,}|None|null|float)""",
        "medium",
        "CWE-400",
        "Unbounded or excessively large context window -- resource exhaustion risk",
        "Set reasonable token limits. Implement input truncation and summarization for long contexts.",
    ),
    (
        "no_output_filter",
        r"""(?i)(?:guardrails?\s*[:=]\s*(?:None|null|False|false|\[\]|{}))""",
        "high",
        "CWE-20",
        "No output guardrails configured -- unfiltered agent output",
        "Implement output validation, content filtering, and safety guardrails for all agent responses.",
    ),
    (
        "raw_llm_to_system",
        r"""(?i)(?:os\.system|subprocess|exec|eval)\s*\(\s*(?:response|output|result|completion|message)""",
        "critical",
        "CWE-78",
        "LLM output passed directly to system command execution",
        "Never execute LLM output as code or system commands. Use structured actions with validated parameters.",
    ),
    (
        "memory_poisoning_risk",
        r"""(?i)(?:memory|context|history)\.(?:add|append|insert|update)\s*\(\s*(?:user|input|message)""",
        "medium",
        "CWE-20",
        "User input stored directly in agent memory -- memory poisoning risk",
        "Validate and sanitize user input before storing in agent memory. Implement memory integrity checks.",
    ),
]


# ---------------------------------------------------------------------------
# Pattern registry by language
# ---------------------------------------------------------------------------

def _get_patterns(language: str) -> list[tuple[str, str, str, str, str, str]]:
    """Return all applicable detection patterns for the given language."""
    patterns: list[tuple[str, str, str, str, str, str]] = []

    # Universal patterns
    patterns.extend(_HARDCODED_SECRETS)
    patterns.extend(_INSECURE_CRYPTO)
    patterns.extend(_WEB_SECURITY)

    lang = language.lower()

    if lang in ("python", "py"):
        patterns.extend(_INSECURE_IMPORTS_PYTHON)
    elif lang in ("javascript", "js", "typescript", "ts"):
        patterns.extend(_INSECURE_IMPORTS_JS)
    else:
        # Include both for unknown languages
        patterns.extend(_INSECURE_IMPORTS_PYTHON)
        patterns.extend(_INSECURE_IMPORTS_JS)

    return patterns


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
# Main tool
# ---------------------------------------------------------------------------

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
        lines_scanned, patterns_checked.
    """
    context = coerce(context, str)

    lines = code.splitlines()
    patterns = _get_patterns(language)

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()  # deduplicate: (pattern_name, line_number)

    # Run every detection pattern against every line
    for name, regex, severity, cwe, description, remediation in patterns:
        try:
            compiled = re.compile(regex)
        except re.error:
            continue

        for line_idx, line in enumerate(lines):
            match = compiled.search(line)
            if match:
                dedup_key = f"{name}:{line_idx}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                finding: dict[str, Any] = {
                    "pattern": name,
                    "severity": severity,
                    "cwe": cwe,
                    "description": description,
                    "remediation": remediation,
                    "line_number": line_idx + 1,
                    "matched_text": match.group(0),
                    "line_content": line.rstrip(),
                    "context_lines": _get_line_context(lines, line_idx),
                }
                findings.append(finding)

    # Check for agent-specific threats
    agent_threats: list[dict[str, Any]] = []
    if _has_agent_signals(code):
        for name, regex, severity, cwe, description, remediation in _AGENT_THREATS:
            try:
                compiled = re.compile(regex)
            except re.error:
                continue

            for line_idx, line in enumerate(lines):
                match = compiled.search(line)
                if match:
                    dedup_key = f"agent:{name}:{line_idx}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    threat: dict[str, Any] = {
                        "pattern": name,
                        "severity": severity,
                        "cwe": cwe,
                        "description": description,
                        "remediation": remediation,
                        "line_number": line_idx + 1,
                        "matched_text": match.group(0),
                        "line_content": line.rstrip(),
                        "context_lines": _get_line_context(lines, line_idx),
                    }
                    agent_threats.append(threat)
                    # Agent threats also go in the main findings
                    findings.append(threat)

    # Compute summary counts
    summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1

    risk_score = _compute_risk_score(findings)

    # Try to enrich with knowledge base patterns if available
    kb_enrichments: list[dict[str, Any]] = []
    try:
        kb = get_knowledge(conn)
        if hasattr(kb, "get_detection_patterns"):
            kb_patterns = kb.get_detection_patterns(language)
            for kbp in kb_patterns:
                kb_regex = kbp.get("pattern", "")
                if not kb_regex:
                    continue
                try:
                    compiled = re.compile(kb_regex)
                except re.error:
                    continue

                for line_idx, line in enumerate(lines):
                    match = compiled.search(line)
                    if match:
                        dedup_key = f"kb:{kbp.get('id', kb_regex)}:{line_idx}"
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        enrichment: dict[str, Any] = {
                            "pattern": kbp.get("id", "kb_pattern"),
                            "severity": kbp.get("severity", "medium"),
                            "cwe": kbp.get("cwe", ""),
                            "description": kbp.get("description", ""),
                            "remediation": kbp.get("remediation", ""),
                            "line_number": line_idx + 1,
                            "matched_text": match.group(0),
                            "line_content": line.rstrip(),
                            "context_lines": _get_line_context(lines, line_idx),
                            "source": "knowledge_base",
                        }
                        kb_enrichments.append(enrichment)
                        findings.append(enrichment)

        # Recompute after enrichment
        if kb_enrichments:
            summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings:
                sev = f["severity"]
                if sev in summary:
                    summary[sev] += 1
            risk_score = _compute_risk_score(findings)
    except Exception:
        pass  # knowledge base not available -- that's fine

    # Sort findings by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 5), f["line_number"]))

    result: dict[str, Any] = {
        "findings": findings,
        "summary": summary,
        "risk_score": risk_score,
        "lines_scanned": len(lines),
        "patterns_checked": len(patterns),
    }

    if agent_threats:
        result["agent_threats"] = agent_threats
        result["agent_code_detected"] = True

    if kb_enrichments:
        result["kb_enrichments_count"] = len(kb_enrichments)

    emit_event("scan_code", {
        "language": language,
        "lines_scanned": len(lines),
        "findings_count": len(findings),
        "risk_score": risk_score,
        "summary": summary,
        "agent_code_detected": bool(agent_threats),
    })

    return result
