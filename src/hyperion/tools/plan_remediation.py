# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""MCP tool: plan_remediation

Given a security finding, plan the fix.  Returns ordered remediation
steps, example secure code, verification procedures, related threats
to check, priority assessment, and estimated effort.
"""

from __future__ import annotations

from typing import Any

from hyperion.tools._shared import coerce, emit_event, get_knowledge

# ---------------------------------------------------------------------------
# Remediation knowledge base -- indexed by threat pattern / CWE
# ---------------------------------------------------------------------------

_REMEDIATIONS: dict[str, dict[str, Any]] = {
    "CWE-78": {
        "title": "OS Command Injection",
        "steps": [
            "Identify all locations where user input reaches system command execution",
            "Replace os.system() / subprocess shell=True with subprocess.run() using argument lists",
            "Implement input validation with allowlisted characters",
            "Add input length limits to prevent buffer-based attacks",
            "Apply least-privilege: run commands with minimal permissions",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# os.system(f'grep {user_input} /var/log/app.log')\n"
                "\n"
                "# SECURE:\n"
                "import subprocess\n"
                "import shlex\n"
                "\n"
                "def safe_grep(pattern: str, logfile: str) -> str:\n"
                "    # Validate input\n"
                "    if not pattern.isalnum():\n"
                "        raise ValueError('Pattern must be alphanumeric')\n"
                "    result = subprocess.run(\n"
                "        ['grep', '--', pattern, logfile],\n"
                "        capture_output=True, text=True, timeout=30,\n"
                "    )\n"
                "    return result.stdout\n"
            ),
            "javascript": (
                "// INSECURE:\n"
                "// exec(`grep ${userInput} /var/log/app.log`)\n"
                "\n"
                "// SECURE:\n"
                "const { execFile } = require('child_process');\n"
                "\n"
                "function safeGrep(pattern, logfile) {\n"
                "  if (!/^[a-zA-Z0-9]+$/.test(pattern)) {\n"
                "    throw new Error('Pattern must be alphanumeric');\n"
                "  }\n"
                "  return execFile('grep', ['--', pattern, logfile]);\n"
                "}\n"
            ),
        },
        "verification": [
            "Run with known malicious inputs: `; rm -rf /`, `$(whoami)`, `| cat /etc/passwd`",
            "Verify subprocess.run uses shell=False (the default)",
            "Check that no user input reaches shell interpretation",
            "Run a SAST tool to confirm no command injection paths remain",
        ],
        "related_threats": ["CWE-77", "CWE-88"],
        "effort": "medium",
    },
    "CWE-89": {
        "title": "SQL Injection",
        "steps": [
            "Identify all SQL queries that incorporate user input",
            "Replace string formatting/concatenation with parameterized queries",
            "Use ORM methods where available instead of raw SQL",
            "Implement input validation as defense-in-depth",
            "Add WAF rules to detect SQL injection attempts",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n"
                "\n"
                "# SECURE:\n"
                "cursor.execute(\n"
                "    'SELECT * FROM users WHERE id = %s',\n"
                "    (user_id,)\n"
                ")\n"
                "\n"
                "# Or with SQLAlchemy:\n"
                "from sqlalchemy import text\n"
                "result = session.execute(\n"
                "    text('SELECT * FROM users WHERE id = :uid'),\n"
                "    {'uid': user_id}\n"
                ")\n"
            ),
            "javascript": (
                "// INSECURE:\n"
                "// db.query(`SELECT * FROM users WHERE id = ${userId}`);\n"
                "\n"
                "// SECURE:\n"
                "db.query('SELECT * FROM users WHERE id = $1', [userId]);\n"
            ),
        },
        "verification": [
            "Test with SQL injection payloads: `' OR '1'='1`, `'; DROP TABLE users;--`",
            "Verify all queries use parameterized placeholders",
            "Run SQLMap or similar tool against the endpoints",
            "Review ORM usage for raw query escape hatches",
        ],
        "related_threats": ["CWE-564", "CWE-943"],
        "effort": "low",
    },
    "CWE-79": {
        "title": "Cross-Site Scripting (XSS)",
        "steps": [
            "Identify all locations where user input is rendered in HTML",
            "Apply context-appropriate output encoding (HTML, JS, URL, CSS)",
            "Use framework auto-escaping (Jinja2, React JSX, etc.)",
            "Implement Content-Security-Policy headers",
            "Sanitize rich text with a library like DOMPurify or bleach",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE (Jinja2 with autoescape off):\n"
                "# return f'<div>{user_input}</div>'\n"
                "\n"
                "# SECURE:\n"
                "from markupsafe import escape\n"
                "return f'<div>{escape(user_input)}</div>'\n"
                "\n"
                "# Or ensure Jinja2 autoescape is on:\n"
                "# Environment(autoescape=True)\n"
            ),
            "javascript": (
                "// INSECURE:\n"
                "// element.innerHTML = userInput;\n"
                "\n"
                "// SECURE:\n"
                "element.textContent = userInput;\n"
                "\n"
                "// If HTML is needed, sanitize first:\n"
                "import DOMPurify from 'dompurify';\n"
                "element.innerHTML = DOMPurify.sanitize(userInput);\n"
            ),
        },
        "verification": [
            "Test with XSS payloads: `<script>alert(1)</script>`, `<img onerror=alert(1) src=x>`",
            "Verify Content-Security-Policy header blocks inline scripts",
            "Check that autoescape is enabled in template engines",
            "Run a browser-based XSS scanner against the application",
        ],
        "related_threats": ["CWE-80", "CWE-87"],
        "effort": "medium",
    },
    "CWE-95": {
        "title": "Code Injection (eval/exec)",
        "steps": [
            "Remove all uses of eval() and exec() on user-controlled input",
            "Replace eval() with ast.literal_eval() for safe data parsing",
            "Use structured dispatch (dict lookup) instead of dynamic execution",
            "If dynamic evaluation is unavoidable, use a sandboxed environment",
            "Audit all code paths that lead to eval/exec",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# result = eval(user_expression)\n"
                "\n"
                "# SECURE (for data parsing):\n"
                "import ast\n"
                "result = ast.literal_eval(user_expression)\n"
                "\n"
                "# SECURE (for dispatch):\n"
                "OPERATIONS = {\n"
                "    'add': lambda a, b: a + b,\n"
                "    'mul': lambda a, b: a * b,\n"
                "}\n"
                "op = OPERATIONS.get(user_op)\n"
                "if op is None:\n"
                "    raise ValueError(f'Unknown operation: {user_op}')\n"
                "result = op(a, b)\n"
            ),
            "javascript": (
                "// INSECURE:\n"
                "// const result = eval(userExpression);\n"
                "\n"
                "// SECURE (for JSON parsing):\n"
                "const result = JSON.parse(userExpression);\n"
                "\n"
                "// SECURE (for dispatch):\n"
                "const operations = {\n"
                "  add: (a, b) => a + b,\n"
                "  mul: (a, b) => a * b,\n"
                "};\n"
                "const op = operations[userOp];\n"
                "if (!op) throw new Error(`Unknown operation: ${userOp}`);\n"
                "const result = op(a, b);\n"
            ),
        },
        "verification": [
            "Verify no eval/exec calls remain on user-controlled paths",
            "Test with code injection payloads: `__import__('os').system('id')`",
            "Run SAST to detect remaining eval/exec usage",
            "Review all dynamic import and reflection patterns",
        ],
        "related_threats": ["CWE-94", "CWE-96"],
        "effort": "medium",
    },
    "CWE-798": {
        "title": "Hardcoded Credentials",
        "steps": [
            "Identify all hardcoded secrets in the codebase",
            "Move secrets to environment variables or a secrets manager",
            "Rotate all exposed credentials immediately",
            "Add secret scanning to the CI/CD pipeline (e.g. git-secrets, trufflehog)",
            "Update .gitignore to exclude config files that may contain secrets",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# API_KEY = 'sk-abc123def456'\n"
                "\n"
                "# SECURE:\n"
                "import os\n"
                "\n"
                "API_KEY = os.environ['API_KEY']\n"
                "\n"
                "# Or with a secrets manager:\n"
                "# from my_secrets import get_secret\n"
                "# API_KEY = get_secret('api-key')\n"
            ),
            "javascript": (
                "// INSECURE:\n"
                "// const API_KEY = 'sk-abc123def456';\n"
                "\n"
                "// SECURE:\n"
                "const API_KEY = process.env.API_KEY;\n"
                "if (!API_KEY) throw new Error('API_KEY not set');\n"
            ),
        },
        "verification": [
            "Run trufflehog or git-secrets against the entire repo history",
            "Verify all secrets load from environment or secrets manager",
            "Confirm rotated credentials work in all environments",
            "Check CI/CD pipeline has secret scanning enabled",
        ],
        "related_threats": ["CWE-321", "CWE-259"],
        "effort": "low",
    },
    "CWE-502": {
        "title": "Deserialization of Untrusted Data",
        "steps": [
            "Replace pickle/marshal with JSON or msgpack for data interchange",
            "If pickle is required, never unpickle data from untrusted sources",
            "Implement allowlist-based deserialization (RestrictedUnpickler)",
            "Add integrity checks (HMAC) to serialized data",
            "Use yaml.safe_load() instead of yaml.load()",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# data = pickle.loads(untrusted_bytes)\n"
                "\n"
                "# SECURE:\n"
                "import json\n"
                "data = json.loads(untrusted_bytes)\n"
                "\n"
                "# If complex objects needed, use a schema:\n"
                "import pydantic\n"
                "\n"
                "class SafeData(pydantic.BaseModel):\n"
                "    name: str\n"
                "    value: int\n"
                "\n"
                "data = SafeData.model_validate_json(untrusted_bytes)\n"
            ),
        },
        "verification": [
            "Verify no pickle.loads/marshal.loads on untrusted data",
            "Test with crafted pickle payloads that execute code",
            "Confirm yaml.safe_load is used everywhere",
            "Check that HMAC validation occurs before deserialization",
        ],
        "related_threats": ["CWE-915"],
        "effort": "medium",
    },
    "CWE-327": {
        "title": "Broken Cryptography",
        "steps": [
            "Replace deprecated algorithms (MD5, SHA-1, DES, 3DES, RC4)",
            "Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption",
            "Use bcrypt, argon2, or scrypt for password hashing",
            "Ensure RSA keys are at least 2048 bits",
            "Use authenticated encryption (GCM) instead of unauthenticated modes",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# import hashlib\n"
                "# hashed = hashlib.md5(password.encode()).hexdigest()\n"
                "\n"
                "# SECURE (password hashing):\n"
                "import bcrypt\n"
                "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n"
                "\n"
                "# SECURE (data integrity):\n"
                "import hashlib\n"
                "digest = hashlib.sha256(data).hexdigest()\n"
            ),
        },
        "verification": [
            "Verify no MD5/SHA-1 usage for security-critical operations",
            "Confirm passwords are hashed with bcrypt/argon2/scrypt",
            "Check AES mode is GCM or CBC-with-HMAC, not ECB",
            "Verify RSA key sizes are >= 2048 bits",
        ],
        "related_threats": ["CWE-328", "CWE-326", "CWE-338"],
        "effort": "medium",
    },
    "CWE-352": {
        "title": "Cross-Site Request Forgery (CSRF)",
        "steps": [
            "Enable CSRF protection in the web framework",
            "Include CSRF tokens in all state-changing forms",
            "Validate the Origin/Referer header on the server",
            "Use SameSite cookie attribute (Strict or Lax)",
            "Implement double-submit cookie pattern as fallback",
        ],
        "code_fixes": {
            "python": (
                "# Flask example -- enable CSRF:\n"
                "from flask_wtf.csrf import CSRFProtect\n"
                "\n"
                "csrf = CSRFProtect(app)\n"
                "\n"
                "# In templates:\n"
                "# <form method='POST'>\n"
                "#   {{ csrf_token() }}\n"
                "#   ...\n"
                "# </form>\n"
            ),
        },
        "verification": [
            "Verify CSRF tokens are present in all state-changing forms",
            "Test form submission without CSRF token (should fail)",
            "Check SameSite cookie attribute is set",
            "Run Burp Suite CSRF scanner against the application",
        ],
        "related_threats": ["CWE-346"],
        "effort": "low",
    },
    "CWE-295": {
        "title": "Certificate Validation Bypass",
        "steps": [
            "Remove all verify=False / SSL_VERIFY=False settings",
            "Fix the root cause: update expired certificates, add correct CA",
            "Use certificate pinning for critical connections",
            "Configure proper CA bundle paths",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# requests.get(url, verify=False)\n"
                "\n"
                "# SECURE:\n"
                "import requests\n"
                "\n"
                "# Default verify=True uses system CA bundle\n"
                "response = requests.get(url)\n"
                "\n"
                "# Or specify a custom CA bundle:\n"
                "response = requests.get(url, verify='/path/to/ca-bundle.crt')\n"
            ),
        },
        "verification": [
            "Verify no verify=False remains in the codebase",
            "Test connections with invalid certificates (should fail)",
            "Check that the CA bundle is up to date",
            "Run sslyze or testssl.sh against your endpoints",
        ],
        "related_threats": ["CWE-297"],
        "effort": "low",
    },
    "CWE-74": {
        "title": "Prompt Injection (Agent/LLM)",
        "steps": [
            "Implement strict input sanitization before including user content in prompts",
            "Use instruction hierarchy: system instructions always override user input",
            "Add output validation to detect and block injection artifacts",
            "Implement prompt templates with clear boundary markers",
            "Use separate LLM calls for untrusted content processing",
            "Monitor for prompt injection patterns in logs",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# prompt = f'You are a helper. User says: {user_input}'\n"
                "\n"
                "# SECURE:\n"
                "def build_prompt(system_instructions: str, user_input: str) -> list:\n"
                "    # Sanitize user input\n"
                "    sanitized = user_input.replace('\\n', ' ').strip()\n"
                "    if len(sanitized) > MAX_INPUT_LENGTH:\n"
                "        sanitized = sanitized[:MAX_INPUT_LENGTH]\n"
                "\n"
                "    return [\n"
                "        {'role': 'system', 'content': system_instructions},\n"
                "        {'role': 'user', 'content': sanitized},\n"
                "    ]\n"
            ),
        },
        "verification": [
            "Test with known prompt injection payloads",
            "Verify system instructions cannot be overridden by user input",
            "Check that output filtering catches injection artifacts",
            "Review all prompt construction paths for input boundaries",
        ],
        "related_threats": ["CWE-77", "CWE-20"],
        "effort": "high",
    },
    "CWE-400": {
        "title": "Resource Exhaustion",
        "steps": [
            "Set token/cost budgets for all LLM calls",
            "Implement request rate limiting",
            "Add timeout limits to all external calls",
            "Monitor resource usage and set alerts",
            "Implement circuit breakers for cascading failure prevention",
        ],
        "code_fixes": {
            "python": (
                "# INSECURE:\n"
                "# response = client.chat(model='gpt-4', max_tokens=None)\n"
                "\n"
                "# SECURE:\n"
                "response = client.chat(\n"
                "    model='gpt-4',\n"
                "    max_tokens=4096,\n"
                "    timeout=30,\n"
                ")\n"
            ),
        },
        "verification": [
            "Verify token limits are set on all LLM calls",
            "Test with large inputs to confirm truncation works",
            "Check rate limiting is active and tested",
            "Verify timeout handling is graceful",
        ],
        "related_threats": ["CWE-770", "CWE-799"],
        "effort": "low",
    },
}

# Fallback for CWEs not in the detailed database
_GENERIC_REMEDIATION: dict[str, Any] = {
    "title": "Security Vulnerability",
    "steps": [
        "Identify the root cause of the vulnerability",
        "Review the CWE entry for detailed mitigation guidance",
        "Apply the principle of least privilege",
        "Implement input validation and output encoding",
        "Add automated security testing to the CI/CD pipeline",
    ],
    "verification": [
        "Run security-focused tests against the fix",
        "Perform code review with security focus",
        "Verify with SAST/DAST tools",
    ],
    "related_threats": [],
    "effort": "medium",
}

# ---------------------------------------------------------------------------
# Priority calculation
# ---------------------------------------------------------------------------

_SEVERITY_PRIORITY: dict[str, int] = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}

_EXPLOITABILITY_BOOST: dict[str, float] = {
    "CWE-89": 0.9,   # SQL injection -- very exploitable
    "CWE-78": 0.9,   # Command injection
    "CWE-95": 0.85,  # Code injection
    "CWE-79": 0.8,   # XSS
    "CWE-798": 0.7,  # Hardcoded creds -- easy to exploit once found
    "CWE-74": 0.85,  # Prompt injection
    "CWE-502": 0.7,  # Deserialization
    "CWE-352": 0.6,  # CSRF
    "CWE-327": 0.4,  # Weak crypto -- needs more effort
    "CWE-295": 0.5,  # Cert bypass -- needs MITM position
}


def _compute_priority(severity: str, cwe: str) -> dict[str, Any]:
    """Compute priority based on severity and exploitability."""
    base = _SEVERITY_PRIORITY.get(severity, 3)
    exploitability = _EXPLOITABILITY_BOOST.get(cwe, 0.5)

    # Lower number = higher priority
    adjusted = max(1, round(base * (1.0 - exploitability * 0.3)))

    labels = {1: "immediate", 2: "urgent", 3: "standard", 4: "low", 5: "backlog"}
    label = labels.get(adjusted, "standard")

    return {
        "priority_rank": adjusted,
        "priority_label": label,
        "exploitability": round(exploitability, 2),
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Main tool
# ---------------------------------------------------------------------------

def plan_remediation(
    finding: dict,
    language: str = "python",
    constraints: dict | None = None,
    conn: object = None,
) -> dict:
    """Plan remediation for a security finding.

    Args:
        finding: Dict with keys:
            - ``threat_id`` (str): Identifier for the threat.
            - ``severity`` (str): "critical", "high", "medium", "low".
            - ``code_context`` (str): The vulnerable code snippet.
            - ``description`` (str): Description of the vulnerability.
            - ``cwe`` (str): CWE identifier (e.g. "CWE-89").
            - ``pattern`` (str): Detection pattern that matched.
        language: Programming language for code fix examples.
        constraints: Optional dict with keys like ``timeline``
            ("immediate"/"sprint"/"quarter"), ``team_size`` (int),
            ``breaking_changes_ok`` (bool).
        conn: Kuzu/LadybugDB connection for graph mode, or None for JSON.

    Returns:
        Dict with keys: remediation_steps, code_fix, verification,
        related_threats, priority, estimated_effort.
    """
    finding = coerce(finding, dict) or {}
    constraints = coerce(constraints, dict) or {}

    threat_id = finding.get("threat_id", "unknown")
    severity = finding.get("severity", "medium").lower()
    cwe = finding.get("cwe", "")
    description = finding.get("description", "")
    code_context = finding.get("code_context", "")
    pattern = finding.get("pattern", "")

    # Look up remediation by CWE
    remediation_data = _REMEDIATIONS.get(cwe, _GENERIC_REMEDIATION)

    # Try knowledge base for additional guidance
    kb_guidance: dict[str, Any] = {}
    try:
        kb = get_knowledge(conn)
        if hasattr(kb, "get_remediation"):
            kb_guidance = kb.get_remediation(cwe) or {}
    except Exception:
        pass

    # Build remediation steps
    steps = list(remediation_data.get("steps", _GENERIC_REMEDIATION["steps"]))

    # Add KB-sourced steps if available
    if kb_guidance.get("additional_steps"):
        steps.extend(kb_guidance["additional_steps"])

    # Add constraint-aware steps
    if constraints.get("breaking_changes_ok") is False:
        steps.insert(0, "Ensure fix is backward-compatible -- no breaking changes allowed")

    if constraints.get("timeline") == "immediate":
        steps.insert(0, "IMMEDIATE: Apply hotfix/WAF rule as temporary mitigation before full fix")

    # Get language-specific code fix
    code_fixes = remediation_data.get("code_fixes", {})
    lang_key = language.lower()
    if lang_key in ("py",):
        lang_key = "python"
    elif lang_key in ("js", "ts", "typescript"):
        lang_key = "javascript"

    code_fix = code_fixes.get(lang_key, code_fixes.get("python", ""))

    # Add KB code fix if available
    if kb_guidance.get("code_fix"):
        code_fix = kb_guidance["code_fix"]

    # Verification steps
    verification = list(
        remediation_data.get("verification", _GENERIC_REMEDIATION["verification"])
    )
    if kb_guidance.get("verification"):
        verification.extend(kb_guidance["verification"])

    # Related threats
    related = list(
        remediation_data.get("related_threats", [])
    )
    if kb_guidance.get("related_threats"):
        related.extend(kb_guidance["related_threats"])
    # Deduplicate
    related = list(dict.fromkeys(related))

    # Priority
    priority = _compute_priority(severity, cwe)

    # Estimated effort
    base_effort = remediation_data.get("effort", "medium")
    team_size = constraints.get("team_size", 1)
    if team_size >= 3 and base_effort == "high":
        estimated_effort = "medium"
    elif team_size <= 1 and base_effort == "low":
        estimated_effort = "low"
    else:
        estimated_effort = base_effort

    result: dict[str, Any] = {
        "threat_id": threat_id,
        "title": remediation_data.get("title", description),
        "cwe": cwe,
        "remediation_steps": steps,
        "code_fix": code_fix,
        "verification": verification,
        "related_threats": related,
        "priority": priority,
        "estimated_effort": estimated_effort,
    }

    if code_context:
        result["original_code_context"] = code_context

    emit_event("plan_remediation", {
        "threat_id": threat_id,
        "severity": severity,
        "cwe": cwe,
        "priority": priority["priority_label"],
        "effort": estimated_effort,
    })

    return result
