# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Shared fixtures for Hyperion test suite."""

from __future__ import annotations

import pytest

from hyperion.server import _CWE_DB, _SCAN_PATTERNS, _findings_log


@pytest.fixture()
def knowledge():
    """Provide access to Hyperion's knowledge base for testing.

    Returns a dict with the CWE database and scan patterns.
    Standalone mode (no graph connection).
    """
    return {
        "cwe_db": _CWE_DB,
        "scan_patterns": _SCAN_PATTERNS,
    }


@pytest.fixture(autouse=True)
def clear_findings_log():
    """Clear the in-memory findings log before each test."""
    _findings_log.clear()
    yield
    _findings_log.clear()


# ---------------------------------------------------------------------------
# Vulnerable code samples
# ---------------------------------------------------------------------------

@pytest.fixture()
def vulnerable_python_sql_injection() -> str:
    """Python code with SQL injection vulnerability."""
    return '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def search_users(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
    return cursor.fetchall()
'''


@pytest.fixture()
def vulnerable_python_command_injection() -> str:
    """Python code with command injection vulnerability."""
    return '''
import os
import subprocess

def convert_file(filename):
    os.system(f"convert {filename} output.pdf")

def list_directory(path):
    result = subprocess.run(f"ls -la {path}", shell=True, capture_output=True)
    return result.stdout.decode()
'''


@pytest.fixture()
def vulnerable_python_hardcoded_secrets() -> str:
    """Python code with hardcoded secrets."""
    return '''
API_KEY = "sk-1234567890abcdefghijklmnop"
DATABASE_URL = "postgresql://admin:s3cretP4ss@prod-db.internal:5432/app"

def connect():
    password = "hunter2"
    return create_connection(password=password)
'''


@pytest.fixture()
def vulnerable_python_deserialization() -> str:
    """Python code with insecure deserialization."""
    return '''
import pickle
import yaml

def load_user_data(data):
    return pickle.loads(data)

def load_config(config_str):
    return yaml.load(config_str)

def calculate(expression):
    return eval(expression)
'''


@pytest.fixture()
def vulnerable_python_prompt_injection() -> str:
    """Python code with prompt injection vulnerability."""
    return '''
def build_prompt(user_input):
    system_prompt = "You are a helpful assistant."
    prompt = f"System: {system_prompt}\\nUser says: {user_input}\\nRespond:"
    return prompt

def agent_with_tools(user_request):
    messages = f"You are an agent. The user input is: {user_request}. Use tools to help."
    return call_llm(messages)
'''


@pytest.fixture()
def safe_python_code() -> str:
    """Python code with no known vulnerabilities."""
    return '''
import os
from pathlib import Path

def get_config():
    return {
        "api_key": os.environ["API_KEY"],
        "debug": os.environ.get("DEBUG", "false").lower() == "true",
    }

def read_file(base_dir: str, filename: str) -> str:
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()
    if not target.is_relative_to(base):
        raise ValueError("Path traversal attempt")
    return target.read_text()
'''


@pytest.fixture()
def vulnerable_javascript_xss() -> str:
    """JavaScript code with XSS vulnerability."""
    return '''
function displayUserProfile(userData) {
    document.getElementById("name").innerHTML = userData.name;
    document.write("<p>" + userData.bio + "</p>");
    $("#comments").html(userData.comments);
}
'''


# ---------------------------------------------------------------------------
# System description samples
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_system_description() -> str:
    """A realistic system description for threat modeling."""
    return (
        "Public-facing REST API that accepts user-submitted JSON, validates "
        "against a schema, queries PostgreSQL, and returns results. Handles "
        "file uploads stored in S3. Uses JWT for authentication with RS256. "
        "Rate limited at the API gateway. Serves 10k requests per minute."
    )


@pytest.fixture()
def sample_structural_signals() -> list[str]:
    """Structural signals matching the sample system description."""
    return [
        "user_input",
        "database",
        "file_upload",
        "public_api",
        "auth_required",
    ]


@pytest.fixture()
def sample_agent_system_description() -> str:
    """A system description for an LLM agent."""
    return (
        "Claude-based agent that reads customer support emails, looks up "
        "order information in a database via tool calls, drafts responses, "
        "and can issue refunds up to $100 without human approval. Takes "
        "user input from a web chat widget. Uses RAG to retrieve relevant "
        "support documentation."
    )


@pytest.fixture()
def sample_agent_structural_signals() -> list[str]:
    """Structural signals for the agent system."""
    return [
        "user_input",
        "agent_tool_calls",
        "llm_prompt",
        "database",
        "pii_data",
    ]
