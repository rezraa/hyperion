# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Shared state and utilities for all Hyperion tools.

Every tool module imports from here to get access to the singleton
KnowledgeLoader and dual-mode support (standalone JSON vs Othrys graph).
"""

from __future__ import annotations

import functools
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from hyperion.knowledge.loader import KnowledgeLoader

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singletons -- shared across all tool modules
# ---------------------------------------------------------------------------

_knowledge: KnowledgeLoader | None = None


def get_knowledge(conn: Any = None) -> KnowledgeLoader:
    """Return the appropriate knowledge loader for the current mode.

    Args:
        conn: If provided, returns a GraphKnowledgeLoader backed by this
              Kuzu/LadybugDB connection.  If None, returns the JSON singleton.
    """
    if conn is not None:
        from hyperion.knowledge.graph_loader import GraphKnowledgeLoader
        return GraphKnowledgeLoader(conn)
    global _knowledge
    if _knowledge is None:
        _knowledge = KnowledgeLoader()
    return _knowledge


# ---------------------------------------------------------------------------
# Unmatched signal logging — seeds future knowledge base entries
# ---------------------------------------------------------------------------

def log_unmatched_signals(
    signals: list[str],
    tool_name: str,
    titan: str = "hyperion",
) -> None:
    """Append unmatched structural signals to ~/.othrys/unmatched_signals.jsonl."""
    log_path = Path.home() / ".othrys" / "unmatched_signals.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = json.dumps({
        "titan": titan,
        "tool": tool_name,
        "signals": signals,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    with open(log_path, "a") as f:
        f.write(entry + "\n")


# ---------------------------------------------------------------------------
# Finding log -- local JSON file for standalone mode
# ---------------------------------------------------------------------------

def _data_dir() -> Path:
    """Return the path to the Hyperion data storage directory."""
    env = os.environ.get("HYPERION_DATA_DIR")
    base = Path(env) if env else Path.home() / ".hyperion" / "data"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _findings_file() -> Path:
    """Return the path to the local findings JSONL file."""
    return _data_dir() / "findings.jsonl"


def append_finding(record: dict[str, Any]) -> str:
    """Append a finding record to the local JSONL log.

    Returns the finding_id.
    """
    import hashlib

    ts = datetime.now(timezone.utc).isoformat()
    record["timestamp"] = ts
    raw = json.dumps(record, sort_keys=True)
    finding_id = "f-" + hashlib.sha256(raw.encode()).hexdigest()[:12]
    record["finding_id"] = finding_id

    ff = _findings_file()
    ff.parent.mkdir(parents=True, exist_ok=True)
    with open(ff, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return finding_id


# ---------------------------------------------------------------------------
# Event system -- file-based for cross-process dashboard communication
# ---------------------------------------------------------------------------

_event_listeners: list[Callable[[str, dict], None]] = []


def _events_file() -> Path:
    """Return the path to the shared events JSONL file."""
    return _data_dir() / "events.jsonl"


def on_event(callback: Callable[[str, dict], None]) -> None:
    """Register a callback that receives (event_name, payload) on every emit."""
    _event_listeners.append(callback)


def emit_event(event_name: str, payload: dict[str, Any]) -> None:
    """Fire an event to all registered listeners and append to events file.

    The events file (events.jsonl) is the cross-process bridge between the
    MCP server (which emits events) and the dashboard (which reads them).
    """
    for cb in _event_listeners:
        try:
            cb(event_name, payload)
        except Exception:
            pass

    try:
        event = {
            "type": event_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        ef = _events_file()
        ef.parent.mkdir(parents=True, exist_ok=True)
        with open(ef, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass  # best-effort -- never break tool execution


# ---------------------------------------------------------------------------
# Coercion utility -- MCP clients sometimes send JSON as strings
# ---------------------------------------------------------------------------

def coerce(val: Any, expected_type: type | None = None, default: Any = None) -> Any:
    """Coerce MCP-supplied values to a native type, else return *default*.

    MCP clients sometimes send JSON containers as strings. This decodes a
    str into the expected list/dict when possible. On any irreconcilable
    type mismatch the *default* is returned, so callers never receive a
    truthy wrong-type value that survives ``coerce(...) or {}`` and crashes
    a later ``.get()``.
    """
    if val is None:
        return default
    if isinstance(val, str) and expected_type in (list, dict):
        try:
            parsed = json.loads(val)
        except (ValueError, TypeError):
            return default
        return parsed if isinstance(parsed, expected_type) else default
    if expected_type is not None and not isinstance(val, expected_type):
        return default
    return val


def coerce_or_raise(
    val: Any, expected_type: type, empty_default: Any
) -> Any:
    """Like :func:`coerce`, but for values that get PERSISTED.

    ``coerce`` returns its default on any irreconcilable mismatch, which is
    correct for transient/optional fields but dangerous for a field that is
    then written to storage: a non-empty wrong-type value (e.g. a list where
    a dict is expected) would be silently replaced by an empty default and
    persisted, dropping caller data without a sound.

    This stricter variant:
      - ``None`` -> ``empty_default`` (the caller supplied nothing).
      - a value already of ``expected_type`` -> used as-is.
      - a ``str`` that JSON-decodes to ``expected_type`` -> the decoded value.
      - anything else (a non-None wrong-type that cannot be coerced) ->
        ``TypeError``. We refuse to silently persist an empty default in
        place of meaningful but mistyped data.
    """
    if val is None:
        return empty_default
    if isinstance(val, expected_type):
        return val
    if isinstance(val, str) and expected_type in (list, dict):
        try:
            parsed = json.loads(val)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, expected_type):
            return parsed
    raise TypeError(
        f"expected {expected_type.__name__} "
        f"(or JSON {expected_type.__name__} string); got {type(val).__name__}"
    )


# ---------------------------------------------------------------------------
# Kwarg normalisation — per-tool alias / ignore tables
# ---------------------------------------------------------------------------

def normalize_kwargs(func: Callable) -> Callable:
    """Remap caller kwarg synonyms to canonical params before invocation.

    Reads ``_ALIASES`` (synonym -> canonical) and ``_IGNORED`` (drop+warn)
    from the wrapped function's own module. Genuinely-unknown kwargs are
    left untouched so the wrapped signature still raises the standard
    ``unexpected keyword argument`` TypeError — typos are not swallowed.

    Raises TypeError if a synonym and its canonical (or two synonyms of the
    same canonical) are both supplied: an aliasing collision is ambiguous
    and must fail loud, not silently pick a winner.

    The tables are read from ``func.__globals__`` (not via module import) so
    this works both as a normal package import and inside the Othrys
    served-source sandbox, where each tool is exec'd into a synthetic
    namespace that is not importable by name.
    """
    g = func.__globals__
    aliases: dict[str, str] = g.get("_ALIASES", {})
    ignored: set[str] = g.get("_IGNORED", set())

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        for name in list(kwargs):
            if name in ignored:
                _log.warning(
                    "%s: ignoring unsupported argument '%s'",
                    func.__name__, name,
                )
                kwargs.pop(name)
        remapped: dict[str, Any] = {}
        for name in list(kwargs):
            canonical = aliases.get(name)
            if canonical is None:
                continue
            value = kwargs.pop(name)
            if canonical in kwargs or canonical in remapped:
                raise TypeError(
                    f"{func.__name__}() received conflicting arguments for "
                    f"'{canonical}': both it and alias '{name}' were supplied"
                )
            remapped[canonical] = value
        kwargs.update(remapped)
        return func(*args, **kwargs)

    return wrapper
