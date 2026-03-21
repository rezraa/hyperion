# Copyright (c) 2026 Reza Malik. Licensed under the Apache License, Version 2.0.
"""Hyperion Dashboard -- Real-time security threat monitoring and finding visualization.

A live SOC-style dashboard showing security findings, active threats, remediation
status, and risk trends.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent
_STATIC = _ROOT / "static"
_TEMPLATES = _ROOT / "templates"
_MAX_FINDINGS = 1000

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    REMEDIATED = "remediated"


@dataclass
class Finding:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    title: str = ""
    severity: str = "info"
    category: str = "general"
    cwe: str = ""
    description: str = ""
    file_path: str = ""
    line: int = 0
    code_context: str = ""
    pattern_matched: str = ""
    secure_alternative: str = ""
    remediation: str = ""
    threat_vector: str = ""
    attack_surface: str = ""
    status: str = "new"
    risk_score: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------

class FindingsStore:
    """Thread-safe bounded store for security findings."""

    def __init__(self, maxlen: int = _MAX_FINDINGS) -> None:
        self._findings: deque[Finding] = deque(maxlen=maxlen)
        self._lock = asyncio.Lock()

    async def add(self, finding: Finding) -> Finding:
        async with self._lock:
            self._findings.appendleft(finding)
        return finding

    async def all(
        self,
        severity: str | None = None,
        category: str | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        async with self._lock:
            items = list(self._findings)
        if severity:
            items = [f for f in items if f.severity == severity]
        if category:
            items = [f for f in items if f.category == category]
        if status:
            items = [f for f in items if f.status == status]
        # Sort: critical first
        items.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.timestamp))
        return [f.to_dict() for f in items[:limit]]

    async def stats(self) -> dict[str, Any]:
        async with self._lock:
            items = list(self._findings)
        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        by_surface: dict[str, int] = {}
        total_risk = 0.0
        for f in items:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_status[f.status] = by_status.get(f.status, 0) + 1
            if f.attack_surface:
                by_surface[f.attack_surface] = by_surface.get(f.attack_surface, 0) + 1
            total_risk += f.risk_score
        count = len(items)
        return {
            "total": count,
            "by_severity": by_severity,
            "by_status": by_status,
            "by_surface": by_surface,
            "risk_score": round(total_risk / max(count, 1), 2),
            "timestamp": time.time(),
        }

    async def threats(self) -> list[dict[str, Any]]:
        async with self._lock:
            items = list(self._findings)
        active = [f for f in items if f.status != "remediated" and f.severity in ("critical", "high")]
        active.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.timestamp))
        return [f.to_dict() for f in active[:50]]

    async def timeline(self, buckets: int = 60) -> list[dict[str, Any]]:
        """Return findings counts bucketed over the last N intervals."""
        async with self._lock:
            items = list(self._findings)
        if not items:
            return []
        now = time.time()
        interval = 60  # 1-minute buckets
        result = []
        for i in range(buckets):
            t_start = now - (i + 1) * interval
            t_end = now - i * interval
            bucket_items = [f for f in items if t_start <= f.timestamp < t_end]
            by_sev: dict[str, int] = {}
            for f in bucket_items:
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            result.append({"time": t_end, "count": len(bucket_items), "by_severity": by_sev})
        result.reverse()
        return result


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, data: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

store = FindingsStore()
manager = ConnectionManager()

app = FastAPI(title="Hyperion Security Operations", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
templates = Jinja2Templates(directory=str(_TEMPLATES))


# -- Pages -----------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# -- WebSocket -------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Send current stats on connect
        stats = await store.stats()
        await ws.send_json({"type": "stats", "data": stats})
        # Send recent findings
        findings = await store.all(limit=50)
        await ws.send_json({"type": "findings_batch", "data": findings})
        # Send timeline
        timeline = await store.timeline()
        await ws.send_json({"type": "timeline", "data": timeline})
        # Keep alive and listen for client messages
        while True:
            data = await ws.receive_json()
            if data.get("type") == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception:
        manager.disconnect(ws)


# -- REST API --------------------------------------------------------------

@app.get("/api/findings")
async def get_findings(
    severity: str | None = Query(None),
    category: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    return await store.all(severity=severity, category=category, status=status, limit=limit)


@app.get("/api/stats")
async def get_stats():
    return await store.stats()


@app.get("/api/threats")
async def get_threats():
    return await store.threats()


@app.get("/api/timeline")
async def get_timeline():
    return await store.timeline()


@app.post("/api/scan")
async def trigger_scan(payload: dict[str, Any] | None = None):
    """Trigger a code scan.  Accepts optional target path / options.

    In production this would invoke the Hyperion scanner pipeline.
    For now, returns an acknowledgement with a scan ID.
    """
    scan_id = uuid.uuid4().hex[:16]
    return {
        "scan_id": scan_id,
        "status": "queued",
        "message": "Scan queued. Findings will stream to the dashboard via WebSocket.",
    }


# -- Programmatic API (for the scanner to push findings) --------------------

async def publish_finding(finding: Finding) -> None:
    """Add a finding to the store and broadcast to all connected clients."""
    await store.add(finding)
    payload = {"type": "finding", "data": finding.to_dict()}
    await manager.broadcast(payload)
    # Also broadcast updated stats
    stats = await store.stats()
    await manager.broadcast({"type": "stats", "data": stats})


@app.post("/api/findings")
async def post_finding(data: dict[str, Any]):
    """Receive a finding from an external scanner or agent."""
    finding = Finding(**{k: v for k, v in data.items() if k in Finding.__dataclass_fields__})
    await publish_finding(finding)
    return finding.to_dict()
