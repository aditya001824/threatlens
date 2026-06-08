from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from apireconx.config import get_settings
from apireconx.schemas import ApiEndpoint, AttackRecord, Finding, ScanSummary


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)


class AppStore:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or get_settings().database_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS endpoints (
                    id TEXT PRIMARY KEY,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '',
                    operation_id TEXT,
                    tags_json TEXT NOT NULL,
                    parameters_json TEXT NOT NULL,
                    request_schema_json TEXT,
                    response_schema_json TEXT,
                    auth_required INTEGER NOT NULL DEFAULT 1,
                    source TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target_base_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    summary_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    endpoint_id TEXT,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                );

                CREATE TABLE IF NOT EXISTS attacks (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    endpoint_id TEXT,
                    name TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    payload_json TEXT,
                    headers_json TEXT NOT NULL,
                    status_code INTEGER,
                    response_excerpt TEXT NOT NULL,
                    impact TEXT NOT NULL,
                    replayable INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                );
                """
            )

    def upsert_endpoints(self, endpoints: list[ApiEndpoint]) -> list[ApiEndpoint]:
        now = utcnow().isoformat()
        with self._lock, self.connect() as conn:
            for endpoint in endpoints:
                conn.execute(
                    """
                    INSERT INTO endpoints (
                        id, method, path, summary, operation_id, tags_json, parameters_json,
                        request_schema_json, response_schema_json, auth_required, source, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        method=excluded.method,
                        path=excluded.path,
                        summary=excluded.summary,
                        operation_id=excluded.operation_id,
                        tags_json=excluded.tags_json,
                        parameters_json=excluded.parameters_json,
                        request_schema_json=excluded.request_schema_json,
                        response_schema_json=excluded.response_schema_json,
                        auth_required=excluded.auth_required,
                        source=excluded.source
                    """,
                    (
                        endpoint.id,
                        endpoint.method,
                        endpoint.path,
                        endpoint.summary,
                        endpoint.operation_id,
                        _json_dumps(endpoint.tags),
                        _json_dumps(endpoint.parameters),
                        _json_dumps(endpoint.request_schema) if endpoint.request_schema else None,
                        _json_dumps(endpoint.response_schema) if endpoint.response_schema else None,
                        1 if endpoint.auth_required else 0,
                        endpoint.source,
                        endpoint.created_at.isoformat() if endpoint.created_at else now,
                    ),
                )
        return self.list_endpoints()

    def list_endpoints(self, ids: list[str] | None = None) -> list[ApiEndpoint]:
        with self._lock, self.connect() as conn:
            if ids:
                placeholders = ",".join("?" for _ in ids)
                rows = conn.execute(f"SELECT * FROM endpoints WHERE id IN ({placeholders}) ORDER BY path, method", ids).fetchall()
            else:
                rows = conn.execute("SELECT * FROM endpoints ORDER BY path, method").fetchall()
        return [self._row_to_endpoint(row) for row in rows]

    def get_endpoint(self, endpoint_id: str) -> ApiEndpoint | None:
        endpoints = self.list_endpoints([endpoint_id])
        return endpoints[0] if endpoints else None

    def create_scan(self, target_base_url: str) -> ScanSummary:
        scan_id = str(uuid4())
        now = utcnow()
        summary = {
            "scan_id": scan_id,
            "status": "running",
            "target_base_url": target_base_url,
            "started_at": now.isoformat(),
            "completed_at": None,
            "endpoints_tested": 0,
            "attacks_executed": 0,
            "findings_count": 0,
            "severity_counts": {},
        }
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT INTO scans (id, target_base_url, status, started_at, completed_at, summary_json) VALUES (?, ?, ?, ?, ?, ?)",
                (scan_id, target_base_url, "running", now.isoformat(), None, _json_dumps(summary)),
            )
        return ScanSummary(**summary)

    def finish_scan(self, scan_id: str, status: str, summary_updates: dict[str, Any]) -> ScanSummary:
        row = self._scan_row(scan_id)
        if not row:
            raise KeyError(f"Scan not found: {scan_id}")
        summary = _json_loads(row["summary_json"], {})
        summary.update(summary_updates)
        summary["status"] = status
        summary["completed_at"] = utcnow().isoformat()
        with self._lock, self.connect() as conn:
            conn.execute(
                "UPDATE scans SET status=?, completed_at=?, summary_json=? WHERE id=?",
                (status, summary["completed_at"], _json_dumps(summary), scan_id),
            )
        return ScanSummary(**summary)

    def add_finding(
        self,
        scan_id: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        endpoint_id: str | None = None,
        evidence: dict[str, Any] | None = None,
        remediation: str = "",
    ) -> Finding:
        finding = Finding(
            id=str(uuid4()),
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            severity=severity,  # type: ignore[arg-type]
            category=category,
            title=title,
            description=description,
            evidence=evidence or {},
            remediation=remediation,
            created_at=utcnow(),
        )
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO findings (
                    id, scan_id, endpoint_id, severity, category, title, description,
                    evidence_json, remediation, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    scan_id,
                    endpoint_id,
                    severity,
                    category,
                    title,
                    description,
                    _json_dumps(finding.evidence),
                    remediation,
                    finding.created_at.isoformat(),
                ),
            )
        return finding

    def add_attack(
        self,
        scan_id: str,
        endpoint_id: str | None,
        name: str,
        method: str,
        url: str,
        payload_json: dict[str, Any] | None,
        headers_json: dict[str, str],
        status_code: int | None,
        response_excerpt: str,
        impact: str,
        replayable: bool = True,
    ) -> AttackRecord:
        attack = AttackRecord(
            id=str(uuid4()),
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            name=name,
            method=method,  # type: ignore[arg-type]
            url=url,
            payload_json=payload_json,
            headers_json=headers_json,
            status_code=status_code,
            response_excerpt=response_excerpt[:2000],
            impact=impact,
            replayable=replayable,
            created_at=utcnow(),
        )
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO attacks (
                    id, scan_id, endpoint_id, name, method, url, payload_json,
                    headers_json, status_code, response_excerpt, impact, replayable, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attack.id,
                    scan_id,
                    endpoint_id,
                    name,
                    method,
                    url,
                    _json_dumps(payload_json) if payload_json is not None else None,
                    _json_dumps(headers_json),
                    status_code,
                    attack.response_excerpt,
                    impact,
                    1 if replayable else 0,
                    attack.created_at.isoformat(),
                ),
            )
        return attack

    def list_attacks(self, scan_id: str | None = None, limit: int = 200) -> list[AttackRecord]:
        with self._lock, self.connect() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM attacks WHERE scan_id=? ORDER BY created_at DESC LIMIT ?",
                    (scan_id, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM attacks ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_attack(row) for row in rows]

    def get_attack(self, attack_id: str) -> AttackRecord | None:
        with self._lock, self.connect() as conn:
            row = conn.execute("SELECT * FROM attacks WHERE id=?", (attack_id,)).fetchone()
        return self._row_to_attack(row) if row else None

    def list_findings(self, scan_id: str | None = None, limit: int = 200) -> list[Finding]:
        with self._lock, self.connect() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE scan_id=? ORDER BY created_at DESC LIMIT ?",
                    (scan_id, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def list_scans(self, limit: int = 50) -> list[ScanSummary]:
        with self._lock, self.connect() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
        return [ScanSummary(**_json_loads(row["summary_json"], {})) for row in rows]

    def get_scan_result(self, scan_id: str) -> tuple[ScanSummary, list[Finding], list[AttackRecord]] | None:
        row = self._scan_row(scan_id)
        if not row:
            return None
        return (
            ScanSummary(**_json_loads(row["summary_json"], {})),
            self.list_findings(scan_id=scan_id),
            self.list_attacks(scan_id=scan_id),
        )

    def _scan_row(self, scan_id: str) -> sqlite3.Row | None:
        with self._lock, self.connect() as conn:
            return conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    def _row_to_endpoint(self, row: sqlite3.Row) -> ApiEndpoint:
        return ApiEndpoint(
            id=row["id"],
            method=row["method"],
            path=row["path"],
            summary=row["summary"],
            operation_id=row["operation_id"],
            tags=_json_loads(row["tags_json"], []),
            parameters=_json_loads(row["parameters_json"], []),
            request_schema=_json_loads(row["request_schema_json"], None),
            response_schema=_json_loads(row["response_schema_json"], None),
            auth_required=bool(row["auth_required"]),
            source=row["source"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            scan_id=row["scan_id"],
            endpoint_id=row["endpoint_id"],
            severity=row["severity"],
            category=row["category"],
            title=row["title"],
            description=row["description"],
            evidence=_json_loads(row["evidence_json"], {}),
            remediation=row["remediation"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    def _row_to_attack(self, row: sqlite3.Row) -> AttackRecord:
        return AttackRecord(
            id=row["id"],
            scan_id=row["scan_id"],
            endpoint_id=row["endpoint_id"],
            name=row["name"],
            method=row["method"],
            url=row["url"],
            payload_json=_json_loads(row["payload_json"], None),
            headers_json=_json_loads(row["headers_json"], {}),
            status_code=row["status_code"],
            response_excerpt=row["response_excerpt"],
            impact=row["impact"],
            replayable=bool(row["replayable"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )


store = AppStore()
