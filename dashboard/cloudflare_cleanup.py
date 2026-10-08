from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CloudflareCleanupQueue:
    """Durable queue for Cloudflare rules left behind by failed rollbacks."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "dashboard.sqlite3"
        self._initialize()

    def _connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cloudflare_cleanup_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    recommendation_id TEXT,
                    zone_id TEXT,
                    ruleset_id TEXT,
                    rule_id TEXT,
                    rule_ref TEXT,
                    rule_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cf_cleanup_status ON cloudflare_cleanup_jobs(status, id)"
            )

    async def enqueue(
        self, recommendation_id: str, rules: list[dict[str, Any]]
    ) -> int:
        return await asyncio.to_thread(self._enqueue_sync, recommendation_id, rules)

    def _enqueue_sync(
        self, recommendation_id: str, rules: list[dict[str, Any]]
    ) -> int:
        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        with self._connection() as conn:
            for rule in rules:
                rule_id = str(rule.get("rule_id") or "")
                zone_id = str(rule.get("zone_id") or "")
                existing = conn.execute(
                    """
                    SELECT id FROM cloudflare_cleanup_jobs
                    WHERE status = 'pending' AND zone_id = ? AND rule_id = ?
                    """,
                    (zone_id, rule_id),
                ).fetchone()
                if existing:
                    continue
                conn.execute(
                    """
                    INSERT INTO cloudflare_cleanup_jobs(
                        created_at, updated_at, recommendation_id, zone_id,
                        ruleset_id, rule_id, rule_ref, rule_json, status,
                        attempts, last_error
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?)
                    """,
                    (
                        now,
                        now,
                        recommendation_id,
                        zone_id,
                        str(rule.get("ruleset_id") or ""),
                        rule_id,
                        str(rule.get("ref") or ""),
                        json.dumps(rule, separators=(",", ":")),
                        str(rule.get("rollback_error") or "") or None,
                    ),
                )
                inserted += 1
        return inserted

    async def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._pending_sync, limit)

    def _pending_sync(self, limit: int) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM cloudflare_cleanup_jobs
                WHERE status = 'pending' ORDER BY id ASC LIMIT ?
                """,
                (max(1, min(500, int(limit))),),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["rule"] = json.loads(item.pop("rule_json"))
            except Exception:
                item["rule"] = {}
                item.pop("rule_json", None)
            result.append(item)
        return result

    async def mark_removed(self, job_id: int) -> None:
        await asyncio.to_thread(self._mark_sync, job_id, "removed", None)

    async def mark_error(self, job_id: int, error: str) -> None:
        await asyncio.to_thread(self._mark_sync, job_id, "pending", error)

    def _mark_sync(self, job_id: int, status: str, error: str | None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE cloudflare_cleanup_jobs
                SET updated_at = ?, status = ?, attempts = attempts + 1,
                    last_error = ? WHERE id = ?
                """,
                (now, status, error, int(job_id)),
            )
