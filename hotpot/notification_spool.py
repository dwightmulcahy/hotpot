from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .notification_digest import NotificationDigestStore


class NotificationSpool:
    """Durable fallback queue for security notifications.

    The main telemetry queue is intentionally memory-bounded. If it cannot accept a
    notification, or an external delivery fails after a cooldown claim, this spool
    preserves the event on disk for a later retry. Cooldown-suppressed activity is
    surfaced through the same retry path as a durable digest job.
    """

    def __init__(self, data_dir: Path, *, retry_seconds: int = 60) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "notification-spool.sqlite3"
        self.retry_seconds = max(10, int(retry_seconds))
        self.digest = NotificationDigestStore(data_dir)
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_spool (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_key TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    claimed INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    event_json TEXT NOT NULL,
                    last_error TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_notification_spool_due ON notification_spool(status, next_attempt_at, id)"
            )

    @staticmethod
    def event_key(event: dict[str, Any]) -> str:
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def enqueue(
        self,
        event: dict[str, Any],
        *,
        claimed: bool,
        error: str | None = None,
    ) -> int | None:
        return await asyncio.to_thread(
            self._enqueue_sync, dict(event), bool(claimed), error
        )

    def _enqueue_sync(
        self, event: dict[str, Any], claimed: bool, error: str | None
    ) -> int | None:
        now = datetime.now(timezone.utc)
        key = self.event_key(event)
        with self._connection() as conn:
            existing = conn.execute(
                "SELECT id FROM notification_spool WHERE event_key = ?",
                (key,),
            ).fetchone()
            if existing:
                return int(existing["id"])
            cursor = conn.execute(
                """
                INSERT INTO notification_spool(
                    event_key, created_at, updated_at, next_attempt_at,
                    claimed, status, attempts, event_json, last_error
                ) VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?)
                """,
                (
                    key,
                    now.isoformat(),
                    now.isoformat(),
                    now.isoformat(),
                    1 if claimed else 0,
                    json.dumps(event, separators=(",", ":"), default=str),
                    error,
                ),
            )
            return int(cursor.lastrowid)

    async def due(self, limit: int = 25) -> list[dict[str, Any]]:
        limit = max(1, min(100, int(limit)))
        spool = await asyncio.to_thread(self._due_sync, limit)
        remaining = max(0, limit - len(spool))
        if remaining:
            spool.extend(await self.digest.due(remaining))
        return spool

    def _due_sync(self, limit: int) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM notification_spool
                WHERE status = 'pending' AND next_attempt_at <= ?
                ORDER BY id ASC LIMIT ?
                """,
                (now, max(1, min(100, int(limit)))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["event"] = json.loads(item.pop("event_json"))
            except Exception:
                item["event"] = {}
                item.pop("event_json", None)
            item["claimed"] = bool(item.get("claimed"))
            item["job_source"] = "spool"
            result.append(item)
        return result

    async def mark_claimed(self, job_id: int) -> None:
        if int(job_id) < 0:
            return
        await asyncio.to_thread(self._mark_claimed_sync, job_id)

    def _mark_claimed_sync(self, job_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                "UPDATE notification_spool SET claimed = 1, updated_at = ? WHERE id = ?",
                (now, int(job_id)),
            )

    async def mark_done(self, job_id: int, *, status: str = "sent") -> None:
        if int(job_id) < 0:
            await self.digest.mark_done(abs(int(job_id)), status=status)
            return
        await asyncio.to_thread(self._mark_done_sync, job_id, status)

    def _mark_done_sync(self, job_id: int, status: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE notification_spool
                SET status = ?, updated_at = ?, last_error = NULL
                WHERE id = ?
                """,
                (status, now, int(job_id)),
            )

    async def mark_error(self, job_id: int, error: str) -> None:
        if int(job_id) < 0:
            await self.digest.mark_error(abs(int(job_id)), error)
            return
        await asyncio.to_thread(self._mark_error_sync, job_id, error)

    def _mark_error_sync(self, job_id: int, error: str) -> None:
        now = datetime.now(timezone.utc)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT attempts FROM notification_spool WHERE id = ?",
                (int(job_id),),
            ).fetchone()
            attempts = int(row["attempts"] or 0) + 1 if row else 1
            delay = min(3600, self.retry_seconds * (2 ** min(attempts - 1, 6)))
            conn.execute(
                """
                UPDATE notification_spool
                SET attempts = ?, updated_at = ?, next_attempt_at = ?, last_error = ?
                WHERE id = ?
                """,
                (
                    attempts,
                    now.isoformat(),
                    (now + timedelta(seconds=delay)).isoformat(),
                    error,
                    int(job_id),
                ),
            )

    async def snapshot(self) -> dict[str, Any]:
        snapshot = await asyncio.to_thread(self._snapshot_sync)
        digest_pending = await self.digest.pending_count()
        snapshot["spool_pending"] = snapshot["pending"]
        snapshot["digest_pending"] = digest_pending
        snapshot["pending"] = int(snapshot["pending"]) + digest_pending
        snapshot["digest_window_seconds"] = self.digest.window_seconds
        return snapshot

    def _snapshot_sync(self) -> dict[str, Any]:
        with self._connection() as conn:
            counts = {
                str(row["status"]): int(row["n"])
                for row in conn.execute(
                    "SELECT status, COUNT(*) AS n FROM notification_spool GROUP BY status"
                ).fetchall()
            }
            oldest = conn.execute(
                """
                SELECT created_at, last_error FROM notification_spool
                WHERE status = 'pending' ORDER BY id ASC LIMIT 1
                """
            ).fetchone()
        return {
            "pending": counts.get("pending", 0),
            "sent": counts.get("sent", 0),
            "suppressed": counts.get("suppressed", 0),
            "oldest_pending_at": oldest["created_at"] if oldest else None,
            "last_pending_error": oldest["last_error"] if oldest else None,
            "retry_base_seconds": self.retry_seconds,
        }
