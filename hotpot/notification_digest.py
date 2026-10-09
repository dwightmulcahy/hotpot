from __future__ import annotations

import asyncio
import ipaddress
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator


class NotificationDigestStore:
    """Durably accumulate notifications suppressed by the per-actor cooldown."""

    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "notification-digest.sqlite3"
        self.window_seconds = max(
            60, int(os.getenv("HOTPOT_NOTIFY_DIGEST_SECONDS", "900"))
        )
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_digest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_key TEXT NOT NULL,
                    level INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    due_at TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT
                )
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_digest_pending_actor ON notification_digest(actor_key, level) WHERE status='pending'"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_notification_digest_due ON notification_digest(status, due_at, id)"
            )

    async def record(self, actor_key: str, level: int) -> None:
        await asyncio.to_thread(self._record_sync, str(actor_key), int(level))

    def _record_sync(self, actor_key: str, level: int) -> None:
        now = datetime.now(timezone.utc)
        due = now + timedelta(seconds=self.window_seconds)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT id FROM notification_digest WHERE actor_key=? AND level=? AND status='pending'",
                (actor_key, level),
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE notification_digest SET count=count+1, last_seen=? WHERE id=?",
                    (now.isoformat(), int(row["id"])),
                )
                return
            conn.execute(
                """
                INSERT INTO notification_digest(actor_key, level, first_seen, last_seen, due_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (actor_key, level, now.isoformat(), now.isoformat(), due.isoformat()),
            )

    async def due(self, limit: int = 25) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._due_sync, limit)

    @staticmethod
    def _source(actor_key: str) -> tuple[str, str]:
        try:
            return str(ipaddress.ip_address(actor_key)), "ip"
        except ValueError:
            if actor_key.startswith("cf-worker:"):
                return "unknown", "cloudflare-worker"
            return "unknown", "identity"

    def _due_sync(self, limit: int) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM notification_digest
                WHERE status='pending' AND due_at<=?
                ORDER BY id ASC LIMIT ?
                """,
                (now, max(1, min(100, int(limit)))),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            actor = str(row["actor_key"])
            client_ip, source_type = self._source(actor)
            count = int(row["count"] or 0)
            event = {
                "event": "notification_digest",
                "attacker_key": actor,
                "client_ip": client_ip,
                "source_type": source_type,
                "escalation_level": int(row["level"] or 1),
                "observed_hits": count,
                "digest_count": count,
                "digest_first_seen": row["first_seen"],
                "digest_last_seen": row["last_seen"],
                "digest_window_seconds": self.window_seconds,
                "category": "repeated-activity",
                "action": "digest",
                "profile": "multiple",
                "path": "multiple suppressed probes",
                "method": "MULTIPLE",
                "severity": int(row["level"] or 1),
            }
            result.append(
                {
                    "id": -int(row["id"]),
                    "event": event,
                    "claimed": True,
                    "job_source": "digest",
                    "attempts": int(row["attempts"] or 0),
                    "last_error": row["last_error"],
                }
            )
        return result

    async def mark_done(self, digest_id: int, *, status: str = "sent") -> None:
        await asyncio.to_thread(self._mark_done_sync, digest_id, status)

    def _mark_done_sync(self, digest_id: int, status: str) -> None:
        with self._connection() as conn:
            conn.execute(
                "UPDATE notification_digest SET status=?, last_error=NULL WHERE id=?",
                (status, int(digest_id)),
            )

    async def mark_error(self, digest_id: int, error: str) -> None:
        await asyncio.to_thread(self._mark_error_sync, digest_id, str(error))

    def _mark_error_sync(self, digest_id: int, error: str) -> None:
        now = datetime.now(timezone.utc)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT attempts FROM notification_digest WHERE id=?", (int(digest_id),)
            ).fetchone()
            attempts = int(row["attempts"] or 0) + 1 if row else 1
            delay = min(3600, 60 * (2 ** min(attempts - 1, 6)))
            conn.execute(
                "UPDATE notification_digest SET attempts=?, due_at=?, last_error=? WHERE id=?",
                (attempts, (now + timedelta(seconds=delay)).isoformat(), error, int(digest_id)),
            )

    async def pending_count(self) -> int:
        return await asyncio.to_thread(self._pending_count_sync)

    def _pending_count_sync(self) -> int:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM notification_digest WHERE status='pending'"
            ).fetchone()
        return int(row["n"] or 0) if row else 0
