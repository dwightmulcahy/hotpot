from __future__ import annotations

import asyncio
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AttackerState:
    ip: str
    hits: int
    score: int
    first_seen: str | None
    last_seen: str | None
    last_category: str | None
    last_scanner: str | None
    escalation_level: int


class IntelligenceStore:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "hotpot.sqlite3"
        self._lock = asyncio.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS attackers (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    hits INTEGER NOT NULL DEFAULT 0,
                    score INTEGER NOT NULL DEFAULT 0,
                    escalation_level INTEGER NOT NULL DEFAULT 1,
                    last_category TEXT,
                    last_scanner TEXT,
                    last_fingerprint TEXT
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    profile TEXT,
                    rule TEXT,
                    category TEXT,
                    action TEXT,
                    scanner TEXT,
                    scanner_family TEXT,
                    fingerprint TEXT,
                    severity INTEGER NOT NULL DEFAULT 1,
                    escalation_level INTEGER NOT NULL DEFAULT 1,
                    details_json TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
                CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
                CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint);

                CREATE TABLE IF NOT EXISTS notification_state (
                    ip TEXT PRIMARY KEY,
                    last_notified_at TEXT NOT NULL,
                    last_notified_level INTEGER NOT NULL
                );
                """
            )

    async def state_for(self, ip: str) -> AttackerState:
        async with self._lock:
            return await asyncio.to_thread(self._state_for_sync, ip)

    def _state_for_sync(self, ip: str) -> AttackerState:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM attackers WHERE ip = ?", (ip,)).fetchone()
        if row is None:
            return AttackerState(ip, 0, 0, None, None, None, None, 1)
        return AttackerState(
            ip=row["ip"], hits=row["hits"], score=row["score"],
            first_seen=row["first_seen"], last_seen=row["last_seen"],
            last_category=row["last_category"], last_scanner=row["last_scanner"],
            escalation_level=row["escalation_level"],
        )

    async def record(self, event: dict[str, Any], *, score: int,
                     escalation_level: int) -> None:
        async with self._lock:
            await asyncio.to_thread(self._record_sync, event, score, escalation_level)

    def _record_sync(self, event: dict[str, Any], score: int,
                     escalation_level: int) -> None:
        ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        ip = str(event["client_ip"])
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO attackers (
                    ip, first_seen, last_seen, hits, score, escalation_level,
                    last_category, last_scanner, last_fingerprint
                ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    hits = attackers.hits + 1,
                    score = excluded.score,
                    escalation_level = MAX(attackers.escalation_level, excluded.escalation_level),
                    last_category = excluded.last_category,
                    last_scanner = excluded.last_scanner,
                    last_fingerprint = excluded.last_fingerprint
                """,
                (ip, ts, ts, score, escalation_level, event.get("category"),
                 event.get("scanner"), event.get("fingerprint")),
            )
            details = {
                k: v for k, v in event.items()
                if k not in {
                    "timestamp", "client_ip", "method", "path", "profile", "rule",
                    "category", "action", "scanner", "scanner_family", "fingerprint",
                    "severity", "escalation_level"
                }
            }
            conn.execute(
                """
                INSERT INTO events (
                    ts, ip, method, path, profile, rule, category, action,
                    scanner, scanner_family, fingerprint, severity,
                    escalation_level, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts, ip, event.get("method", ""), event.get("path", ""),
                    event.get("profile"), event.get("rule"), event.get("category"),
                    event.get("action"), event.get("scanner"), event.get("scanner_family"),
                    event.get("fingerprint"), int(event.get("severity", 1)),
                    escalation_level, json.dumps(details, separators=(",", ":")),
                ),
            )

    async def claim_notification(self, ip: str, level: int, cooldown_seconds: int) -> bool:
        async with self._lock:
            return await asyncio.to_thread(self._claim_notification_sync, ip, level, cooldown_seconds)

    def _claim_notification_sync(self, ip: str, level: int, cooldown_seconds: int) -> bool:
        now = datetime.now(timezone.utc)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT last_notified_at, last_notified_level FROM notification_state WHERE ip = ?",
                (ip,),
            ).fetchone()
            if row is not None:
                last = datetime.fromisoformat(row["last_notified_at"])
                age = (now - last).total_seconds()
                # Always alert on a new higher escalation level; otherwise respect cooldown.
                if level <= row["last_notified_level"] and age < cooldown_seconds:
                    return False
            conn.execute(
                """
                INSERT INTO notification_state (ip, last_notified_at, last_notified_level)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_notified_at = excluded.last_notified_at,
                    last_notified_level = MAX(notification_state.last_notified_level, excluded.last_notified_level)
                """,
                (ip, now.isoformat(), level),
            )
        return True

    async def cleanup(self, retention_days: int, attacker_retention_days: int) -> dict[str, int]:
        async with self._lock:
            return await asyncio.to_thread(self._cleanup_sync, retention_days, attacker_retention_days)

    def _cleanup_sync(self, retention_days: int, attacker_retention_days: int) -> dict[str, int]:
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        event_cutoff = (now - timedelta(days=retention_days)).isoformat()
        attacker_cutoff = (now - timedelta(days=attacker_retention_days)).isoformat()
        with self._connection() as conn:
            before_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            before_attackers = conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
            conn.execute("DELETE FROM events WHERE ts < ?", (event_cutoff,))
            conn.execute("DELETE FROM attackers WHERE last_seen < ?", (attacker_cutoff,))
            conn.execute("DELETE FROM notification_state WHERE ip NOT IN (SELECT ip FROM attackers)")
            after_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            after_attackers = conn.execute("SELECT COUNT(*) FROM attackers").fetchone()[0]
        # Checkpoint only after the cleanup transaction has committed.
        with self._connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return {
            "events_deleted": before_events - after_events,
            "attackers_deleted": before_attackers - after_attackers,
        }

    async def attacker_history(self, ip: str, limit: int = 100) -> dict[str, Any]:
        async with self._lock:
            return await asyncio.to_thread(self._attacker_history_sync, ip, limit)

    def _attacker_history_sync(self, ip: str, limit: int) -> dict[str, Any]:
        with self._connection() as conn:
            attacker = conn.execute(
                "SELECT * FROM attackers WHERE ip = ?", (ip,)
            ).fetchone()
            events = conn.execute(
                """
                SELECT ts, method, path, profile, rule, category, action, scanner,
                       scanner_family, fingerprint, severity, escalation_level
                FROM events WHERE ip = ? ORDER BY id DESC LIMIT ?
                """,
                (ip, max(1, min(limit, 500))),
            ).fetchall()
        return {
            "attacker": dict(attacker) if attacker is not None else None,
            "events": [dict(row) for row in events],
        }

    async def dashboard_snapshot(self, limit: int = 25) -> dict[str, Any]:
        async with self._lock:
            return await asyncio.to_thread(self._dashboard_snapshot_sync, limit)

    def _dashboard_snapshot_sync(self, limit: int) -> dict[str, Any]:
        with self._connection() as conn:
            totals = conn.execute(
                "SELECT COUNT(*) events, COUNT(DISTINCT ip) unique_ips FROM events"
            ).fetchone()
            top_paths = conn.execute(
                "SELECT path, COUNT(*) hits FROM events GROUP BY path ORDER BY hits DESC LIMIT 10"
            ).fetchall()
            top_categories = conn.execute(
                "SELECT category, COUNT(*) hits FROM events GROUP BY category ORDER BY hits DESC LIMIT 10"
            ).fetchall()
            top_scanners = conn.execute(
                "SELECT scanner, COUNT(*) hits FROM events GROUP BY scanner ORDER BY hits DESC LIMIT 10"
            ).fetchall()
            offenders = conn.execute(
                """
                SELECT ip, hits, score, escalation_level, last_seen, last_category, last_scanner
                FROM attackers ORDER BY score DESC, hits DESC, last_seen DESC LIMIT 10
                """
            ).fetchall()
            recent = conn.execute(
                """
                SELECT ts, ip, method, path, category, action, scanner, fingerprint,
                       severity, escalation_level
                FROM events ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            fingerprints = conn.execute(
                """
                SELECT fingerprint, scanner_family, category, COUNT(*) hits,
                       COUNT(DISTINCT ip) unique_ips
                FROM events GROUP BY fingerprint, scanner_family, category
                ORDER BY hits DESC LIMIT 10
                """
            ).fetchall()

        def rows(values: list[sqlite3.Row]) -> list[dict[str, Any]]:
            return [dict(row) for row in values]

        return {
            "events": totals["events"], "unique_ips": totals["unique_ips"],
            "top_paths": rows(top_paths), "top_categories": rows(top_categories),
            "top_scanners": rows(top_scanners), "top_offenders": rows(offenders),
            "top_fingerprints": rows(fingerprints), "recent": rows(recent),
        }
