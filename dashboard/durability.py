from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .global_scoring import (
    CLOUDFLARE_WORKER_SHARED_IP,
    LEGACY_WORKER_KEY,
    GlobalCentralStore,
    SCORING_VERSION,
    score_attacker,
)


class DurableGlobalStore(GlobalCentralStore):
    """Central store with retention, lifetime rollups, and source generations."""

    def __init__(self, data_dir: Path, *, retention_days: int = 90) -> None:
        self.retention_days = max(1, int(retention_days))
        super().__init__(data_dir)

    def _initialize(self) -> None:
        super()._initialize()
        conn = self._connect()
        try:
            event_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()
            }
            if "lifetime_accounted" not in event_columns:
                conn.execute(
                    "ALTER TABLE events ADD COLUMN lifetime_accounted INTEGER NOT NULL DEFAULT 0"
                )

            cursor_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(cursors)").fetchall()
            }
            if "source_id" not in cursor_columns:
                conn.execute("ALTER TABLE cursors ADD COLUMN source_id TEXT")
            if "reset_count" not in cursor_columns:
                conn.execute(
                    "ALTER TABLE cursors ADD COLUMN reset_count INTEGER NOT NULL DEFAULT 0"
                )
            if "source_changed_at" not in cursor_columns:
                conn.execute("ALTER TABLE cursors ADD COLUMN source_changed_at TEXT")

            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS lifetime_attackers (
                    ip TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    lifetime_hits INTEGER NOT NULL DEFAULT 0,
                    persisted_hits INTEGER NOT NULL DEFAULT 0,
                    severity_score INTEGER NOT NULL DEFAULT 0,
                    max_severity INTEGER NOT NULL DEFAULT 0,
                    max_local_level INTEGER NOT NULL DEFAULT 1,
                    max_global_level INTEGER NOT NULL DEFAULT 1,
                    last_client_ip TEXT,
                    source_type TEXT NOT NULL DEFAULT 'ip',
                    worker_zone TEXT
                );

                CREATE TABLE IF NOT EXISTS lifetime_apps (
                    ip TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    instance_name TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    lifetime_hits INTEGER NOT NULL DEFAULT 0,
                    persisted_hits INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(ip, instance_id)
                );

                CREATE TABLE IF NOT EXISTS lifetime_categories (
                    ip TEXT NOT NULL,
                    category TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    lifetime_hits INTEGER NOT NULL DEFAULT 0,
                    persisted_hits INTEGER NOT NULL DEFAULT 0,
                    max_severity INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(ip, category)
                );

                CREATE TABLE IF NOT EXISTS dashboard_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_lifetime_attackers_last_seen
                    ON lifetime_attackers(last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_lifetime_apps_instance
                    ON lifetime_apps(instance_id, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_lifetime_categories_category
                    ON lifetime_categories(category, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_lifetime_accounted
                    ON events(lifetime_accounted, event_id);
                """
            )

            lifetime_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(lifetime_attackers)").fetchall()
            }
            if "last_client_ip" not in lifetime_columns:
                conn.execute("ALTER TABLE lifetime_attackers ADD COLUMN last_client_ip TEXT")
            if "source_type" not in lifetime_columns:
                conn.execute(
                    "ALTER TABLE lifetime_attackers ADD COLUMN source_type TEXT NOT NULL DEFAULT 'ip'"
                )
            if "worker_zone" not in lifetime_columns:
                conn.execute("ALTER TABLE lifetime_attackers ADD COLUMN worker_zone TEXT")

            # Relabel the pre-identity lifetime bucket for Cloudflare's documented
            # cross-zone Worker shared IPv6. Its historical requests cannot be split
            # by zone retroactively, but they should no longer look like one end user.
            legacy_exists = conn.execute(
                "SELECT 1 FROM lifetime_attackers WHERE ip = ?", (LEGACY_WORKER_KEY,)
            ).fetchone()
            shared_exists = conn.execute(
                "SELECT 1 FROM lifetime_attackers WHERE ip = ?",
                (CLOUDFLARE_WORKER_SHARED_IP,),
            ).fetchone()
            if shared_exists is not None and legacy_exists is None:
                conn.execute(
                    """
                    UPDATE lifetime_attackers
                    SET ip = ?, last_client_ip = ?, source_type = 'cloudflare-worker'
                    WHERE ip = ?
                    """,
                    (
                        LEGACY_WORKER_KEY,
                        CLOUDFLARE_WORKER_SHARED_IP,
                        CLOUDFLARE_WORKER_SHARED_IP,
                    ),
                )
                conn.execute(
                    "UPDATE lifetime_apps SET ip = ? WHERE ip = ?",
                    (LEGACY_WORKER_KEY, CLOUDFLARE_WORKER_SHARED_IP),
                )
                conn.execute(
                    "UPDATE lifetime_categories SET ip = ? WHERE ip = ?",
                    (LEGACY_WORKER_KEY, CLOUDFLARE_WORKER_SHARED_IP),
                )

            self._account_unprocessed_conn(conn)
            conn.commit()
        finally:
            conn.close()

    def _ingest_sync(self, instance, events: list[dict[str, Any]], next_cursor: int) -> int:
        inserted = super()._ingest_sync(instance, events, next_cursor)
        conn = self._connect()
        try:
            self._account_unprocessed_conn(conn)
            conn.commit()
        finally:
            conn.close()
        return inserted

    def _account_unprocessed_conn(self, conn: sqlite3.Connection) -> int:
        rows = conn.execute(
            """
            SELECT instance_id, instance_name, event_id, ts, client_ip,
                   attacker_key, source_type, worker_zone, category,
                   severity, escalation_level, suppressed_before
            FROM events
            WHERE lifetime_accounted = 0
            ORDER BY instance_id, event_id
            """
        ).fetchall()
        if not rows:
            return 0

        affected: set[str] = set()
        for row in rows:
            client_ip = str(row["client_ip"] or "").strip()
            identity_key = str(row["attacker_key"] or client_ip).strip()
            if not identity_key or identity_key == "unknown":
                conn.execute(
                    "UPDATE events SET lifetime_accounted = 1 WHERE instance_id = ? AND event_id = ?",
                    (row["instance_id"], row["event_id"]),
                )
                continue

            ts = str(row["ts"])
            category = str(row["category"] or "unknown")
            observed_hits = 1 + max(0, int(row["suppressed_before"] or 0))
            severity = max(0, int(row["severity"] or 0))
            local_level = max(1, int(row["escalation_level"] or 1))
            source_type = str(row["source_type"] or "ip")
            worker_zone = str(row["worker_zone"]) if row["worker_zone"] else None
            affected.add(identity_key)

            conn.execute(
                """
                INSERT INTO lifetime_attackers(
                    ip, first_seen, last_seen, lifetime_hits, persisted_hits,
                    severity_score, max_severity, max_local_level, max_global_level,
                    last_client_ip, source_type, worker_zone
                ) VALUES (?, ?, ?, ?, 1, ?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    first_seen = MIN(lifetime_attackers.first_seen, excluded.first_seen),
                    last_seen = MAX(lifetime_attackers.last_seen, excluded.last_seen),
                    lifetime_hits = lifetime_attackers.lifetime_hits + excluded.lifetime_hits,
                    persisted_hits = lifetime_attackers.persisted_hits + 1,
                    severity_score = lifetime_attackers.severity_score + excluded.severity_score,
                    max_severity = MAX(lifetime_attackers.max_severity, excluded.max_severity),
                    max_local_level = MAX(lifetime_attackers.max_local_level, excluded.max_local_level),
                    last_client_ip = excluded.last_client_ip,
                    source_type = excluded.source_type,
                    worker_zone = COALESCE(excluded.worker_zone, lifetime_attackers.worker_zone)
                """,
                (
                    identity_key,
                    ts,
                    ts,
                    observed_hits,
                    severity,
                    severity,
                    local_level,
                    client_ip or None,
                    source_type,
                    worker_zone,
                ),
            )
            conn.execute(
                """
                INSERT INTO lifetime_apps(
                    ip, instance_id, instance_name, first_seen, last_seen,
                    lifetime_hits, persisted_hits
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(ip, instance_id) DO UPDATE SET
                    instance_name = excluded.instance_name,
                    first_seen = MIN(lifetime_apps.first_seen, excluded.first_seen),
                    last_seen = MAX(lifetime_apps.last_seen, excluded.last_seen),
                    lifetime_hits = lifetime_apps.lifetime_hits + excluded.lifetime_hits,
                    persisted_hits = lifetime_apps.persisted_hits + 1
                """,
                (
                    identity_key,
                    row["instance_id"],
                    row["instance_name"],
                    ts,
                    ts,
                    observed_hits,
                ),
            )
            conn.execute(
                """
                INSERT INTO lifetime_categories(
                    ip, category, first_seen, last_seen, lifetime_hits,
                    persisted_hits, max_severity
                ) VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(ip, category) DO UPDATE SET
                    first_seen = MIN(lifetime_categories.first_seen, excluded.first_seen),
                    last_seen = MAX(lifetime_categories.last_seen, excluded.last_seen),
                    lifetime_hits = lifetime_categories.lifetime_hits + excluded.lifetime_hits,
                    persisted_hits = lifetime_categories.persisted_hits + 1,
                    max_severity = MAX(lifetime_categories.max_severity, excluded.max_severity)
                """,
                (identity_key, category, ts, ts, observed_hits, severity),
            )
            conn.execute(
                "UPDATE events SET lifetime_accounted = 1 WHERE instance_id = ? AND event_id = ?",
                (row["instance_id"], row["event_id"]),
            )

        for identity_key in affected:
            row = conn.execute(
                "SELECT lifetime_hits, severity_score FROM lifetime_attackers WHERE ip = ?",
                (identity_key,),
            ).fetchone()
            apps = conn.execute(
                "SELECT COUNT(*) FROM lifetime_apps WHERE ip = ?", (identity_key,)
            ).fetchone()[0]
            categories = conn.execute(
                "SELECT COUNT(*) FROM lifetime_categories WHERE ip = ?", (identity_key,)
            ).fetchone()[0]
            score = score_attacker(
                severity_score=int(row["severity_score"] or 0),
                hits=int(row["lifetime_hits"] or 0),
                app_count=int(apps or 0),
                category_count=int(categories or 0),
            )
            conn.execute(
                "UPDATE lifetime_attackers SET max_global_level = MAX(max_global_level, ?) WHERE ip = ?",
                (score.level, identity_key),
            )
        return len(rows)

    async def cursor_state(self, instance_id: str) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._cursor_state_sync, instance_id)

    def _cursor_state_sync(self, instance_id: str) -> dict[str, Any]:
        conn = self._connect()
        try:
            row = conn.execute(
                """
                SELECT cursor, source_id, reset_count, source_changed_at, updated_at
                FROM cursors WHERE instance_id = ?
                """,
                (instance_id,),
            ).fetchone()
            if row is None:
                return {
                    "cursor": 0,
                    "source_id": None,
                    "reset_count": 0,
                    "source_changed_at": None,
                    "updated_at": None,
                }
            return dict(row)
        finally:
            conn.close()

    async def register_source(self, instance_id: str, source_id: str) -> None:
        async with self.lock:
            await asyncio.to_thread(self._register_source_sync, instance_id, source_id)

    def _register_source_sync(self, instance_id: str, source_id: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO cursors(instance_id, cursor, updated_at, source_id, source_changed_at)
                VALUES (?, 0, ?, ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    source_id = CASE
                        WHEN cursors.source_id IS NULL OR cursors.source_id = '' THEN excluded.source_id
                        ELSE cursors.source_id
                    END,
                    source_changed_at = CASE
                        WHEN cursors.source_id IS NULL OR cursors.source_id = '' THEN excluded.source_changed_at
                        ELSE cursors.source_changed_at
                    END
                """,
                (instance_id, now, source_id, now),
            )
            conn.commit()
        finally:
            conn.close()

    async def reset_source(self, instance_id: str, source_id: str) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._reset_source_sync, instance_id, source_id)

    def _reset_source_sync(self, instance_id: str, source_id: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            self._account_unprocessed_conn(conn)
            old = conn.execute(
                "SELECT source_id, cursor, reset_count FROM cursors WHERE instance_id = ?",
                (instance_id,),
            ).fetchone()
            removed = conn.execute(
                "DELETE FROM events WHERE instance_id = ?", (instance_id,)
            ).rowcount
            conn.execute(
                """
                INSERT INTO cursors(
                    instance_id, cursor, updated_at, source_id, reset_count, source_changed_at
                ) VALUES (?, 0, ?, ?, 1, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    cursor = 0,
                    updated_at = excluded.updated_at,
                    source_id = excluded.source_id,
                    reset_count = cursors.reset_count + 1,
                    source_changed_at = excluded.source_changed_at
                """,
                (instance_id, now, source_id, now),
            )
            conn.commit()
            return {
                "instance_id": instance_id,
                "old_source_id": old["source_id"] if old else None,
                "new_source_id": source_id,
                "old_cursor": int(old["cursor"] or 0) if old else 0,
                "events_removed": int(removed or 0),
            }
        finally:
            conn.close()

    async def housekeeping(self, retention_days: int | None = None) -> dict[str, Any]:
        days = self.retention_days if retention_days is None else max(1, int(retention_days))
        async with self.lock:
            return await asyncio.to_thread(self._housekeeping_sync, days)

    def _housekeeping_sync(self, retention_days: int) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        cutoff = (started - timedelta(days=retention_days)).isoformat()
        conn = self._connect()
        try:
            self._account_unprocessed_conn(conn)
            before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            deleted = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
            after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            payload = {
                "at": started.isoformat(),
                "retention_days": retention_days,
                "cutoff": cutoff,
                "events_before": int(before or 0),
                "events_deleted": int(deleted or 0),
                "events_after": int(after or 0),
            }
            conn.execute(
                """
                INSERT INTO dashboard_meta(key, value) VALUES ('last_housekeeping', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (json.dumps(payload, separators=(",", ":")),),
            )
            conn.commit()
            checkpoint = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
            conn.execute("PRAGMA optimize")
            conn.commit()
            if checkpoint is not None:
                payload["wal_checkpoint"] = list(checkpoint)
            return payload
        finally:
            conn.close()

    def _lifetime_attacker_conn(
        self, conn: sqlite3.Connection, identity_key: str
    ) -> dict[str, Any] | None:
        row = conn.execute(
            "SELECT * FROM lifetime_attackers WHERE ip = ?", (identity_key,)
        ).fetchone()
        if row is None:
            return None
        apps = conn.execute(
            """
            SELECT instance_id, instance_name, first_seen, last_seen,
                   lifetime_hits, persisted_hits
            FROM lifetime_apps WHERE ip = ?
            ORDER BY lifetime_hits DESC, instance_name ASC
            """,
            (identity_key,),
        ).fetchall()
        categories = conn.execute(
            """
            SELECT category, first_seen, last_seen, lifetime_hits,
                   persisted_hits, max_severity
            FROM lifetime_categories WHERE ip = ?
            ORDER BY lifetime_hits DESC, category ASC
            """,
            (identity_key,),
        ).fetchall()
        result = dict(row)
        result["identity_key"] = result["ip"]
        result["client_ip"] = result.get("last_client_ip")
        result["app_count"] = len(apps)
        result["category_count"] = len(categories)
        score = score_attacker(
            severity_score=int(result["severity_score"] or 0),
            hits=int(result["lifetime_hits"] or 0),
            app_count=len(apps),
            category_count=len(categories),
        )
        result["global_score"] = score.score
        result["global_level"] = score.level
        result["max_global_level"] = max(
            int(result["max_global_level"] or 1), score.level
        )
        result["apps"] = [dict(value) for value in apps]
        result["categories"] = [dict(value) for value in categories]
        return result

    def _top_lifetime_conn(
        self, conn: sqlite3.Connection, limit: int = 20
    ) -> list[dict[str, Any]]:
        keys = conn.execute(
            """
            SELECT ip FROM lifetime_attackers
            ORDER BY severity_score DESC, lifetime_hits DESC, last_seen DESC
            LIMIT ?
            """,
            (max(limit * 4, limit),),
        ).fetchall()
        values = [
            self._lifetime_attacker_conn(conn, str(row["ip"])) for row in keys
        ]
        result = [value for value in values if value is not None]
        result.sort(
            key=lambda item: (
                int(item["global_score"]),
                int(item["lifetime_hits"]),
                str(item["last_seen"]),
            ),
            reverse=True,
        )
        return result[:limit]

    def _database_health_sync(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            totals = conn.execute(
                """
                SELECT COUNT(*) AS events, MIN(ts) AS oldest_event, MAX(ts) AS newest_event
                FROM events
                """
            ).fetchone()
            lifetime_attackers = conn.execute(
                "SELECT COUNT(*) FROM lifetime_attackers"
            ).fetchone()[0]
            cursor_stats = conn.execute(
                "SELECT COALESCE(SUM(reset_count), 0) resets FROM cursors"
            ).fetchone()
            meta = conn.execute(
                "SELECT value FROM dashboard_meta WHERE key = 'last_housekeeping'"
            ).fetchone()
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
            journal_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0])
        finally:
            conn.close()

        last_housekeeping = None
        if meta is not None:
            try:
                last_housekeeping = json.loads(meta["value"])
            except (TypeError, json.JSONDecodeError):
                last_housekeeping = {"raw": meta["value"]}
        wal_path = Path(str(self.path) + "-wal")
        return {
            "path": str(self.path),
            "size_bytes": self.path.stat().st_size if self.path.exists() else 0,
            "wal_size_bytes": wal_path.stat().st_size if wal_path.exists() else 0,
            "logical_size_bytes": page_count * page_size,
            "journal_mode": journal_mode,
            "raw_events": int(totals["events"] or 0),
            "oldest_event": totals["oldest_event"],
            "newest_event": totals["newest_event"],
            "retention_days": self.retention_days,
            "lifetime_attackers": int(lifetime_attackers or 0),
            "source_resets": int(cursor_stats["resets"] or 0),
            "last_housekeeping": last_housekeeping,
        }

    def _snapshot_sync(self, apps: list[dict[str, Any]]) -> dict[str, Any]:
        snapshot = super()._snapshot_sync(apps)
        conn = self._connect()
        try:
            for attacker in snapshot.get("top_offenders", []):
                attacker["lifetime"] = self._lifetime_attacker_conn(
                    conn, str(attacker.get("identity_key") or attacker.get("ip", ""))
                )
            snapshot["top_lifetime_offenders"] = self._top_lifetime_conn(conn, 20)
        finally:
            conn.close()

        database = self._database_health_sync()
        snapshot["database"] = database
        snapshot["summary"]["lifetime_attackers"] = database["lifetime_attackers"]
        snapshot["summary"]["database_size_mb"] = round(
            database["size_bytes"] / (1024 * 1024), 1
        )
        snapshot["summary"]["retention_days"] = self.retention_days
        snapshot["summary"]["source_resets"] = database["source_resets"]
        return snapshot

    def _attacker_snapshot_sync(self, identity_key: str) -> dict[str, Any] | None:
        current = super()._attacker_snapshot_sync(identity_key)
        conn = self._connect()
        try:
            lifetime = self._lifetime_attacker_conn(conn, identity_key)
        finally:
            conn.close()
        if current is None and lifetime is None:
            return None
        result = current or {
            "identity_key": identity_key,
            "ip": identity_key,
            "client_ip": lifetime.get("client_ip") if lifetime else None,
            "source_type": lifetime.get("source_type", "ip") if lifetime else "ip",
            "worker_zone": lifetime.get("worker_zone") if lifetime else None,
            "persisted_hits": 0,
            "hits": 0,
            "severity_score": 0,
            "max_severity": 0,
            "max_local_level": 1,
            "app_count": 0,
            "category_count": 0,
            "global_score": 0,
            "global_level": 1,
            "score": 0,
            "level": 1,
            "score_components": {
                "severity": 0,
                "volume": 0,
                "applications": 0,
                "categories": 0,
            },
            "apps": [],
            "app_activity": [],
            "categories": [],
            "category_activity": [],
            "recent": [],
            "scoring_version": SCORING_VERSION,
        }
        result["lifetime"] = lifetime
        return result
