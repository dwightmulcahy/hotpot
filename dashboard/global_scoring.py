from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from typing import Any

from . import runtime as core


SCORING_VERSION = 2
CLOUDFLARE_WORKER_SHARED_IP = "2a06:98c0:3600::103"
LEGACY_WORKER_KEY = "cf-worker:legacy-unknown"


@dataclass(frozen=True)
class GlobalScore:
    score: int
    level: int
    severity_score: int
    volume_bonus: int
    app_bonus: int
    category_bonus: int


def score_attacker(
    *,
    severity_score: int,
    hits: int,
    app_count: int,
    category_count: int,
) -> GlobalScore:
    """Calculate an explainable global attacker score."""

    severity_score = max(0, int(severity_score))
    hits = max(0, int(hits))
    app_count = max(0, int(app_count))
    category_count = max(0, int(category_count))

    volume_bonus = min(20, int(math.log2(max(1, hits))) * 4)
    app_bonus = max(0, app_count - 1) * 8
    category_bonus = max(0, category_count - 1) * 4
    score = severity_score + volume_bonus + app_bonus + category_bonus

    if hits >= 20 or score >= 60 or app_count >= 4:
        level = 4
    elif hits >= 10 or score >= 30 or app_count >= 3 or category_count >= 3:
        level = 3
    elif hits >= 3 or score >= 10 or app_count >= 2:
        level = 2
    else:
        level = 1

    return GlobalScore(
        score=score,
        level=level,
        severity_score=severity_score,
        volume_bonus=volume_bonus,
        app_bonus=app_bonus,
        category_bonus=category_bonus,
    )


class GlobalCentralStore(core.CentralStore):
    """Central intelligence store with cross-application actor scoring.

    ``client_ip`` remains the network address observed by Hotpot. ``attacker_key``
    is the correlation identity. They are normally identical, but cross-zone
    Cloudflare Worker requests use ``cf-worker:<zone>`` so unrelated Workers do
    not inherit one shared synthetic IPv6 reputation.
    """

    def _initialize(self) -> None:
        super()._initialize()
        conn = self._connect()
        try:
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(events)").fetchall()
            }
            if "suppressed_before" not in columns:
                conn.execute(
                    "ALTER TABLE events ADD COLUMN suppressed_before INTEGER NOT NULL DEFAULT 0"
                )
            if "attacker_key" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN attacker_key TEXT")
            if "source_type" not in columns:
                conn.execute(
                    "ALTER TABLE events ADD COLUMN source_type TEXT NOT NULL DEFAULT 'ip'"
                )
            if "worker_zone" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN worker_zone TEXT")

            # Existing rows predate actor-aware identity. Normal rows correlate by
            # their original IP. The documented Cloudflare cross-zone Worker shared
            # address is labeled explicitly instead of being presented as an end user.
            conn.execute(
                """
                UPDATE events
                SET attacker_key = CASE
                        WHEN client_ip = ? THEN ?
                        ELSE client_ip
                    END,
                    source_type = CASE
                        WHEN client_ip = ? THEN 'cloudflare-worker'
                        ELSE COALESCE(NULLIF(source_type, ''), 'ip')
                    END
                WHERE attacker_key IS NULL OR attacker_key = ''
                """,
                (
                    CLOUDFLARE_WORKER_SHARED_IP,
                    LEGACY_WORKER_KEY,
                    CLOUDFLARE_WORKER_SHARED_IP,
                ),
            )
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_ip_category
                    ON events(client_ip, category);
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_attacker_key
                    ON events(attacker_key, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_dashboard_events_attacker_category
                    ON events(attacker_key, category);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _ingest_sync(self, instance, events: list[dict[str, Any]], next_cursor: int) -> int:
        inserted = super()._ingest_sync(instance, events, next_cursor)
        conn = self._connect()
        try:
            for event in events:
                event_id = int(event.get("id", 0) or 0)
                if event_id <= 0:
                    continue
                client_ip = str(event.get("client_ip", "unknown"))
                attacker_key = str(event.get("attacker_key") or client_ip)
                source_type = str(event.get("source_type") or "ip")
                worker_zone = event.get("worker_zone")
                conn.execute(
                    """
                    UPDATE events
                    SET suppressed_before = ?, attacker_key = ?, source_type = ?, worker_zone = ?
                    WHERE instance_id = ? AND event_id = ?
                    """,
                    (
                        max(0, int(event.get("suppressed_before", 0) or 0)),
                        attacker_key,
                        source_type,
                        str(worker_zone) if worker_zone else None,
                        instance.instance_id,
                        event_id,
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        return inserted

    def _aggregate_attackers(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT
                attacker_key AS identity_key,
                attacker_key AS ip,
                MAX(client_ip) AS client_ip,
                MAX(source_type) AS source_type,
                MAX(worker_zone) AS worker_zone,
                COUNT(*) AS persisted_hits,
                COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits,
                COALESCE(SUM(severity), 0) AS severity_score,
                COALESCE(MAX(severity), 0) AS max_severity,
                COALESCE(MAX(escalation_level), 1) AS max_local_level,
                COUNT(DISTINCT instance_id) AS app_count,
                COUNT(DISTINCT category) AS category_count,
                MIN(ts) AS first_seen,
                MAX(ts) AS last_seen
            FROM events
            WHERE attacker_key IS NOT NULL AND attacker_key != '' AND attacker_key != 'unknown'
            GROUP BY attacker_key
            """
        ).fetchall()

        scored: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            result = score_attacker(
                severity_score=int(item.get("severity_score", 0) or 0),
                hits=int(item.get("hits", 0) or 0),
                app_count=int(item.get("app_count", 0) or 0),
                category_count=int(item.get("category_count", 0) or 0),
            )
            item.update(
                global_score=result.score,
                global_level=result.level,
                score_components={
                    "severity": result.severity_score,
                    "volume": result.volume_bonus,
                    "applications": result.app_bonus,
                    "categories": result.category_bonus,
                },
            )
            item["score"] = result.score
            item["level"] = result.level
            scored.append(item)

        scored.sort(
            key=lambda item: (
                int(item["global_score"]),
                int(item["hits"]),
                int(item["app_count"]),
                str(item["last_seen"] or ""),
            ),
            reverse=True,
        )
        return scored

    @staticmethod
    def _enrich_attacker(conn: sqlite3.Connection, item: dict[str, Any]) -> dict[str, Any]:
        identity_key = item["identity_key"]
        apps = conn.execute(
            """
            SELECT instance_id, instance_name, COUNT(*) AS persisted_hits,
                   COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits,
                   MAX(ts) AS last_seen
            FROM events
            WHERE attacker_key = ?
            GROUP BY instance_id, instance_name
            ORDER BY hits DESC, instance_name ASC
            """,
            (identity_key,),
        ).fetchall()
        categories = conn.execute(
            """
            SELECT category, COUNT(*) AS persisted_hits,
                   COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits,
                   MAX(severity) AS max_severity
            FROM events
            WHERE attacker_key = ?
            GROUP BY category
            ORDER BY hits DESC, category ASC
            """,
            (identity_key,),
        ).fetchall()
        result = dict(item)
        result["apps"] = [row["instance_name"] for row in apps]
        result["app_activity"] = [dict(row) for row in apps]
        result["categories"] = [row["category"] for row in categories]
        result["category_activity"] = [dict(row) for row in categories]
        return result

    def _snapshot_sync(self, apps: list[dict[str, Any]]) -> dict[str, Any]:
        snapshot = super()._snapshot_sync(apps)
        conn = self._connect()
        try:
            attackers = self._aggregate_attackers(conn)
            top = [self._enrich_attacker(conn, row) for row in attackers[:20]]
        finally:
            conn.close()

        level_counts = {str(level): 0 for level in range(1, 5)}
        for attacker in attackers:
            level_counts[str(attacker["global_level"])] += 1

        snapshot["top_offenders"] = top
        snapshot["summary"]["level3_plus"] = sum(
            1 for row in attackers if int(row["global_level"]) >= 3
        )
        snapshot["summary"]["global_level4"] = level_counts["4"]
        snapshot["summary"]["highest_global_score"] = (
            int(attackers[0]["global_score"]) if attackers else 0
        )
        snapshot["global_scoring"] = {
            "version": SCORING_VERSION,
            "identity": "attacker_key (Cloudflare Workers split by trusted CF-Worker zone)",
            "levels": level_counts,
            "policy": {
                "level2": "hits>=3 or score>=10 or apps>=2",
                "level3": "hits>=10 or score>=30 or apps>=3 or categories>=3",
                "level4": "hits>=20 or score>=60 or apps>=4",
                "app_bonus_per_additional_app": 8,
                "category_bonus_per_additional_category": 4,
                "volume_bonus_cap": 20,
            },
        }
        return snapshot

    async def attacker_snapshot(self, identity_key: str) -> dict[str, Any] | None:
        async with self.lock:
            import asyncio

            return await asyncio.to_thread(self._attacker_snapshot_sync, identity_key)

    def _attacker_snapshot_sync(self, identity_key: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            attacker = next(
                (
                    row
                    for row in self._aggregate_attackers(conn)
                    if row["identity_key"] == identity_key
                ),
                None,
            )
            if attacker is None:
                return None
            result = self._enrich_attacker(conn, attacker)
            recent = conn.execute(
                """
                SELECT instance_id, instance_name, event_id, ts, client_ip,
                       attacker_key AS identity_key, source_type, worker_zone,
                       method, path, category, action, scanner, severity,
                       escalation_level, attacker_score, suppressed_before
                FROM events
                WHERE attacker_key = ?
                ORDER BY ts DESC
                LIMIT 100
                """,
                (identity_key,),
            ).fetchall()
            result["recent"] = [dict(row) for row in recent]
            result["scoring_version"] = SCORING_VERSION
            return result
        finally:
            conn.close()
