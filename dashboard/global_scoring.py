from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from typing import Any

from . import runtime as core


SCORING_VERSION = 1


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
    """Calculate an explainable global attacker score.

    Local Hotpot scores remain authoritative for each protected application. This
    global score is dashboard-only correlation across all collected applications.

    The persisted severity total is the base score. Volume grows logarithmically so
    one noisy source cannot dominate the dashboard forever. Cross-application and
    cross-category behavior receives explicit bonuses because the same source probing
    several unrelated applications is substantially more suspicious than one isolated
    probe.
    """

    severity_score = max(0, int(severity_score))
    hits = max(0, int(hits))
    app_count = max(0, int(app_count))
    category_count = max(0, int(category_count))

    # 0, 4, 8, 12, 16, 20 ... as observed volume doubles, capped at 20.
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
    """Central intelligence store with exact cross-application scoring."""

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
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_dashboard_events_ip_category "
                "ON events(client_ip, category)"
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
                conn.execute(
                    """
                    UPDATE events
                    SET suppressed_before = ?
                    WHERE instance_id = ? AND event_id = ?
                    """,
                    (
                        max(0, int(event.get("suppressed_before", 0) or 0)),
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
                client_ip AS ip,
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
            WHERE client_ip IS NOT NULL AND client_ip != '' AND client_ip != 'unknown'
            GROUP BY client_ip
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
            # Keep compatibility with older dashboard consumers while making the
            # global meaning explicit for new clients.
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
        ip = item["ip"]
        apps = conn.execute(
            """
            SELECT instance_id, instance_name, COUNT(*) AS persisted_hits,
                   COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits,
                   MAX(ts) AS last_seen
            FROM events
            WHERE client_ip = ?
            GROUP BY instance_id, instance_name
            ORDER BY hits DESC, instance_name ASC
            """,
            (ip,),
        ).fetchall()
        categories = conn.execute(
            """
            SELECT category, COUNT(*) AS persisted_hits,
                   COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits,
                   MAX(severity) AS max_severity
            FROM events
            WHERE client_ip = ?
            GROUP BY category
            ORDER BY hits DESC, category ASC
            """,
            (ip,),
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

    async def attacker_snapshot(self, ip: str) -> dict[str, Any] | None:
        async with self.lock:
            import asyncio

            return await asyncio.to_thread(self._attacker_snapshot_sync, ip)

    def _attacker_snapshot_sync(self, ip: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            attacker = next(
                (row for row in self._aggregate_attackers(conn) if row["ip"] == ip),
                None,
            )
            if attacker is None:
                return None
            result = self._enrich_attacker(conn, attacker)
            recent = conn.execute(
                """
                SELECT instance_id, instance_name, event_id, ts, method, path, category,
                       action, scanner, severity, escalation_level, attacker_score,
                       suppressed_before
                FROM events
                WHERE client_ip = ?
                ORDER BY ts DESC
                LIMIT 100
                """,
                (ip,),
            ).fetchall()
            result["recent"] = [dict(row) for row in recent]
            result["scoring_version"] = SCORING_VERSION
            return result
        finally:
            conn.close()
