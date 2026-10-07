from __future__ import annotations

import asyncio
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .durability import DurableGlobalStore


class NetworkIntelligenceStore(DurableGlobalStore):
    """Durable dashboard store with persisted network attribution and rollups.

    GeoIP/ASN data is context only. It is deliberately excluded from attacker
    scoring so geography or network ownership can never make an actor more
    suspicious by itself.
    """

    def __init__(self, data_dir: Path, *, retention_days: int = 90) -> None:
        super().__init__(data_dir, retention_days=retention_days)

    def _initialize(self) -> None:
        super()._initialize()
        conn = self._connect()
        try:
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(lifetime_attackers)").fetchall()
            }
            additions = {
                "network_ip": "TEXT",
                "network_asn": "INTEGER",
                "network_provider": "TEXT",
                "network_country_code": "TEXT",
                "network_country": "TEXT",
                "network_city": "TEXT",
                "network_continent": "TEXT",
                "network_enriched": "INTEGER NOT NULL DEFAULT 0",
                "network_enriched_at": "TEXT",
                "network_revision": "TEXT",
            }
            for name, sql_type in additions.items():
                if name not in columns:
                    conn.execute(
                        f"ALTER TABLE lifetime_attackers ADD COLUMN {name} {sql_type}"
                    )
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_lifetime_attackers_network_asn
                    ON lifetime_attackers(network_asn, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_lifetime_attackers_network_country
                    ON lifetime_attackers(network_country_code, last_seen DESC);
                CREATE INDEX IF NOT EXISTS idx_lifetime_attackers_network_revision
                    ON lifetime_attackers(network_revision, last_seen DESC);
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _network_from_row(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "asn": row.get("network_asn"),
            "provider": row.get("network_provider"),
            "country_code": row.get("network_country_code"),
            "country": row.get("network_country"),
            "city": row.get("network_city"),
            "continent": row.get("network_continent"),
            "enriched": bool(row.get("network_enriched", 0)),
            "ip": row.get("network_ip"),
            "enriched_at": row.get("network_enriched_at"),
            "revision": row.get("network_revision"),
            "persisted": True,
        }

    def _lifetime_attacker_conn(
        self, conn: sqlite3.Connection, identity_key: str
    ) -> dict[str, Any] | None:
        result = super()._lifetime_attacker_conn(conn, identity_key)
        if result is not None:
            result["network"] = self._network_from_row(result)
        return result

    async def network_enrichment_candidates(
        self, revision: str, limit: int = 500
    ) -> list[dict[str, str]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._network_enrichment_candidates_sync,
                revision,
                max(1, min(5000, int(limit))),
            )

    def _network_enrichment_candidates_sync(
        self, revision: str, limit: int
    ) -> list[dict[str, str]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT
                    ip AS identity_key,
                    COALESCE(
                        NULLIF(last_client_ip, ''),
                        CASE WHEN source_type = 'ip' THEN ip ELSE NULL END
                    ) AS client_ip
                FROM lifetime_attackers
                WHERE COALESCE(
                        NULLIF(last_client_ip, ''),
                        CASE WHEN source_type = 'ip' THEN ip ELSE NULL END
                    ) IS NOT NULL
                  AND (
                        network_revision IS NULL
                        OR network_revision != ?
                        OR network_ip IS NULL
                        OR network_ip != COALESCE(
                            NULLIF(last_client_ip, ''),
                            CASE WHEN source_type = 'ip' THEN ip ELSE NULL END
                        )
                    )
                ORDER BY last_seen DESC
                LIMIT ?
                """,
                (revision, limit),
            ).fetchall()
            return [
                {
                    "identity_key": str(row["identity_key"]),
                    "client_ip": str(row["client_ip"]),
                }
                for row in rows
                if row["client_ip"]
            ]
        finally:
            conn.close()

    async def update_network_attributions(
        self, records: list[dict[str, Any]]
    ) -> int:
        if not records:
            return 0
        async with self.lock:
            return await asyncio.to_thread(self._update_network_attributions_sync, records)

    def _update_network_attributions_sync(self, records: list[dict[str, Any]]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        updated = 0
        try:
            for record in records:
                network = record.get("network") or {}
                cur = conn.execute(
                    """
                    UPDATE lifetime_attackers
                    SET network_ip = ?,
                        network_asn = ?,
                        network_provider = ?,
                        network_country_code = ?,
                        network_country = ?,
                        network_city = ?,
                        network_continent = ?,
                        network_enriched = ?,
                        network_enriched_at = ?,
                        network_revision = ?
                    WHERE ip = ?
                    """,
                    (
                        str(record.get("client_ip") or "") or None,
                        network.get("asn"),
                        network.get("provider"),
                        network.get("country_code"),
                        network.get("country"),
                        network.get("city"),
                        network.get("continent"),
                        1 if network.get("enriched") else 0,
                        now,
                        str(record.get("revision") or ""),
                        str(record.get("identity_key") or ""),
                    ),
                )
                updated += int(cur.rowcount or 0)
            conn.commit()
            return updated
        finally:
            conn.close()

    @staticmethod
    def _network_match_sql(alias: str = "a") -> str:
        return (
            f"(({alias}.network_asn = ?) OR "
            f"({alias}.network_asn IS NULL AND ? IS NULL)) "
            f"AND COALESCE({alias}.network_provider, '') = ?"
        )

    def _activity_for_network_conn(
        self, conn: sqlite3.Connection, asn: int | None, provider: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        params = (asn, asn, provider)
        match = self._network_match_sql("a")
        apps = conn.execute(
            f"""
            SELECT x.instance_id, x.instance_name,
                   SUM(x.lifetime_hits) AS hits,
                   COUNT(DISTINCT x.ip) AS attackers,
                   MAX(x.last_seen) AS last_seen
            FROM lifetime_apps x
            JOIN lifetime_attackers a ON a.ip = x.ip
            WHERE {match}
            GROUP BY x.instance_id, x.instance_name
            ORDER BY hits DESC, attackers DESC, x.instance_name ASC
            LIMIT 5
            """,
            params,
        ).fetchall()
        categories = conn.execute(
            f"""
            SELECT x.category,
                   SUM(x.lifetime_hits) AS hits,
                   COUNT(DISTINCT x.ip) AS attackers,
                   MAX(x.last_seen) AS last_seen
            FROM lifetime_categories x
            JOIN lifetime_attackers a ON a.ip = x.ip
            WHERE {match}
            GROUP BY x.category
            ORDER BY hits DESC, attackers DESC, x.category ASC
            LIMIT 5
            """,
            params,
        ).fetchall()
        attackers = conn.execute(
            f"""
            SELECT a.ip AS identity_key,
                   a.last_client_ip AS client_ip,
                   a.source_type,
                   a.worker_zone,
                   a.lifetime_hits AS hits,
                   a.max_global_level AS global_level,
                   a.last_seen
            FROM lifetime_attackers a
            WHERE {match}
            ORDER BY a.max_global_level DESC, a.lifetime_hits DESC, a.last_seen DESC
            LIMIT 5
            """,
            params,
        ).fetchall()
        return (
            [dict(row) for row in apps],
            [dict(row) for row in categories],
            [dict(row) for row in attackers],
        )

    def _activity_for_country_conn(
        self, conn: sqlite3.Connection, country_code: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        apps = conn.execute(
            """
            SELECT x.instance_id, x.instance_name,
                   SUM(x.lifetime_hits) AS hits,
                   COUNT(DISTINCT x.ip) AS attackers
            FROM lifetime_apps x
            JOIN lifetime_attackers a ON a.ip = x.ip
            WHERE a.network_country_code = ?
            GROUP BY x.instance_id, x.instance_name
            ORDER BY hits DESC, attackers DESC, x.instance_name ASC
            LIMIT 3
            """,
            (country_code,),
        ).fetchall()
        categories = conn.execute(
            """
            SELECT x.category,
                   SUM(x.lifetime_hits) AS hits,
                   COUNT(DISTINCT x.ip) AS attackers
            FROM lifetime_categories x
            JOIN lifetime_attackers a ON a.ip = x.ip
            WHERE a.network_country_code = ?
            GROUP BY x.category
            ORDER BY hits DESC, attackers DESC, x.category ASC
            LIMIT 3
            """,
            (country_code,),
        ).fetchall()
        return [dict(row) for row in apps], [dict(row) for row in categories]

    def _network_intelligence_conn(self, conn: sqlite3.Connection) -> dict[str, Any]:
        totals = conn.execute(
            """
            SELECT
                COUNT(*) AS lifetime_attackers,
                SUM(CASE WHEN network_enriched = 1 THEN 1 ELSE 0 END) AS attributed_attackers,
                COALESCE(SUM(CASE WHEN network_enriched = 1 THEN lifetime_hits ELSE 0 END), 0)
                    AS attributed_hits
            FROM lifetime_attackers
            """
        ).fetchone()

        network_rows = conn.execute(
            """
            SELECT
                network_asn AS asn,
                COALESCE(NULLIF(network_provider, ''), 'Unknown provider') AS provider,
                COUNT(*) AS attackers,
                COALESCE(SUM(lifetime_hits), 0) AS hits,
                SUM(CASE WHEN max_global_level >= 3 THEN 1 ELSE 0 END) AS level3_plus,
                SUM(CASE WHEN max_global_level >= 4 THEN 1 ELSE 0 END) AS level4,
                MIN(first_seen) AS first_seen,
                MAX(last_seen) AS last_seen
            FROM lifetime_attackers
            WHERE network_enriched = 1
              AND (network_asn IS NOT NULL OR COALESCE(network_provider, '') != '')
            GROUP BY network_asn, network_provider
            ORDER BY hits DESC, attackers DESC, last_seen DESC
            LIMIT 20
            """
        ).fetchall()
        top_networks: list[dict[str, Any]] = []
        for row in network_rows:
            item = dict(row)
            apps, categories, attackers = self._activity_for_network_conn(
                conn,
                int(item["asn"]) if item.get("asn") is not None else None,
                str(item.get("provider") or "Unknown provider"),
            )
            item["top_apps"] = apps
            item["top_categories"] = categories
            item["top_attackers"] = attackers
            top_networks.append(item)

        country_rows = conn.execute(
            """
            SELECT
                network_country_code AS country_code,
                COALESCE(NULLIF(network_country, ''), network_country_code) AS country,
                COUNT(*) AS attackers,
                COALESCE(SUM(lifetime_hits), 0) AS hits,
                SUM(CASE WHEN max_global_level >= 3 THEN 1 ELSE 0 END) AS level3_plus,
                SUM(CASE WHEN max_global_level >= 4 THEN 1 ELSE 0 END) AS level4,
                MIN(first_seen) AS first_seen,
                MAX(last_seen) AS last_seen
            FROM lifetime_attackers
            WHERE network_enriched = 1
              AND COALESCE(network_country_code, '') != ''
            GROUP BY network_country_code, network_country
            ORDER BY hits DESC, attackers DESC, last_seen DESC
            LIMIT 20
            """
        ).fetchall()
        top_countries: list[dict[str, Any]] = []
        for row in country_rows:
            item = dict(row)
            apps, categories = self._activity_for_country_conn(
                conn, str(item.get("country_code") or "")
            )
            item["top_apps"] = apps
            item["top_categories"] = categories
            top_countries.append(item)

        lifetime_attackers = int(totals["lifetime_attackers"] or 0)
        attributed_attackers = int(totals["attributed_attackers"] or 0)
        return {
            "attributed_attackers": attributed_attackers,
            "unattributed_attackers": max(0, lifetime_attackers - attributed_attackers),
            "attributed_hits": int(totals["attributed_hits"] or 0),
            "top_networks": top_networks,
            "top_countries": top_countries,
            "policy": {
                "geography_affects_score": False,
                "asn_affects_score": False,
                "provider_affects_score": False,
                "description": "Network and geography are correlation context only.",
            },
        }

    def _snapshot_sync(self, apps: list[dict[str, Any]]) -> dict[str, Any]:
        snapshot = super()._snapshot_sync(apps)
        conn = self._connect()
        try:
            intelligence = self._network_intelligence_conn(conn)
        finally:
            conn.close()
        snapshot["network_intelligence"] = intelligence
        snapshot["summary"]["network_attributed_attackers"] = intelligence[
            "attributed_attackers"
        ]
        return snapshot

    async def network_snapshot(
        self,
        *,
        asn: int | None = None,
        provider: str | None = None,
        country_code: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._network_snapshot_sync,
                asn,
                provider,
                country_code,
                max(1, min(500, int(limit))),
            )

    def _network_snapshot_sync(
        self,
        asn: int | None,
        provider: str | None,
        country_code: str | None,
        limit: int,
    ) -> dict[str, Any] | None:
        clauses = ["network_enriched = 1"]
        params: list[Any] = []
        selector: dict[str, Any] = {}
        if asn is not None:
            clauses.append("network_asn = ?")
            params.append(asn)
            selector["asn"] = asn
        if provider:
            clauses.append("network_provider = ?")
            params.append(provider)
            selector["provider"] = provider
        if country_code:
            clauses.append("network_country_code = ?")
            params.append(country_code.upper())
            selector["country_code"] = country_code.upper()
        if len(clauses) == 1:
            return None

        conn = self._connect()
        try:
            where = " AND ".join(clauses)
            aggregate = conn.execute(
                f"""
                SELECT COUNT(*) AS attackers,
                       COALESCE(SUM(lifetime_hits), 0) AS hits,
                       SUM(CASE WHEN max_global_level >= 3 THEN 1 ELSE 0 END) AS level3_plus,
                       SUM(CASE WHEN max_global_level >= 4 THEN 1 ELSE 0 END) AS level4,
                       MIN(first_seen) AS first_seen,
                       MAX(last_seen) AS last_seen
                FROM lifetime_attackers
                WHERE {where}
                """,
                tuple(params),
            ).fetchone()
            if aggregate is None or int(aggregate["attackers"] or 0) == 0:
                return None
            keys = conn.execute(
                f"""
                SELECT ip FROM lifetime_attackers
                WHERE {where}
                ORDER BY max_global_level DESC, lifetime_hits DESC, last_seen DESC
                LIMIT ?
                """,
                tuple(params + [limit]),
            ).fetchall()
            attackers = [
                self._lifetime_attacker_conn(conn, str(row["ip"])) for row in keys
            ]
            return {
                "selector": selector,
                "summary": dict(aggregate),
                "attackers": [row for row in attackers if row is not None],
                "policy": {
                    "network_context_affects_score": False,
                },
            }
        finally:
            conn.close()
