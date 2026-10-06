from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from .store import IntelligenceStore


class SourceIdentityStore(IntelligenceStore):
    """Intelligence store with a persistent generation identifier.

    The source ID belongs to the SQLite event store, not the container. It survives
    restarts while the database survives and changes when a fresh database is
    created. Central collectors can therefore detect event-ID reuse safely.

    Attacker state is keyed by event ``attacker_key`` when present, while the raw
    event still stores the actual network ``client_ip``. This keeps Cloudflare
    Worker identities separate without losing the address seen at the proxy edge.
    """

    def _initialize(self) -> None:
        super()._initialize()
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS store_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            row = conn.execute(
                "SELECT value FROM store_metadata WHERE key = 'source_id'"
            ).fetchone()
            if row is None:
                source_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO store_metadata(key, value) VALUES ('source_id', ?)",
                    (source_id,),
                )
            else:
                source_id = str(row["value"])
        self.source_id = source_id

    def _record_sync(
        self,
        event: dict[str, Any],
        score: int,
        escalation_level: int,
    ) -> None:
        ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
        client_ip = str(event["client_ip"])
        attacker_key = str(event.get("attacker_key") or client_ip)

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
                (
                    attacker_key,
                    ts,
                    ts,
                    score,
                    escalation_level,
                    event.get("category"),
                    event.get("scanner"),
                    event.get("fingerprint"),
                ),
            )
            details = {
                k: v
                for k, v in event.items()
                if k
                not in {
                    "timestamp",
                    "client_ip",
                    "method",
                    "path",
                    "profile",
                    "rule",
                    "category",
                    "action",
                    "scanner",
                    "scanner_family",
                    "fingerprint",
                    "severity",
                    "escalation_level",
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
                    ts,
                    client_ip,
                    event.get("method", ""),
                    event.get("path", ""),
                    event.get("profile"),
                    event.get("rule"),
                    event.get("category"),
                    event.get("action"),
                    event.get("scanner"),
                    event.get("scanner_family"),
                    event.get("fingerprint"),
                    int(event.get("severity", 1)),
                    escalation_level,
                    json.dumps(details, separators=(",", ":")),
                ),
            )
