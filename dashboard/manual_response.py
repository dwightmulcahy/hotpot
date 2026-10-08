from __future__ import annotations

import asyncio
import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .global_scoring import CLOUDFLARE_WORKER_SHARED_IP, LEGACY_WORKER_KEY


MANUAL_ACTIONS = {
    "challenge": ("recommend_challenge", 6),
    "block_1h": ("recommend_block", 1),
    "block_24h": ("recommend_block", 24),
    "long_block": ("recommend_long_block", 168),
}


class ManualResponseService:
    """Build and persist explicit operator-approved response recommendations."""

    def __init__(self, store) -> None:
        self.store = store

    async def prepare(
        self,
        *,
        actor_key: str,
        action_key: str,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        actor_key = actor_key.strip()
        if not actor_key:
            raise ValueError("actor_key is required")
        if action_key not in MANUAL_ACTIONS:
            raise ValueError("unsupported manual response action")
        async with self.store.lock:
            return await asyncio.to_thread(
                self._prepare_sync, actor_key, action_key, apps
            )

    def _prepare_sync(
        self,
        actor_key: str,
        action_key: str,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        conn = self.store._connect()
        try:
            event = conn.execute(
                """
                SELECT attacker_key, client_ip, source_type, worker_zone, ts
                FROM events
                WHERE attacker_key = ?
                ORDER BY ts DESC LIMIT 1
                """,
                (actor_key,),
            ).fetchone()
            if event is None:
                raise ValueError("actor has no retained events")
            client_ip = str(event["client_ip"] or "").strip()
            source_type = str(event["source_type"] or "ip").strip()
            worker_zone = str(event["worker_zone"] or "").strip() or None
            if not client_ip:
                raise ValueError("actor has no usable network target")

            if (
                client_ip == CLOUDFLARE_WORKER_SHARED_IP
                and (source_type != "cloudflare-worker" or not worker_zone or actor_key == LEGACY_WORKER_KEY)
            ):
                raise ValueError(
                    "shared Cloudflare Worker address cannot be manually blocked without a trustworthy Worker zone"
                )

            allow_cidrs: set[str] = set()
            trusted_proxy_cidrs: set[str] = set()
            for app in apps:
                allow_cidrs.update(str(value) for value in app.get("allowlist_cidrs") or [])
                trusted_proxy_cidrs.update(
                    str(value) for value in app.get("trusted_proxy_cidrs") or []
                )
            try:
                address = ipaddress.ip_address(client_ip)
            except ValueError as exc:
                raise ValueError("actor client IP is invalid") from exc
            for raw in sorted(allow_cidrs | trusted_proxy_cidrs):
                try:
                    network = ipaddress.ip_network(raw, strict=False)
                except ValueError:
                    continue
                if address.version == network.version and address in network:
                    raise ValueError(f"target is safety-excluded by CIDR {network.with_prefixlen}")

            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            app_rows = conn.execute(
                """
                SELECT instance_id, instance_name,
                       COUNT(*) + COALESCE(SUM(suppressed_before), 0) AS hits
                FROM events
                WHERE attacker_key = ? AND ts >= ?
                GROUP BY instance_id, instance_name
                ORDER BY hits DESC, instance_name ASC
                """,
                (actor_key, cutoff),
            ).fetchall()
            if not app_rows:
                app_rows = conn.execute(
                    """
                    SELECT instance_id, instance_name, COUNT(*) AS hits
                    FROM events WHERE attacker_key = ?
                    GROUP BY instance_id, instance_name
                    ORDER BY hits DESC, instance_name ASC
                    """,
                    (actor_key,),
                ).fetchall()
            if not app_rows:
                raise ValueError("actor has no protected application activity")

            action, duration_hours = MANUAL_ACTIONS[action_key]
            target_type = "ip"
            target_value = client_ip
            if source_type == "cloudflare-worker" and worker_zone:
                target_type = "cloudflare-worker-zone"
                target_value = worker_zone

            now = datetime.now(timezone.utc)
            recommendation_id = "manual_" + uuid.uuid4().hex
            evidence = {
                "manual": True,
                "instance_ids": [str(row["instance_id"]) for row in app_rows],
                "app_activity": [dict(row) for row in app_rows],
                "client_ip": client_ip,
                "source_type": source_type,
                "worker_zone": worker_zone,
                "last_seen": str(event["ts"] or ""),
            }
            return {
                "recommendation_id": recommendation_id,
                "actor_key": actor_key,
                "action": action,
                "confidence": "high",
                "status": "approved",
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=max(24, duration_hours))).isoformat(),
                "approved_at": now.isoformat(),
                "enforcement_expires_at": (now + timedelta(hours=duration_hours)).isoformat(),
                "last_seen": evidence["last_seen"],
                "target_type": target_type,
                "target_value": target_value,
                "duration_hours": duration_hours,
                "summary": f"Manual {action_key.replace('_', ' ')} for {duration_hours} hour(s)",
                "policy_version": 1,
                "evidence": evidence,
                "enforcement_rules": [],
            }
        finally:
            conn.close()

    async def persist(
        self, recommendation: dict[str, Any], *, principal: str
    ) -> dict[str, Any]:
        async with self.store.lock:
            return await asyncio.to_thread(
                self._persist_sync, dict(recommendation), principal
            )

    def _persist_sync(
        self, recommendation: dict[str, Any], principal: str
    ) -> dict[str, Any]:
        conn = self.store._connect()
        try:
            evidence = recommendation.get("evidence") or {}
            conn.execute(
                """
                INSERT INTO response_recommendations(
                    recommendation_id, actor_key, action, confidence, status,
                    created_at, updated_at, expires_at, last_seen,
                    target_type, target_value, duration_hours, summary,
                    evidence_json, policy_version, approved_at,
                    enforcement_expires_at, enforcement_rules_json,
                    enforcement_error, removal_attempts,
                    reconciliation_detail_json
                ) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', NULL, 0, '{}')
                """,
                (
                    recommendation["recommendation_id"],
                    recommendation["actor_key"],
                    recommendation["action"],
                    recommendation.get("confidence", "high"),
                    recommendation["created_at"],
                    recommendation["updated_at"],
                    recommendation["expires_at"],
                    recommendation.get("last_seen"),
                    recommendation["target_type"],
                    recommendation["target_value"],
                    int(recommendation["duration_hours"]),
                    recommendation["summary"],
                    json.dumps(evidence, separators=(",", ":"), sort_keys=True),
                    int(recommendation.get("policy_version", 1)),
                    recommendation["approved_at"],
                    recommendation["enforcement_expires_at"],
                ),
            )
            append = getattr(self.store, "_append_audit_conn", None)
            if callable(append):
                append(
                    conn,
                    recommendation_id=recommendation["recommendation_id"],
                    actor_key=recommendation["actor_key"],
                    event_type="manual_approved",
                    status="approved",
                    message=(
                        f"Manual response approved by {principal}: "
                        f"{recommendation['action']} for {recommendation['duration_hours']} hours"
                    ),
                    details={
                        "principal": principal,
                        "target_type": recommendation["target_type"],
                        "target_value": recommendation["target_value"],
                        "instance_ids": evidence.get("instance_ids", []),
                    },
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation["recommendation_id"],),
            ).fetchone()
            if row is None:
                raise RuntimeError("manual recommendation was not persisted")
            return self.store._recommendation_from_row(row)
        finally:
            conn.close()
