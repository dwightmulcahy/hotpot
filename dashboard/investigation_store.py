from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .security_store import SecureEnforcementStore


_AUDIT_KIND = {
    "recommendation_created": "recommendation",
    "dismissed": "recommendation",
    "approved": "approval",
    "applied": "enforcement",
    "apply_failed": "enforcement",
    "removal_failed": "enforcement",
    "removed": "enforcement",
    "reconciliation_issue": "enforcement",
    "reconciliation_resolved": "enforcement",
    "dashboard_dismiss": "approval",
    "dashboard_approve": "approval",
    "dashboard_remove": "approval",
}


class InvestigationStore(SecureEnforcementStore):
    """Secure enforcement state plus investigation and notification durability."""

    def _initialize(self) -> None:
        super()._initialize()
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS dashboard_notification_log (
                    event_key TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    message TEXT NOT NULL,
                    actor_key TEXT,
                    recommendation_id TEXT,
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    channels_json TEXT NOT NULL DEFAULT '[]',
                    delivery_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'recorded',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    last_attempt_at TEXT,
                    next_attempt_at TEXT,
                    sent_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_dashboard_notification_created
                    ON dashboard_notification_log(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_dashboard_notification_retry
                    ON dashboard_notification_log(status, next_attempt_at);
                CREATE INDEX IF NOT EXISTS idx_dashboard_notification_actor
                    ON dashboard_notification_log(actor_key, created_at DESC);
                """
            )
            conn.commit()
        finally:
            conn.close()

    async def attacker_timeline(
        self,
        identity_key: str,
        *,
        event_limit: int = 150,
        audit_limit: int = 100,
    ) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._attacker_timeline_sync,
                identity_key,
                max(10, min(500, int(event_limit))),
                max(10, min(500, int(audit_limit))),
            )

    def _attacker_timeline_sync(
        self, identity_key: str, event_limit: int, audit_limit: int
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            # Fetch newest retained probes but process them oldest-first so rising
            # escalation transitions can be reconstructed into the same story.
            rows = conn.execute(
                """
                SELECT instance_id, instance_name, event_id, ts, client_ip,
                       method, path, category, action, scanner, severity,
                       escalation_level, attacker_score, suppressed_before
                FROM events
                WHERE attacker_key = ?
                ORDER BY ts DESC, event_id DESC
                LIMIT ?
                """,
                (identity_key, event_limit),
            ).fetchall()
            events = [dict(row) for row in reversed(rows)]

            audit_rows = conn.execute(
                """
                SELECT audit_id, recommendation_id, actor_key, event_type, status,
                       message, details_json, created_at, principal, session_id, source
                FROM response_audit_log
                WHERE actor_key = ?
                ORDER BY created_at DESC, audit_id DESC
                LIMIT ?
                """,
                (identity_key, audit_limit),
            ).fetchall()
        finally:
            conn.close()

        timeline: list[dict[str, Any]] = []
        highest_level = 0
        for event in events:
            level = max(1, int(event.get("escalation_level", 1) or 1))
            path = str(event.get("path") or "/")
            category = str(event.get("category") or "unknown")
            action = str(event.get("action") or "")
            scanner = str(event.get("scanner") or "unknown")
            suppressed = max(0, int(event.get("suppressed_before", 0) or 0))
            detail_bits = [category]
            if action:
                detail_bits.append(action)
            if scanner and scanner != "unknown":
                detail_bits.append(scanner)
            if suppressed:
                detail_bits.append(f"{suppressed} similar request(s) suppressed before")
            timeline.append(
                {
                    "id": f"probe:{event['instance_id']}:{event['event_id']}",
                    "ts": event["ts"],
                    "kind": "probe",
                    "level": level,
                    "title": f"{event.get('method') or 'HTTP'} {path}",
                    "detail": " · ".join(detail_bits),
                    "instance_id": event.get("instance_id"),
                    "instance_name": event.get("instance_name"),
                    "path": path,
                    "category": category,
                    "action": action,
                    "scanner": scanner,
                    "severity": int(event.get("severity", 1) or 1),
                    "attacker_score": int(event.get("attacker_score", 0) or 0),
                    "suppressed_before": suppressed,
                }
            )
            if level > highest_level:
                previous = highest_level or 1
                highest_level = level
                if level >= 2:
                    timeline.append(
                        {
                            "id": f"escalation:{event['instance_id']}:{event['event_id']}:{level}",
                            "ts": event["ts"],
                            "kind": "escalation",
                            "level": level,
                            "title": f"Threat escalated to L{level}",
                            "detail": (
                                f"Escalation increased from L{previous} after {category} activity"
                            ),
                            "instance_id": event.get("instance_id"),
                            "instance_name": event.get("instance_name"),
                            "path": path,
                            "category": category,
                            "action": action,
                        }
                    )

        for row in reversed(audit_rows):
            item = dict(row)
            raw_details = item.pop("details_json", "{}")
            try:
                details = json.loads(raw_details)
            except (TypeError, json.JSONDecodeError):
                details = {}
            event_type = str(item.get("event_type") or "audit")
            kind = _AUDIT_KIND.get(event_type, "audit")
            level: int | None = None
            if event_type == "recommendation_created":
                action = str(details.get("action") or "")
                if "block" in action:
                    level = 4
                elif "challenge" in action:
                    level = 3
            timeline.append(
                {
                    "id": f"audit:{item['audit_id']}",
                    "ts": item["created_at"],
                    "kind": kind,
                    "level": level,
                    "title": str(item.get("message") or event_type.replace("_", " ")),
                    "detail": event_type.replace("_", " "),
                    "event_type": event_type,
                    "status": item.get("status"),
                    "recommendation_id": item.get("recommendation_id"),
                    "principal": item.get("principal"),
                    "session_id": item.get("session_id"),
                    "source": item.get("source") or "system",
                    "details": details if isinstance(details, dict) else {},
                }
            )

        timeline.sort(key=lambda value: (str(value.get("ts") or ""), str(value.get("id"))))
        return timeline[-300:]

    async def audit_events_after(
        self, audit_id: int, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._audit_events_after_sync,
                max(0, int(audit_id)),
                max(1, min(1000, int(limit))),
            )

    def _audit_events_after_sync(self, audit_id: int, limit: int) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT audit_id, recommendation_id, actor_key, event_type, status,
                       message, details_json, created_at, principal, session_id, source
                FROM response_audit_log
                WHERE audit_id > ?
                ORDER BY audit_id ASC
                LIMIT ?
                """,
                (audit_id, limit),
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                raw = item.pop("details_json", "{}")
                try:
                    details = json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    details = {}
                item["details"] = details if isinstance(details, dict) else {}
                result.append(item)
            return result
        finally:
            conn.close()

    async def latest_audit_id(self) -> int:
        async with self.lock:
            return await asyncio.to_thread(self._latest_audit_id_sync)

    def _latest_audit_id_sync(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COALESCE(MAX(audit_id), 0) AS audit_id FROM response_audit_log"
            ).fetchone()
            return int(row["audit_id"] or 0)
        finally:
            conn.close()

    async def observability_state(self, key: str) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(self._observability_state_sync, key)

    def _observability_state_sync(self, key: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value_json FROM response_state WHERE key = ?", (key,)
            ).fetchone()
            if row is None:
                return None
            try:
                value = json.loads(row["value_json"])
            except (TypeError, json.JSONDecodeError):
                return None
            return value if isinstance(value, dict) else None
        finally:
            conn.close()

    async def set_observability_state(self, key: str, value: dict[str, Any]) -> None:
        async with self.lock:
            await asyncio.to_thread(self._set_observability_state_sync, key, value)

    def _set_observability_state_sync(self, key: str, value: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT INTO response_state(key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (
                    key,
                    json.dumps(value, separators=(",", ":"), sort_keys=True)[:100000],
                    now,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    async def queue_notification(
        self,
        *,
        event_key: str,
        event_type: str,
        severity: str,
        subject: str,
        message: str,
        channels: list[str],
        actor_key: str | None = None,
        recommendation_id: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        async with self.lock:
            return await asyncio.to_thread(
                self._queue_notification_sync,
                event_key,
                event_type,
                severity,
                subject,
                message,
                list(channels),
                actor_key,
                recommendation_id,
                payload or {},
            )

    def _queue_notification_sync(
        self,
        event_key: str,
        event_type: str,
        severity: str,
        subject: str,
        message: str,
        channels: list[str],
        actor_key: str | None,
        recommendation_id: str | None,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        now = datetime.now(timezone.utc).isoformat()
        normalized_channels = sorted({str(value) for value in channels if str(value)})
        delivery = {channel: {"status": "pending"} for channel in normalized_channels}
        status = "pending" if normalized_channels else "recorded"
        conn = self._connect()
        try:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO dashboard_notification_log(
                    event_key, event_type, severity, subject, message,
                    actor_key, recommendation_id, payload_json, channels_json,
                    delivery_json, status, attempts, created_at, next_attempt_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    event_key[:500],
                    event_type[:100],
                    severity[:32],
                    subject[:500],
                    message[:4000],
                    actor_key,
                    recommendation_id,
                    json.dumps(payload, separators=(",", ":"), sort_keys=True)[:16000],
                    json.dumps(normalized_channels, separators=(",", ":")),
                    json.dumps(delivery, separators=(",", ":"), sort_keys=True),
                    status,
                    now,
                    now if normalized_channels else None,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM dashboard_notification_log WHERE event_key = ?",
                (event_key[:500],),
            ).fetchone()
            return self._notification_from_row(row), bool(cur.rowcount)
        finally:
            conn.close()

    @staticmethod
    def _notification_from_row(row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            return {}
        item = dict(row)
        for source_key, target_key, default in (
            ("payload_json", "payload", {}),
            ("channels_json", "channels", []),
            ("delivery_json", "delivery", {}),
        ):
            raw = item.pop(source_key, json.dumps(default))
            try:
                parsed = json.loads(raw)
            except (TypeError, json.JSONDecodeError):
                parsed = default
            item[target_key] = parsed
        return item

    async def due_notifications(
        self, now_iso: str, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._due_notifications_sync,
                now_iso,
                max(1, min(200, int(limit))),
            )

    def _due_notifications_sync(self, now_iso: str, limit: int) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM dashboard_notification_log
                WHERE status IN ('pending', 'failed')
                  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                ORDER BY created_at ASC
                LIMIT ?
                """,
                (now_iso, limit),
            ).fetchall()
            return [self._notification_from_row(row) for row in rows]
        finally:
            conn.close()

    async def mark_notification_delivery(
        self,
        event_key: str,
        outcomes: dict[str, dict[str, Any]],
        *,
        next_attempt_at: str | None,
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._mark_notification_delivery_sync,
                event_key,
                outcomes,
                next_attempt_at,
            )

    def _mark_notification_delivery_sync(
        self,
        event_key: str,
        outcomes: dict[str, dict[str, Any]],
        next_attempt_at: str | None,
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT delivery_json, channels_json FROM dashboard_notification_log WHERE event_key = ?",
                (event_key,),
            ).fetchone()
            if row is None:
                return None
            try:
                delivery = json.loads(row["delivery_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                delivery = {}
            try:
                channels = json.loads(row["channels_json"] or "[]")
            except (TypeError, json.JSONDecodeError):
                channels = []
            if not isinstance(delivery, dict):
                delivery = {}
            delivery.update(outcomes)
            pending = [
                channel
                for channel in channels
                if not isinstance(delivery.get(channel), dict)
                or delivery[channel].get("status") != "sent"
            ]
            errors = [
                str(delivery[channel].get("error") or "delivery failed")
                for channel in pending
                if isinstance(delivery.get(channel), dict)
            ]
            status = "sent" if not pending else "failed"
            sent_at = now if status == "sent" else None
            conn.execute(
                """
                UPDATE dashboard_notification_log
                SET delivery_json = ?, status = ?, attempts = attempts + 1,
                    last_error = ?, last_attempt_at = ?, next_attempt_at = ?,
                    sent_at = COALESCE(sent_at, ?)
                WHERE event_key = ?
                """,
                (
                    json.dumps(delivery, separators=(",", ":"), sort_keys=True),
                    status,
                    "; ".join(errors)[:4000] if errors else None,
                    now,
                    next_attempt_at if status != "sent" else None,
                    sent_at,
                    event_key,
                ),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM dashboard_notification_log WHERE event_key = ?",
                (event_key,),
            ).fetchone()
            return self._notification_from_row(updated)
        finally:
            conn.close()

    async def recent_notifications(self, *, limit: int = 50) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._recent_notifications_sync, max(1, min(200, int(limit)))
            )

    def _recent_notifications_sync(self, limit: int) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM dashboard_notification_log "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._notification_from_row(row) for row in rows]
        finally:
            conn.close()
