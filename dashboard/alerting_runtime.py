from __future__ import annotations

from typing import Any

from aiohttp import ClientSession

from .investigation_store import InvestigationStore
from .notifications import NotificationCenter
from .response_recommendations import ResponsePolicy


class AlertingInvestigationStore(InvestigationStore):
    """Add durable audit markers when a pending recommendation materially changes."""

    def _pending_actions(self) -> dict[str, dict[str, str]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT recommendation_id, actor_key, action, confidence
                FROM response_recommendations
                WHERE status = 'pending'
                """
            ).fetchall()
            return {
                str(row["recommendation_id"]): {
                    "actor_key": str(row["actor_key"] or ""),
                    "action": str(row["action"] or ""),
                    "confidence": str(row["confidence"] or ""),
                }
                for row in rows
            }
        finally:
            conn.close()

    def _sync_response_recommendations_sync(
        self,
        policy: ResponsePolicy,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        before = self._pending_actions()
        result = super()._sync_response_recommendations_sync(policy, apps)
        after = self._pending_actions()
        changed = [
            recommendation_id
            for recommendation_id in before.keys() & after.keys()
            if before[recommendation_id]["action"] != after[recommendation_id]["action"]
            or before[recommendation_id]["confidence"]
            != after[recommendation_id]["confidence"]
        ]
        if not changed:
            return result

        conn = self._connect()
        try:
            for recommendation_id in changed:
                old = before[recommendation_id]
                new = after[recommendation_id]
                self._append_audit_conn(
                    conn,
                    recommendation_id=recommendation_id,
                    actor_key=new["actor_key"] or None,
                    event_type="recommendation_changed",
                    status="pending",
                    message=(
                        "Response recommendation changed: "
                        f"{old['action']} ({old['confidence']}) -> "
                        f"{new['action']} ({new['confidence']})"
                    ),
                    details={
                        "from_action": old["action"],
                        "from_confidence": old["confidence"],
                        "action": new["action"],
                        "confidence": new["confidence"],
                    },
                )
            conn.commit()
        finally:
            conn.close()
        return result

    async def attacker_timeline(
        self,
        identity_key: str,
        *,
        event_limit: int = 150,
        audit_limit: int = 100,
    ) -> list[dict[str, Any]]:
        timeline = await super().attacker_timeline(
            identity_key, event_limit=event_limit, audit_limit=audit_limit
        )
        for item in timeline:
            if item.get("event_type") != "recommendation_changed":
                continue
            item["kind"] = "recommendation"
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            action = str((details or {}).get("action") or "")
            if "block" in action:
                item["level"] = 4
            elif "challenge" in action:
                item["level"] = 3
        return timeline


class AlertNotificationCenter(NotificationCenter):
    """Notification runtime with escalation awareness and an immediate kill switch."""

    async def _candidate_from_audit(
        self, audit: dict[str, Any]
    ) -> dict[str, Any] | None:
        if str(audit.get("event_type") or "") == "recommendation_changed":
            audit = dict(audit)
            audit["event_type"] = "recommendation_created"
        return await super()._candidate_from_audit(audit)

    async def deliver_due(self, client: ClientSession) -> int:
        # Turning delivery off must stop both new sends and retries of previously
        # queued failures. Local notification recording continues normally.
        if not self.config.enabled:
            return 0
        return await super().deliver_due(client)
