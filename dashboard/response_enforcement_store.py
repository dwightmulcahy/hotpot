from __future__ import annotations

import asyncio
import ipaddress
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .response_recommendations import (
    ACTION_RANK,
    ResponsePolicy,
    ThreatResponseStore,
    decide_response,
)


ENFORCEABLE_ACTIONS = {
    "recommend_challenge",
    "recommend_block",
    "recommend_long_block",
}


@dataclass(frozen=True)
class ApprovalResponsePolicy(ResponsePolicy):
    def as_dict(self) -> dict[str, Any]:
        value = super().as_dict()
        value["enforcement"] = "approval-required"
        value["automatic_enforcement"] = False
        value["approved_rules_auto_expire"] = True
        return value


class EnforcementStore(ThreatResponseStore):
    """Threat-response state with durable Cloudflare enforcement lifecycle."""

    def _initialize(self) -> None:
        super()._initialize()
        conn = self._connect()
        try:
            columns = {
                row["name"]
                for row in conn.execute(
                    "PRAGMA table_info(response_recommendations)"
                ).fetchall()
            }
            additions = {
                "approved_at": "TEXT",
                "applied_at": "TEXT",
                "removed_at": "TEXT",
                "enforcement_expires_at": "TEXT",
                "enforcement_rules_json": "TEXT NOT NULL DEFAULT '[]'",
                "enforcement_error": "TEXT",
                "removal_attempts": "INTEGER NOT NULL DEFAULT 0",
                "last_removal_attempt_at": "TEXT",
            }
            for name, sql_type in additions.items():
                if name not in columns:
                    conn.execute(
                        f"ALTER TABLE response_recommendations ADD COLUMN {name} {sql_type}"
                    )
            conn.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_response_enforcement_due
                    ON response_recommendations(status, enforcement_expires_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _recommendation_from_row(
        row: sqlite3.Row | dict[str, Any]
    ) -> dict[str, Any]:
        item = ThreatResponseStore._recommendation_from_row(row)
        raw_rules = item.pop("enforcement_rules_json", "[]")
        try:
            rules = json.loads(raw_rules)
        except (TypeError, json.JSONDecodeError):
            rules = []
        item["enforcement_rules"] = rules if isinstance(rules, list) else []
        return item

    @staticmethod
    def _ip_matches(ip: str | None, cidrs: tuple[str, ...]) -> bool:
        if not ip:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for raw in cidrs:
            try:
                if address in ipaddress.ip_network(raw, strict=False):
                    return True
            except ValueError:
                continue
        return False

    async def approve_recommendation(
        self,
        recommendation_id: str,
        policy: ResponsePolicy,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._approve_recommendation_sync,
                recommendation_id,
                policy,
                apps,
            )

    def _approve_recommendation_sync(
        self,
        recommendation_id: str,
        policy: ResponsePolicy,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        cutoff = (now - timedelta(hours=policy.active_window_hours)).isoformat()
        safety = self.safety_context_from_apps(apps)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            if row is None:
                return None
            recommendation = self._recommendation_from_row(row)
            if recommendation["status"] != "pending":
                raise ValueError("only pending recommendations can be approved")

            actor_key = str(recommendation["actor_key"])
            actor = next(
                (
                    value
                    for value in self._active_attackers_conn(conn, cutoff)
                    if str(value.get("identity_key")) == actor_key
                ),
                None,
            )
            if actor is None:
                raise ValueError("actor is no longer active enough to approve")

            decision = decide_response(actor, policy, safety, now=now)
            action = str(decision["action"])
            if action not in ENFORCEABLE_ACTIONS:
                reason = "; ".join(decision.get("safety_reasons") or [])
                detail = f": {reason}" if reason else ""
                raise ValueError(f"current policy no longer permits enforcement{detail}")
            if ACTION_RANK.get(action, 0) < ACTION_RANK["recommend_challenge"]:
                raise ValueError("current policy no longer permits enforcement")

            client_ip = decision["evidence"].get("client_ip")
            if decision["target_type"] == "ip":
                if self._ip_matches(client_ip, safety.allow_cidrs):
                    raise ValueError("target is now allowlisted")
                if self._ip_matches(client_ip, safety.trusted_proxy_cidrs):
                    raise ValueError("target is now a trusted proxy")

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
                raise ValueError("no active protected applications remain for this actor")

            evidence = dict(decision["evidence"])
            evidence["instance_ids"] = [str(value["instance_id"]) for value in app_rows]
            evidence["app_activity"] = [dict(value) for value in app_rows]
            evidence_json = json.dumps(
                evidence, separators=(",", ":"), sort_keys=True
            )
            duration_hours = max(1, int(decision["duration_hours"] or 1))
            enforcement_expires_at = (now + timedelta(hours=duration_hours)).isoformat()
            conn.execute(
                """
                UPDATE response_recommendations
                SET status = 'approved', action = ?, confidence = ?, updated_at = ?,
                    approved_at = ?, enforcement_expires_at = ?, last_seen = ?,
                    target_type = ?, target_value = ?, duration_hours = ?, summary = ?,
                    evidence_json = ?, enforcement_error = NULL,
                    enforcement_rules_json = '[]', removal_attempts = 0,
                    last_removal_attempt_at = NULL
                WHERE recommendation_id = ? AND status = 'pending'
                """,
                (
                    action,
                    decision["confidence"],
                    now_iso,
                    now_iso,
                    enforcement_expires_at,
                    evidence.get("last_seen"),
                    decision["target_type"],
                    decision["target_value"],
                    duration_hours,
                    decision["summary"],
                    evidence_json,
                    recommendation_id,
                ),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return self._recommendation_from_row(updated) if updated is not None else None
        finally:
            conn.close()

    async def approved_recommendations(self, limit: int = 20) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._approved_recommendations_sync, max(1, min(100, int(limit)))
            )

    def _approved_recommendations_sync(self, limit: int) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM response_recommendations WHERE status = 'approved' "
                "ORDER BY approved_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._recommendation_from_row(row) for row in rows]
        finally:
            conn.close()

    async def mark_applied(
        self, recommendation_id: str, rules: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._mark_applied_sync, recommendation_id, rules
            )

    def _mark_applied_sync(
        self, recommendation_id: str, rules: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                UPDATE response_recommendations
                SET status = 'applied', applied_at = ?, updated_at = ?,
                    enforcement_rules_json = ?, enforcement_error = NULL
                WHERE recommendation_id = ? AND status = 'approved'
                """,
                (
                    now,
                    now,
                    json.dumps(rules, separators=(",", ":"), sort_keys=True),
                    recommendation_id,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return self._recommendation_from_row(row) if row is not None else None
        finally:
            conn.close()

    async def mark_apply_failed(
        self, recommendation_id: str, error: str
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._mark_apply_failed_sync, recommendation_id, error
            )

    def _mark_apply_failed_sync(
        self, recommendation_id: str, error: str
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                UPDATE response_recommendations
                SET status = 'failed', updated_at = ?, enforcement_error = ?
                WHERE recommendation_id = ? AND status = 'approved'
                """,
                (now, error[:2000], recommendation_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return self._recommendation_from_row(row) if row is not None else None
        finally:
            conn.close()

    async def due_removals(self, limit: int = 100) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._due_removals_sync, max(1, min(500, int(limit)))
            )

    def _due_removals_sync(self, limit: int) -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT * FROM response_recommendations
                WHERE status = 'applied' AND enforcement_expires_at <= ?
                ORDER BY enforcement_expires_at ASC LIMIT ?
                """,
                (now, limit),
            ).fetchall()
            return [self._recommendation_from_row(row) for row in rows]
        finally:
            conn.close()

    async def mark_removal_result(
        self,
        recommendation_id: str,
        errors: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._mark_removal_result_sync, recommendation_id, errors
            )

    def _mark_removal_result_sync(
        self,
        recommendation_id: str,
        errors: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            if errors:
                conn.execute(
                    """
                    UPDATE response_recommendations
                    SET updated_at = ?, enforcement_error = ?,
                        removal_attempts = removal_attempts + 1,
                        last_removal_attempt_at = ?
                    WHERE recommendation_id = ? AND status = 'applied'
                    """,
                    (
                        now,
                        json.dumps(errors, separators=(",", ":"))[:2000],
                        now,
                        recommendation_id,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE response_recommendations
                    SET status = 'expired', updated_at = ?, removed_at = ?,
                        enforcement_error = NULL,
                        last_removal_attempt_at = ?
                    WHERE recommendation_id = ? AND status = 'applied'
                    """,
                    (now, now, now, recommendation_id),
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return self._recommendation_from_row(row) if row is not None else None
        finally:
            conn.close()

    async def enforcement_summary(self) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._enforcement_summary_sync)

    def _enforcement_summary_sync(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM response_recommendations
                WHERE status IN ('approved', 'applied', 'failed')
                GROUP BY status
                """
            ).fetchall()
            counts = {str(row["status"]): int(row["count"] or 0) for row in rows}
            overdue = conn.execute(
                """
                SELECT COUNT(*) FROM response_recommendations
                WHERE status = 'applied' AND enforcement_expires_at <= ?
                """,
                (now,),
            ).fetchone()[0]
            removal_errors = conn.execute(
                """
                SELECT COUNT(*) FROM response_recommendations
                WHERE status = 'applied' AND enforcement_error IS NOT NULL
                """
            ).fetchone()[0]
            return {
                "approved": counts.get("approved", 0),
                "applied": counts.get("applied", 0),
                "failed": counts.get("failed", 0),
                "overdue_removal": int(overdue or 0),
                "removal_errors": int(removal_errors or 0),
            }
        finally:
            conn.close()
