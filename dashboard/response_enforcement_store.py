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
                "reconciliation_status": "TEXT",
                "reconciliation_detail_json": "TEXT NOT NULL DEFAULT '{}'",
                "last_reconciled_at": "TEXT",
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
                CREATE INDEX IF NOT EXISTS idx_response_reconciliation
                    ON response_recommendations(status, reconciliation_status);

                CREATE TABLE IF NOT EXISTS response_audit_log (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recommendation_id TEXT,
                    actor_key TEXT,
                    event_type TEXT NOT NULL,
                    status TEXT,
                    message TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_response_audit_created
                    ON response_audit_log(created_at DESC, audit_id DESC);
                CREATE INDEX IF NOT EXISTS idx_response_audit_recommendation
                    ON response_audit_log(recommendation_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS response_state (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
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
        raw_reconciliation = item.pop("reconciliation_detail_json", "{}")
        try:
            reconciliation = json.loads(raw_reconciliation)
        except (TypeError, json.JSONDecodeError):
            reconciliation = {}
        item["reconciliation"] = (
            reconciliation if isinstance(reconciliation, dict) else {}
        )
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

    @staticmethod
    def _append_audit_conn(
        conn: sqlite3.Connection,
        *,
        event_type: str,
        message: str,
        recommendation_id: str | None = None,
        actor_key: str | None = None,
        status: str | None = None,
        details: dict[str, Any] | None = None,
        created_at: str | None = None,
    ) -> None:
        if recommendation_id and (actor_key is None or status is None):
            row = conn.execute(
                "SELECT actor_key, status FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            if row is not None:
                if actor_key is None:
                    actor_key = str(row["actor_key"] or "") or None
                if status is None:
                    status = str(row["status"] or "") or None
        conn.execute(
            """
            INSERT INTO response_audit_log(
                recommendation_id, actor_key, event_type, status,
                message, details_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                recommendation_id,
                actor_key,
                event_type,
                status,
                message[:1000],
                json.dumps(details or {}, separators=(",", ":"), sort_keys=True)[
                    :8000
                ],
                created_at or datetime.now(timezone.utc).isoformat(),
            ),
        )

    def _sync_response_recommendations_sync(
        self,
        policy: ResponsePolicy,
        apps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        # Track IDs so the durable audit log records only genuinely new pending
        # recommendations, not each 15-second refresh of an existing one.
        before_conn = self._connect()
        try:
            before_ids = {
                str(row["recommendation_id"])
                for row in before_conn.execute(
                    "SELECT recommendation_id FROM response_recommendations"
                ).fetchall()
            }
        finally:
            before_conn.close()

        # Let the recommendation engine evaluate current activity first, then remove
        # any fresh duplicate pending recommendation for an actor whose explicitly
        # approved Cloudflare action is still being applied or is already active.
        super()._sync_response_recommendations_sync(policy, apps)
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            conn.execute(
                """
                UPDATE response_recommendations AS pending
                SET status = 'expired', updated_at = ?
                WHERE pending.status = 'pending'
                  AND EXISTS (
                      SELECT 1 FROM response_recommendations AS active
                      WHERE active.actor_key = pending.actor_key
                        AND active.recommendation_id != pending.recommendation_id
                        AND active.status IN ('approved', 'applied')
                  )
                """,
                (now_iso,),
            )
            new_rows = conn.execute(
                "SELECT recommendation_id, actor_key, action, status FROM response_recommendations WHERE status = 'pending'"
            ).fetchall()
            for row in new_rows:
                recommendation_id = str(row["recommendation_id"])
                if recommendation_id in before_ids:
                    continue
                self._append_audit_conn(
                    conn,
                    recommendation_id=recommendation_id,
                    actor_key=str(row["actor_key"] or "") or None,
                    event_type="recommendation_created",
                    status="pending",
                    message=f"Response recommendation created: {row['action']}",
                    created_at=now_iso,
                )
            conn.commit()
            return self._response_snapshot_conn(conn, policy)
        finally:
            conn.close()

    def _dismiss_recommendation_sync(
        self, recommendation_id: str, dismiss_hours: int
    ) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            previous_status = str(row["status"]) if row is not None else None
        finally:
            conn.close()
        result = super()._dismiss_recommendation_sync(
            recommendation_id, dismiss_hours
        )
        if result is not None and previous_status == "pending" and result.get("status") == "dismissed":
            conn = self._connect()
            try:
                self._append_audit_conn(
                    conn,
                    recommendation_id=recommendation_id,
                    event_type="dismissed",
                    status="dismissed",
                    message=f"Recommendation dismissed for {max(1, int(dismiss_hours))} hours",
                )
                conn.commit()
            finally:
                conn.close()
        return result

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
                raise ValueError(
                    f"current policy no longer permits enforcement{detail}"
                )
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
                raise ValueError(
                    "no active protected applications remain for this actor"
                )

            evidence = dict(decision["evidence"])
            evidence["instance_ids"] = [
                str(value["instance_id"]) for value in app_rows
            ]
            evidence["app_activity"] = [dict(value) for value in app_rows]
            evidence_json = json.dumps(
                evidence, separators=(",", ":"), sort_keys=True
            )
            duration_hours = max(1, int(decision["duration_hours"] or 1))
            enforcement_expires_at = (
                now + timedelta(hours=duration_hours)
            ).isoformat()
            conn.execute(
                """
                UPDATE response_recommendations
                SET status = 'approved', action = ?, confidence = ?, updated_at = ?,
                    approved_at = ?, enforcement_expires_at = ?, last_seen = ?,
                    target_type = ?, target_value = ?, duration_hours = ?, summary = ?,
                    evidence_json = ?, enforcement_error = NULL,
                    enforcement_rules_json = '[]', removal_attempts = 0,
                    last_removal_attempt_at = NULL, reconciliation_status = NULL,
                    reconciliation_detail_json = '{}', last_reconciled_at = NULL
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
            self._append_audit_conn(
                conn,
                recommendation_id=recommendation_id,
                actor_key=actor_key,
                event_type="approved",
                status="approved",
                message=f"Approved {action} for {duration_hours} hours",
                details={
                    "action": action,
                    "duration_hours": duration_hours,
                    "target_type": decision["target_type"],
                    "target_value": decision["target_value"],
                    "instance_ids": evidence["instance_ids"],
                    "enforcement_expires_at": enforcement_expires_at,
                },
                created_at=now_iso,
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return (
                self._recommendation_from_row(updated)
                if updated is not None
                else None
            )
        finally:
            conn.close()

    async def approved_recommendations(
        self, limit: int = 20
    ) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._approved_recommendations_sync,
                max(1, min(100, int(limit))),
            )

    def _approved_recommendations_sync(
        self, limit: int
    ) -> list[dict[str, Any]]:
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
                    enforcement_rules_json = ?, enforcement_error = NULL,
                    reconciliation_status = NULL,
                    reconciliation_detail_json = '{}', last_reconciled_at = NULL
                WHERE recommendation_id = ? AND status = 'approved'
                """,
                (
                    now,
                    now,
                    json.dumps(rules, separators=(",", ":"), sort_keys=True),
                    recommendation_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            if row is not None and str(row["status"]) == "applied":
                self._append_audit_conn(
                    conn,
                    recommendation_id=recommendation_id,
                    event_type="applied",
                    status="applied",
                    message=f"Cloudflare enforcement applied with {len(rules)} rule(s)",
                    details={
                        "rules": [
                            {
                                "zone_id": rule.get("zone_id"),
                                "ruleset_id": rule.get("ruleset_id"),
                                "rule_id": rule.get("rule_id"),
                                "ref": rule.get("ref"),
                                "action": rule.get("action"),
                                "hosts": rule.get("hosts"),
                            }
                            for rule in rules
                        ]
                    },
                    created_at=now,
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
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            if row is not None and str(row["status"]) == "failed":
                self._append_audit_conn(
                    conn,
                    recommendation_id=recommendation_id,
                    event_type="apply_failed",
                    status="failed",
                    message="Cloudflare enforcement apply failed",
                    details={"error": error[:2000]},
                    created_at=now,
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
        *,
        reason: str = "automatic_expiry",
    ) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(
                self._mark_removal_result_sync,
                recommendation_id,
                errors,
                reason,
            )

    def _mark_removal_result_sync(
        self,
        recommendation_id: str,
        errors: list[dict[str, Any]],
        reason: str,
    ) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            previous = conn.execute(
                "SELECT enforcement_error FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            previous_error = str(previous["enforcement_error"] or "") if previous else ""
            if errors:
                error_text = json.dumps(errors, separators=(",", ":"))[:2000]
                conn.execute(
                    """
                    UPDATE response_recommendations
                    SET updated_at = ?, enforcement_error = ?,
                        removal_attempts = removal_attempts + 1,
                        last_removal_attempt_at = ?
                    WHERE recommendation_id = ? AND status = 'applied'
                    """,
                    (now, error_text, now, recommendation_id),
                )
                if error_text != previous_error:
                    self._append_audit_conn(
                        conn,
                        recommendation_id=recommendation_id,
                        event_type="removal_failed",
                        status="applied",
                        message="Cloudflare rule removal failed; Hotpot will retry",
                        details={"reason": reason, "errors": errors},
                        created_at=now,
                    )
            else:
                conn.execute(
                    """
                    UPDATE response_recommendations
                    SET status = 'expired', updated_at = ?, removed_at = ?,
                        enforcement_error = NULL,
                        last_removal_attempt_at = ?, reconciliation_status = NULL,
                        reconciliation_detail_json = '{}', last_reconciled_at = NULL
                    WHERE recommendation_id = ? AND status = 'applied'
                    """,
                    (now, now, now, recommendation_id),
                )
                self._append_audit_conn(
                    conn,
                    recommendation_id=recommendation_id,
                    event_type="removed",
                    status="expired",
                    message=(
                        "Cloudflare enforcement removed manually"
                        if reason == "manual_remove"
                        else "Cloudflare enforcement removed at expiry"
                    ),
                    details={"reason": reason},
                    created_at=now,
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM response_recommendations WHERE recommendation_id = ?",
                (recommendation_id,),
            ).fetchone()
            return self._recommendation_from_row(row) if row is not None else None
        finally:
            conn.close()

    async def record_reconciliation(self, report: dict[str, Any]) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._record_reconciliation_sync, report)

    def _record_reconciliation_sync(self, report: dict[str, Any]) -> dict[str, Any]:
        checked_at = str(report.get("checked_at") or datetime.now(timezone.utc).isoformat())
        conn = self._connect()
        try:
            for result in report.get("recommendations") or []:
                if not isinstance(result, dict):
                    continue
                recommendation_id = str(result.get("recommendation_id") or "")
                if not recommendation_id:
                    continue
                current = conn.execute(
                    "SELECT reconciliation_status FROM response_recommendations WHERE recommendation_id = ? AND status = 'applied'",
                    (recommendation_id,),
                ).fetchone()
                if current is None:
                    continue
                previous_status = str(current["reconciliation_status"] or "") or None
                new_status = str(result.get("status") or "error")
                conn.execute(
                    """
                    UPDATE response_recommendations
                    SET reconciliation_status = ?, reconciliation_detail_json = ?,
                        last_reconciled_at = ?
                    WHERE recommendation_id = ? AND status = 'applied'
                    """,
                    (
                        new_status,
                        json.dumps(result, separators=(",", ":"), sort_keys=True)[:12000],
                        checked_at,
                        recommendation_id,
                    ),
                )
                if previous_status == new_status:
                    continue
                if new_status == "healthy":
                    if previous_status and previous_status != "healthy":
                        self._append_audit_conn(
                            conn,
                            recommendation_id=recommendation_id,
                            event_type="reconciliation_resolved",
                            status="applied",
                            message="Cloudflare rule reconciliation returned to healthy",
                            details={"previous_status": previous_status},
                            created_at=checked_at,
                        )
                else:
                    self._append_audit_conn(
                        conn,
                        recommendation_id=recommendation_id,
                        event_type="reconciliation_issue",
                        status="applied",
                        message=f"Cloudflare reconciliation detected {new_status} enforcement",
                        details={
                            "previous_status": previous_status,
                            "reconciliation": result,
                        },
                        created_at=checked_at,
                    )

            previous_state = conn.execute(
                "SELECT value_json FROM response_state WHERE key = 'cloudflare_reconciliation'"
            ).fetchone()
            previous_report: dict[str, Any] = {}
            if previous_state is not None:
                try:
                    parsed = json.loads(previous_state["value_json"])
                    if isinstance(parsed, dict):
                        previous_report = parsed
                except (TypeError, json.JSONDecodeError):
                    pass
            old_orphans = {
                str(item.get("zone_id")) + ":" + str(item.get("ref"))
                for item in previous_report.get("orphans") or []
                if isinstance(item, dict)
            }
            new_orphans = {
                str(item.get("zone_id")) + ":" + str(item.get("ref"))
                for item in report.get("orphans") or []
                if isinstance(item, dict)
            }
            orphan_by_key = {
                str(item.get("zone_id")) + ":" + str(item.get("ref")): item
                for item in report.get("orphans") or []
                if isinstance(item, dict)
            }
            for key in sorted(new_orphans - old_orphans):
                item = orphan_by_key[key]
                self._append_audit_conn(
                    conn,
                    event_type="orphan_detected",
                    status="drifted",
                    message="Orphaned Hotpot Cloudflare rule detected",
                    details=item,
                    created_at=checked_at,
                )
            for key in sorted(old_orphans - new_orphans):
                self._append_audit_conn(
                    conn,
                    event_type="orphan_resolved",
                    status="healthy",
                    message="Previously orphaned Hotpot Cloudflare rule is no longer present",
                    details={"key": key},
                    created_at=checked_at,
                )

            conn.execute(
                """
                INSERT INTO response_state(key, value_json, updated_at)
                VALUES ('cloudflare_reconciliation', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (
                    json.dumps(report, separators=(",", ":"), sort_keys=True)[:100000],
                    checked_at,
                ),
            )
            conn.commit()
            return report
        finally:
            conn.close()

    async def latest_reconciliation(self) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._latest_reconciliation_sync)

    def _latest_reconciliation_sync(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value_json FROM response_state WHERE key = 'cloudflare_reconciliation'"
            ).fetchone()
            if row is None:
                return {}
            try:
                value = json.loads(row["value_json"])
            except (TypeError, json.JSONDecodeError):
                return {}
            return value if isinstance(value, dict) else {}
        finally:
            conn.close()

    async def audit_log(
        self, *, limit: int = 100, recommendation_id: str | None = None
    ) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(
                self._audit_log_sync,
                max(1, min(500, int(limit))),
                recommendation_id,
            )

    def _audit_log_sync(
        self, limit: int, recommendation_id: str | None
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            if recommendation_id:
                rows = conn.execute(
                    """
                    SELECT * FROM response_audit_log
                    WHERE recommendation_id = ?
                    ORDER BY created_at DESC, audit_id DESC LIMIT ?
                    """,
                    (recommendation_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM response_audit_log ORDER BY created_at DESC, audit_id DESC LIMIT ?",
                    (limit,),
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

    async def storage_self_check(self) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._storage_self_check_sync)

    def _storage_self_check_sync(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            quick = str(conn.execute("PRAGMA quick_check(1)").fetchone()[0])
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO response_state(key, value_json, updated_at)
                VALUES ('system_check_probe', '{}', ?)
                ON CONFLICT(key) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (datetime.now(timezone.utc).isoformat(),),
            )
            conn.rollback()
            return {"writable": True, "quick_check": quick, "path": str(self.path)}
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
            counts = {
                str(row["status"]): int(row["count"] or 0) for row in rows
            }
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
            reconciliation_rows = conn.execute(
                """
                SELECT reconciliation_status, COUNT(*) AS count
                FROM response_recommendations
                WHERE status = 'applied' AND reconciliation_status IS NOT NULL
                GROUP BY reconciliation_status
                """
            ).fetchall()
            reconciliation_counts = {
                str(row["reconciliation_status"]): int(row["count"] or 0)
                for row in reconciliation_rows
            }
            state = conn.execute(
                "SELECT value_json FROM response_state WHERE key = 'cloudflare_reconciliation'"
            ).fetchone()
            orphaned = 0
            last_reconciled_at = None
            if state is not None:
                try:
                    latest = json.loads(state["value_json"])
                    if isinstance(latest, dict):
                        orphaned = int(latest.get("orphaned", 0) or 0)
                        last_reconciled_at = latest.get("checked_at")
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
            return {
                "approved": counts.get("approved", 0),
                "applied": counts.get("applied", 0),
                "failed": counts.get("failed", 0),
                "overdue_removal": int(overdue or 0),
                "removal_errors": int(removal_errors or 0),
                "reconciliation_healthy": reconciliation_counts.get("healthy", 0),
                "reconciliation_drifted": reconciliation_counts.get("drifted", 0),
                "reconciliation_missing": reconciliation_counts.get("missing", 0),
                "reconciliation_errors": reconciliation_counts.get("error", 0),
                "orphaned_rules": orphaned,
                "last_reconciled_at": last_reconciled_at,
            }
        finally:
            conn.close()
