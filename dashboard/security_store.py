from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from .response_enforcement_store import EnforcementStore


class SecureEnforcementStore(EnforcementStore):
    """Enforcement store extended with dashboard principal/session attribution."""

    def _initialize(self) -> None:
        super()._initialize()
        conn = self._connect()
        try:
            columns = {
                row["name"]
                for row in conn.execute(
                    "PRAGMA table_info(response_audit_log)"
                ).fetchall()
            }
            additions = {
                "principal": "TEXT",
                "session_id": "TEXT",
                "source": "TEXT NOT NULL DEFAULT 'system'",
            }
            for name, sql_type in additions.items():
                if name not in columns:
                    conn.execute(
                        f"ALTER TABLE response_audit_log ADD COLUMN {name} {sql_type}"
                    )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_response_audit_principal "
                "ON response_audit_log(principal, created_at DESC)"
            )
            conn.commit()
        finally:
            conn.close()

    async def record_dashboard_action(
        self,
        *,
        event_type: str,
        message: str,
        principal: str,
        session_id: str | None,
        recommendation_id: str | None = None,
        actor_key: str | None = None,
        status: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        async with self.lock:
            await asyncio.to_thread(
                self._record_dashboard_action_sync,
                event_type,
                message,
                principal,
                session_id,
                recommendation_id,
                actor_key,
                status,
                details or {},
            )

    def _record_dashboard_action_sync(
        self,
        event_type: str,
        message: str,
        principal: str,
        session_id: str | None,
        recommendation_id: str | None,
        actor_key: str | None,
        status: str | None,
        details: dict[str, Any],
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            if recommendation_id and (actor_key is None or status is None):
                row = conn.execute(
                    "SELECT actor_key, status FROM response_recommendations "
                    "WHERE recommendation_id = ?",
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
                    message, details_json, created_at, principal, session_id, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'dashboard')
                """,
                (
                    recommendation_id,
                    actor_key,
                    event_type,
                    status,
                    message[:1000],
                    json.dumps(details, separators=(",", ":"), sort_keys=True)[:8000],
                    now,
                    principal[:200],
                    (session_id or "")[:200] or None,
                ),
            )
            conn.commit()
        finally:
            conn.close()
