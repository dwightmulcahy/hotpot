from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from aiohttp import ClientSession

from .runtime import Instance


POLICY_SCHEMA_VERSION = 1
POLICY_KINDS = {"allow_cidr", "suppress_actor", "suppress_scanner", "exclude_category"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR: {value}") from exc
    if network.prefixlen == 0:
        raise ValueError("default-route CIDRs (0.0.0.0/0 and ::/0) are prohibited")
    return network.with_prefixlen


def _canonical_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=lambda item: str(item.get("policy_id") or ""))


def _revision(instance_id: str, entries: list[dict[str, Any]]) -> str:
    canonical = json.dumps(
        {
            "schema_version": POLICY_SCHEMA_VERSION,
            "instance_id": instance_id,
            "entries": _canonical_entries(entries),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class PolicyManager:
    """Durable dashboard policy source of truth and per-instance reconciler."""

    def __init__(self, data_dir: Path, instances: list[Instance]) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "dashboard.sqlite3"
        self.instances = {instance.instance_id: instance for instance in instances}
        self.lock = asyncio.Lock()
        self.reconcile_seconds = max(
            30, int(os.getenv("HOTPOT_DASHBOARD_POLICY_RECONCILE_SECONDS", "60"))
        )
        self._last_reconcile = 0.0
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS policies (
                    policy_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    app_ids_json TEXT NOT NULL DEFAULT '[]',
                    reason TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    disabled_by TEXT,
                    disabled_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_policies_active
                    ON policies(enabled, expires_at, kind);

                CREATE TABLE IF NOT EXISTS policy_sync (
                    instance_id TEXT PRIMARY KEY,
                    desired_revision TEXT,
                    applied_revision TEXT,
                    last_attempt_at TEXT,
                    last_success_at TEXT,
                    last_error TEXT
                );

                CREATE TABLE IF NOT EXISTS policy_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id TEXT,
                    event_type TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    message TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_policy_audit_created
                    ON policy_audit(created_at DESC, audit_id DESC);
                """
            )

    def _validate_apps(self, values: Any) -> list[str]:
        if values in (None, ""):
            return []
        if not isinstance(values, list):
            raise ValueError("app_ids must be a JSON list")
        result = sorted({str(value).strip() for value in values if str(value).strip()})
        unknown = [value for value in result if value not in self.instances]
        if unknown:
            raise ValueError("unknown application ids: " + ", ".join(unknown))
        return result

    def validate_policy(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("policy body must be a JSON object")
        kind = str(payload.get("kind") or "").strip()
        value = str(payload.get("value") or "").strip()
        if kind not in POLICY_KINDS:
            raise ValueError(f"unsupported policy kind: {kind}")
        if not value:
            raise ValueError("value is required")
        if kind == "allow_cidr":
            value = _normalize_cidr(value)
        elif len(value) > 512:
            raise ValueError("policy value is too long")
        expires_at = str(payload.get("expires_at") or "").strip() or None
        if expires_at and _parse_time(expires_at) is None:
            raise ValueError("expires_at must be an ISO-8601 timestamp")
        if expires_at and _parse_time(expires_at) <= _utcnow():
            raise ValueError("expires_at must be in the future")
        reason = str(payload.get("reason") or "").strip()
        if not reason:
            raise ValueError("reason is required")
        return {
            "kind": kind,
            "value": value,
            "app_ids": self._validate_apps(payload.get("app_ids")),
            "reason": reason[:500],
            "notes": str(payload.get("notes") or "").strip()[:2000],
            "expires_at": expires_at,
        }

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        try:
            item["app_ids"] = json.loads(item.pop("app_ids_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            item["app_ids"] = []
            item.pop("app_ids_json", None)
        item["enabled"] = bool(item.get("enabled"))
        return item

    @staticmethod
    def _is_active(item: dict[str, Any], now: datetime) -> bool:
        if not item.get("enabled"):
            return False
        expires = _parse_time(item.get("expires_at"))
        return expires is None or expires > now

    async def create(self, payload: Any, *, principal: str) -> dict[str, Any]:
        validated = self.validate_policy(payload)
        async with self.lock:
            return await asyncio.to_thread(self._create_sync, validated, principal)

    def _create_sync(self, policy: dict[str, Any], principal: str) -> dict[str, Any]:
        now = _utcnow().isoformat()
        policy_id = "policy_" + uuid.uuid4().hex
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO policies(
                    policy_id, kind, value, app_ids_json, reason, notes,
                    created_by, created_at, expires_at, enabled
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    policy_id,
                    policy["kind"],
                    policy["value"],
                    json.dumps(policy["app_ids"], separators=(",", ":")),
                    policy["reason"],
                    policy["notes"],
                    principal,
                    now,
                    policy["expires_at"],
                ),
            )
            self._audit_conn(
                conn,
                policy_id=policy_id,
                event_type="created",
                principal=principal,
                message=f"Created {policy['kind']} policy",
                details=policy,
            )
            row = conn.execute("SELECT * FROM policies WHERE policy_id = ?", (policy_id,)).fetchone()
            assert row is not None
            return self._row(row)

    async def disable(self, policy_id: str, *, principal: str) -> dict[str, Any] | None:
        async with self.lock:
            return await asyncio.to_thread(self._disable_sync, policy_id, principal)

    def _disable_sync(self, policy_id: str, principal: str) -> dict[str, Any] | None:
        now = _utcnow().isoformat()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM policies WHERE policy_id = ?", (policy_id,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE policies SET enabled = 0, disabled_by = ?, disabled_at = ? WHERE policy_id = ?",
                (principal, now, policy_id),
            )
            self._audit_conn(
                conn,
                policy_id=policy_id,
                event_type="disabled",
                principal=principal,
                message="Disabled policy",
                details={"previous": self._row(row)},
            )
            updated = conn.execute("SELECT * FROM policies WHERE policy_id = ?", (policy_id,)).fetchone()
            return self._row(updated) if updated is not None else None

    def _audit_conn(
        self,
        conn: sqlite3.Connection,
        *,
        policy_id: str | None,
        event_type: str,
        principal: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO policy_audit(policy_id, event_type, principal, message, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                policy_id,
                event_type,
                principal,
                message[:1000],
                json.dumps(details or {}, separators=(",", ":"), sort_keys=True)[:12000],
                _utcnow().isoformat(),
            ),
        )

    async def list(self, *, include_inactive: bool = True) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(self._list_sync, include_inactive)

    def _list_sync(self, include_inactive: bool) -> list[dict[str, Any]]:
        with self._connect() as conn:
            if include_inactive:
                rows = conn.execute("SELECT * FROM policies ORDER BY created_at DESC").fetchall()
            else:
                rows = conn.execute("SELECT * FROM policies WHERE enabled = 1 ORDER BY created_at DESC").fetchall()
        return [self._row(row) for row in rows]

    async def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        async with self.lock:
            return await asyncio.to_thread(self._audit_sync, limit)

    def _audit_sync(self, limit: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM policy_audit ORDER BY audit_id DESC LIMIT ?",
                (max(1, min(500, int(limit))),),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                item["details"] = {}
                item.pop("details_json", None)
            result.append(item)
        return result

    async def active_for_instance(self, instance_id: str) -> list[dict[str, Any]]:
        policies = await self.list(include_inactive=False)
        now = _utcnow()
        return [
            item
            for item in policies
            if self._is_active(item, now)
            and (not item.get("app_ids") or instance_id in item.get("app_ids", []))
        ]

    async def snapshot_for(self, instance_id: str) -> dict[str, Any]:
        active = await self.active_for_instance(instance_id)
        entries = [
            {
                "policy_id": item["policy_id"],
                "kind": item["kind"],
                "value": item["value"],
                "reason": item.get("reason") or "",
                "notes": item.get("notes") or "",
                "created_by": item.get("created_by") or "",
                "created_at": item.get("created_at"),
                "expires_at": item.get("expires_at"),
            }
            for item in active
        ]
        entries = _canonical_entries(entries)
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "instance_id": instance_id,
            "revision": _revision(instance_id, entries),
            "updated_at": _utcnow().isoformat(),
            "entries": entries,
        }

    async def effective_allow_cidrs(self, instance_id: str) -> list[str]:
        return [
            str(item["value"])
            for item in await self.active_for_instance(instance_id)
            if item.get("kind") == "allow_cidr"
        ]

    async def suppression_for_actor(self, actor_key: str) -> dict[str, Any] | None:
        now = _utcnow()
        for item in await self.list(include_inactive=False):
            if (
                self._is_active(item, now)
                and item.get("kind") == "suppress_actor"
                and item.get("value") == actor_key
            ):
                return item
        return None

    async def preview(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("preview body must be a JSON object")
        app_id = str(payload.get("app_id") or "").strip()
        if app_id and app_id not in self.instances:
            raise ValueError("unknown app_id")
        client_ip = str(payload.get("client_ip") or "").strip()
        actor_key = str(payload.get("actor_key") or client_ip).strip()
        scanner = str(payload.get("scanner_family") or "").strip()
        category = str(payload.get("category") or "").strip()
        matches: list[dict[str, Any]] = []
        policies = await (self.active_for_instance(app_id) if app_id else self.list(include_inactive=False))
        now = _utcnow()
        for item in policies:
            if not self._is_active(item, now):
                continue
            kind = item.get("kind")
            matched = False
            if kind == "allow_cidr" and client_ip:
                try:
                    matched = ipaddress.ip_address(client_ip) in ipaddress.ip_network(item["value"], strict=False)
                except ValueError:
                    matched = False
            elif kind == "suppress_actor":
                matched = actor_key == item.get("value")
            elif kind == "suppress_scanner":
                matched = scanner == item.get("value")
            elif kind == "exclude_category":
                matched = category == item.get("value")
            if matched:
                matches.append(item)
        impacts = []
        if any(item.get("kind") == "allow_cidr" for item in matches):
            impacts.append("bypass_deception")
        if any(item.get("kind") in {"suppress_actor", "suppress_scanner", "exclude_category"} for item in matches):
            impacts.extend(["suppress_notifications", "suppress_response_approval"])
        return {"matched": bool(matches), "matches": matches, "impacts": sorted(set(impacts))}

    async def reconcile(
        self,
        client: ClientSession,
        *,
        token: str,
        force: bool = False,
    ) -> dict[str, Any]:
        now_mono = time.monotonic()
        if not force and self._last_reconcile and now_mono - self._last_reconcile < self.reconcile_seconds:
            return await self.sync_status()
        self._last_reconcile = now_mono
        results = []
        for instance in self.instances.values():
            desired = await self.snapshot_for(instance.instance_id)
            desired_revision = desired["revision"]
            applied_revision = None
            error = None
            attempted_at = _utcnow().isoformat()
            try:
                headers = {"Authorization": f"Bearer {token}"}
                async with client.get(
                    f"{instance.url}/_hotpot/api/policy", headers=headers
                ) as response:
                    if response.status != 200:
                        raise RuntimeError(f"policy read returned HTTP {response.status}")
                    remote = await response.json()
                applied_revision = str(remote.get("revision") or "")
                if force or applied_revision != desired_revision:
                    put_headers = {
                        **headers,
                        "Content-Type": "application/json",
                        "X-Hotpot-Action": "policy-sync",
                    }
                    async with client.put(
                        f"{instance.url}/_hotpot/api/policy",
                        headers=put_headers,
                        json=desired,
                    ) as response:
                        body = await response.json(content_type=None)
                        if response.status != 200:
                            detail = body.get("error") if isinstance(body, dict) else None
                            raise RuntimeError(detail or f"policy write returned HTTP {response.status}")
                        policy = body.get("policy", {}) if isinstance(body, dict) else {}
                        applied_revision = str(policy.get("revision") or "")
                if applied_revision != desired_revision:
                    raise RuntimeError("remote policy revision did not converge")
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
            await asyncio.to_thread(
                self._record_sync_result,
                instance.instance_id,
                desired_revision,
                applied_revision,
                attempted_at,
                error,
            )
            results.append(
                {
                    "instance_id": instance.instance_id,
                    "name": instance.name,
                    "desired_revision": desired_revision,
                    "applied_revision": applied_revision,
                    "in_sync": error is None and applied_revision == desired_revision,
                    "error": error,
                }
            )
        return {
            "reconciled_at": _utcnow().isoformat(),
            "instances": results,
            "in_sync": all(item["in_sync"] for item in results),
        }

    def _record_sync_result(
        self,
        instance_id: str,
        desired_revision: str,
        applied_revision: str | None,
        attempted_at: str,
        error: str | None,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO policy_sync(
                    instance_id, desired_revision, applied_revision,
                    last_attempt_at, last_success_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(instance_id) DO UPDATE SET
                    desired_revision=excluded.desired_revision,
                    applied_revision=excluded.applied_revision,
                    last_attempt_at=excluded.last_attempt_at,
                    last_success_at=CASE WHEN excluded.last_error IS NULL THEN excluded.last_attempt_at ELSE policy_sync.last_success_at END,
                    last_error=excluded.last_error
                """,
                (
                    instance_id,
                    desired_revision,
                    applied_revision,
                    attempted_at,
                    attempted_at if error is None else None,
                    error,
                ),
            )

    async def sync_status(self) -> dict[str, Any]:
        async with self.lock:
            return await asyncio.to_thread(self._sync_status_sync)

    def _sync_status_sync(self) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM policy_sync ORDER BY instance_id").fetchall()
        values = [dict(row) for row in rows]
        return {
            "instances": [
                {
                    **item,
                    "in_sync": bool(item.get("desired_revision"))
                    and item.get("desired_revision") == item.get("applied_revision")
                    and not item.get("last_error"),
                }
                for item in values
            ],
            "in_sync": bool(values)
            and all(
                item.get("desired_revision") == item.get("applied_revision")
                and not item.get("last_error")
                for item in values
            ),
        }
