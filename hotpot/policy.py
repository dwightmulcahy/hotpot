from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def normalize_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid CIDR: {value}") from exc
    if network.prefixlen == 0:
        raise ValueError("default-route CIDRs (0.0.0.0/0 and ::/0) are prohibited")
    return network.with_prefixlen


def _canonical_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=lambda item: str(item.get("policy_id") or ""))


def snapshot_revision(instance_id: str, entries: list[dict[str, Any]]) -> str:
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


def validate_entry(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("policy entries must be JSON objects")
    policy_id = str(raw.get("policy_id") or "").strip()
    kind = str(raw.get("kind") or "").strip()
    value = str(raw.get("value") or "").strip()
    if not policy_id or len(policy_id) > 128:
        raise ValueError("policy_id is required and must be at most 128 characters")
    if kind not in POLICY_KINDS:
        raise ValueError(f"unsupported policy kind: {kind}")
    if not value:
        raise ValueError("policy value is required")
    if kind == "allow_cidr":
        value = normalize_cidr(value)
    elif len(value) > 512:
        raise ValueError("policy value is too long")
    expires_at = str(raw.get("expires_at") or "").strip() or None
    if expires_at and _parse_time(expires_at) is None:
        raise ValueError("expires_at must be an ISO-8601 timestamp")
    return {
        "policy_id": policy_id,
        "kind": kind,
        "value": value,
        "reason": str(raw.get("reason") or "").strip()[:500],
        "notes": str(raw.get("notes") or "").strip()[:2000],
        "created_by": str(raw.get("created_by") or "").strip()[:128],
        "created_at": str(raw.get("created_at") or "").strip() or None,
        "expires_at": expires_at,
    }


class RuntimePolicyStore:
    """Last-known-good policy snapshot used by one Hotpot instance.

    Dashboard policy is persisted atomically under /data. Environment allowlists stay
    independent and are always honored as bootstrap/emergency configuration.
    """

    def __init__(
        self,
        data_dir: Path,
        *,
        instance_id: str,
        bootstrap_allow_cidrs: tuple[str, ...] = (),
    ) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "policy.json"
        self.instance_id = instance_id
        self.bootstrap_allow_cidrs = tuple(normalize_cidr(value) for value in bootstrap_allow_cidrs)
        self.entries: list[dict[str, Any]] = []
        self.revision = snapshot_revision(instance_id, [])
        self.updated_at: str | None = None
        self.last_error: str | None = None
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            validated = self.validate_snapshot(payload)
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return
        self.entries = validated["entries"]
        self.revision = validated["revision"]
        self.updated_at = validated["updated_at"]
        self.last_error = None

    def validate_snapshot(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ValueError("policy snapshot must be a JSON object")
        if int(payload.get("schema_version", 0) or 0) != POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported policy schema version")
        target = str(payload.get("instance_id") or "").strip()
        if target not in {self.instance_id, "*"}:
            raise ValueError("policy snapshot targets a different Hotpot instance")
        raw_entries = payload.get("entries") or []
        if not isinstance(raw_entries, list) or len(raw_entries) > 500:
            raise ValueError("policy entries must be a list with at most 500 entries")
        entries = [validate_entry(item) for item in raw_entries]
        expected = snapshot_revision(self.instance_id, entries)
        supplied = str(payload.get("revision") or "").strip()
        if supplied and supplied != expected:
            raise ValueError("policy revision does not match canonical snapshot contents")
        updated_at = str(payload.get("updated_at") or _utcnow().isoformat())
        if _parse_time(updated_at) is None:
            raise ValueError("updated_at must be an ISO-8601 timestamp")
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "instance_id": self.instance_id,
            "revision": expected,
            "updated_at": updated_at,
            "entries": _canonical_entries(entries),
        }

    def apply_snapshot(self, payload: Any) -> dict[str, Any]:
        snapshot = self.validate_snapshot(payload)
        encoded = json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(encoded, encoding="utf-8")
        os.replace(tmp, self.path)
        self.entries = snapshot["entries"]
        self.revision = snapshot["revision"]
        self.updated_at = snapshot["updated_at"]
        self.last_error = None
        return self.status()

    @staticmethod
    def _active(entry: dict[str, Any], now: datetime) -> bool:
        expires = _parse_time(entry.get("expires_at"))
        return expires is None or expires > now

    def active_entries(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        current = now or _utcnow()
        return [dict(entry) for entry in self.entries if self._active(entry, current)]

    def allow_match(self, client_ip: str, *, now: datetime | None = None) -> dict[str, Any] | None:
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return None
        current = now or _utcnow()
        for entry in self.entries:
            if entry.get("kind") != "allow_cidr" or not self._active(entry, current):
                continue
            network = ipaddress.ip_network(str(entry["value"]), strict=False)
            if address.version == network.version and address in network:
                return dict(entry)
        return None

    def suppression_match(
        self,
        *,
        actor_key: str,
        scanner_family: str | None = None,
        category: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        current = now or _utcnow()
        candidates = {
            "suppress_actor": actor_key,
            "suppress_scanner": scanner_family or "",
            "exclude_category": category or "",
        }
        for entry in self.entries:
            if not self._active(entry, current):
                continue
            expected = candidates.get(str(entry.get("kind")))
            if expected and str(entry.get("value")) == expected:
                return dict(entry)
        return None

    def status(self) -> dict[str, Any]:
        now = _utcnow()
        active = self.active_entries(now=now)
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "instance_id": self.instance_id,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "path": str(self.path),
            "active_entries": len(active),
            "expired_entries": len(self.entries) - len(active),
            "bootstrap_allow_cidrs": list(self.bootstrap_allow_cidrs),
            "entries": active,
            "last_error": self.last_error,
            "source": "dashboard-last-known-good",
        }
