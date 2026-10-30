from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlencode

from .cloudflare_enforcement_legacy import CloudflareEnforcementError

IP_ACCESS_PROVIDER = "ip_access"
CUSTOM_WAF_PROVIDER = "custom_waf"
HOT_POT_ACCESS_NOTES_PREFIX = "hotpot-long-block"
IP_ACCESS_PERMISSION_HINT = (
    "long blocks require Cloudflare Account Firewall Access Rules Edit "
    "(API permission: Account Firewall Access Rules Write) scoped to the account"
)


def parse_iso(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def access_notes(expires_at: str, target_value: str) -> str:
    return f"{HOT_POT_ACCESS_NOTES_PREFIX};expires={expires_at};target={target_value}"


def parse_access_notes(notes: str | None) -> dict[str, str]:
    raw = str(notes or "")
    if not raw.startswith(HOT_POT_ACCESS_NOTES_PREFIX):
        return {}
    result = {}
    for part in raw.split(";")[1:]:
        key, sep, value = part.partition("=")
        if sep and key:
            result[key] = value
    return result


def access_target(value: str) -> tuple[str, str]:
    address = ipaddress.ip_address(value)
    return ("ip" if address.version == 4 else "ip6", address.compressed)


class IPAccessMixin:
    async def _ip_access_request(
        self,
        method: str,
        path: str,
        *,
        payload=None,
        allow_404: bool = False,
    ):
        try:
            return await self._request(
                method, path, payload=payload, allow_404=allow_404
            )
        except CloudflareEnforcementError as exc:
            if "HTTP 403" in str(exc):
                raise CloudflareEnforcementError(
                    f"{exc}; {IP_ACCESS_PERMISSION_HINT}"
                ) from exc
            raise

    async def inspect_ip_access_capability(self, zone_id: str) -> dict[str, object]:
        await self._ip_access_request(
            "GET",
            f"/zones/{zone_id}/firewall/access_rules/rules?per_page=1",
        )
        return {
            "zone_id": zone_id,
            "accessible": True,
            "permission": "Account Firewall Access Rules Write",
        }

    async def inspect_access_rule(self, zone_id: str, rule_id: str):
        status, data = await self._ip_access_request(
            "GET", f"/zones/{zone_id}/firewall/access_rules/rules/{rule_id}", allow_404=True
        )
        if status == 404:
            return None
        result = (data or {}).get("result")
        return result if isinstance(result, dict) else None

    async def _find_hotpot_access_rule(self, zone_id: str, value: str):
        target, normalized = access_target(value)
        query = urlencode({
            "configuration.target": target,
            "configuration.value": normalized,
            "mode": "block",
            "match": "all",
            "per_page": "50",
        })
        _, data = await self._ip_access_request(
            "GET", f"/zones/{zone_id}/firewall/access_rules/rules?{query}"
        )
        for item in (data or {}).get("result") or []:
            if not isinstance(item, dict):
                continue
            config = item.get("configuration") or {}
            if str(config.get("value") or "") != normalized:
                continue
            if str(item.get("mode") or "") != "block":
                continue
            if not parse_access_notes(item.get("notes")):
                continue
            return item
        return None

    async def _apply_ip_access(self, recommendation, zone_hosts):
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        expires_at = str(
            recommendation.get("enforcement_expires_at")
            or recommendation.get("expires_at")
            or ""
        )
        target, normalized = access_target(str(recommendation.get("target_value") or ""))
        stored, created = [], []
        try:
            for zone_id, hosts in zone_hosts.items():
                existing = await self._find_hotpot_access_rule(zone_id, normalized)
                reused = existing is not None
                if reused:
                    rule_id = str(existing.get("id") or "")
                    notes = parse_access_notes(existing.get("notes"))
                    current = parse_iso(notes.get("expires"))
                    requested = parse_iso(expires_at)
                    effective = current.isoformat() if current else expires_at
                    if requested and (current is None or requested > current):
                        effective = requested.isoformat()
                        await self._ip_access_request(
                            "PATCH",
                            f"/zones/{zone_id}/firewall/access_rules/rules/{rule_id}",
                            payload={
                                "configuration": {"target": target, "value": normalized},
                                "mode": "block",
                                "notes": access_notes(effective, normalized),
                            },
                        )
                else:
                    _, response = await self._ip_access_request(
                        "POST",
                        f"/zones/{zone_id}/firewall/access_rules/rules",
                        payload={
                            "configuration": {"target": target, "value": normalized},
                            "mode": "block",
                            "notes": access_notes(expires_at, normalized),
                        },
                    )
                    rule_id = str(((response or {}).get("result") or {}).get("id") or "")
                    if not rule_id:
                        raise RuntimeError("Cloudflare IP Access rule creation omitted rule id")
                item = self._stored_rule(
                    zone_id=zone_id,
                    ruleset_id="",
                    rule_id=rule_id,
                    action="block",
                    expression=f"ip.src eq {normalized}",
                    hosts=hosts,
                    ref=f"hotpot_ip_{recommendation_id[:16]}_{zone_id[:8]}",
                    reused=reused,
                    provider=IP_ACCESS_PROVIDER,
                    target_value=normalized,
                    expires_at=expires_at,
                )
                stored.append(item)
                if not reused:
                    created.append(item)
            return stored
        except Exception:
            for item in reversed(created):
                try:
                    await self._remove_ip_access(item)
                except Exception:
                    pass
            raise

    async def _remove_ip_access(self, rule):
        zone_id = str(rule.get("zone_id") or "")
        rule_id = str(rule.get("rule_id") or "")
        current = await self.inspect_access_rule(zone_id, rule_id)
        if current is None:
            return
        notes = parse_access_notes(current.get("notes"))
        if not notes:
            raise RuntimeError("refusing to remove IP Access rule no longer owned by Hotpot")
        expected = str(rule.get("target_value") or "")
        actual = str((current.get("configuration") or {}).get("value") or "")
        if expected and actual != expected:
            raise RuntimeError("IP Access rule target changed since Hotpot applied it")
        remote_expiry = parse_iso(notes.get("expires"))
        stored_expiry = parse_iso(rule.get("expires_at"))
        if remote_expiry and stored_expiry and remote_expiry > stored_expiry:
            return
        await self._ip_access_request(
            "DELETE", f"/zones/{zone_id}/firewall/access_rules/rules/{rule_id}", allow_404=True
        )
