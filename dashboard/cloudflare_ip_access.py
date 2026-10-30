from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlencode

from .cloudflare_enforcement_legacy import CloudflareEnforcementError

IP_ACCESS_PROVIDER = "ip_access"
CUSTOM_WAF_PROVIDER = "custom_waf"
HOT_POT_ACCESS_NOTES_PREFIX = "hotpot-long-block"
IP_ACCESS_PERMISSION_HINT = (
    "account-wide long blocks require Cloudflare Account Firewall Access Rules Edit "
    "(API permission: Account Firewall Access Rules Write) on the configured account"
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
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CloudflareEnforcementError("invalid IP enforcement target") from exc
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

    @staticmethod
    def _access_base(scope: str, resource_id: str) -> str:
        if scope == "account":
            return f"/accounts/{resource_id}/firewall/access_rules/rules"
        if scope == "zone":
            return f"/zones/{resource_id}/firewall/access_rules/rules"
        raise CloudflareEnforcementError(f"unsupported IP Access scope: {scope}")

    async def _inspect_access_rule(
        self, scope: str, resource_id: str, rule_id: str
    ):
        base = self._access_base(scope, resource_id)
        status, data = await self._ip_access_request(
            "GET", f"{base}/{rule_id}", allow_404=True
        )
        if status == 404:
            return None
        result = (data or {}).get("result")
        return result if isinstance(result, dict) else None

    async def inspect_access_rule(self, zone_id: str, rule_id: str):
        """Backward-compatible zone-scoped inspection for legacy persisted rules."""
        return await self._inspect_access_rule("zone", zone_id, rule_id)

    async def inspect_account_access_rule(self, account_id: str, rule_id: str):
        return await self._inspect_access_rule("account", account_id, rule_id)

    async def inspect_access_rule_for_metadata(self, rule):
        account_id = str(rule.get("account_id") or "")
        if str(rule.get("scope") or "") == "account" or account_id:
            if not account_id:
                account_id = str(getattr(self.config, "account_id", "") or "")
            if not account_id:
                raise CloudflareEnforcementError(
                    "stored account-wide IP Access rule is missing account_id"
                )
            return await self.inspect_account_access_rule(
                account_id, str(rule.get("rule_id") or "")
            )
        return await self.inspect_access_rule(
            str(rule.get("zone_id") or ""), str(rule.get("rule_id") or "")
        )

    async def _find_hotpot_access_rule_scoped(
        self, scope: str, resource_id: str, value: str
    ):
        target, normalized = access_target(value)
        query = urlencode(
            {
                "configuration.target": target,
                "configuration.value": normalized,
                "mode": "block",
                "match": "all",
                "per_page": "50",
            }
        )
        base = self._access_base(scope, resource_id)
        _, data = await self._ip_access_request("GET", f"{base}?{query}")
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

    async def _find_hotpot_access_rule(self, zone_id: str, value: str):
        """Backward-compatible lookup for legacy zone-scoped rules."""
        return await self._find_hotpot_access_rule_scoped("zone", zone_id, value)

    async def _find_hotpot_account_access_rule(
        self, account_id: str, value: str
    ):
        return await self._find_hotpot_access_rule_scoped(
            "account", account_id, value
        )

    async def inspect_account_ip_access_capability(
        self, account_id: str
    ) -> dict[str, object]:
        base = self._access_base("account", account_id)
        await self._ip_access_request("GET", f"{base}?per_page=1")
        return {
            "account_id": account_id,
            "accessible": True,
            "permission": "Account Firewall Access Rules Write",
        }

    async def _apply_account_ip_access(self, recommendation):
        account_id = str(getattr(self.config, "account_id", "") or "").strip()
        if not account_id:
            raise CloudflareEnforcementError(
                "HOTPOT_CLOUDFLARE_ACCOUNT_ID is required for account-wide long blocks"
            )
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        expires_at = str(
            recommendation.get("enforcement_expires_at")
            or recommendation.get("expires_at")
            or ""
        )
        target, normalized = access_target(
            str(recommendation.get("target_value") or "")
        )
        base = self._access_base("account", account_id)
        existing = await self._find_hotpot_account_access_rule(account_id, normalized)
        reused = existing is not None
        created = False
        expiry_extended = False
        previous_expires_at = None
        try:
            if reused:
                rule_id = str(existing.get("id") or "")
                notes = parse_access_notes(existing.get("notes"))
                current = parse_iso(notes.get("expires"))
                requested = parse_iso(expires_at)
                previous_expires_at = current.isoformat() if current else None
                effective = current.isoformat() if current else expires_at
                if requested and (current is None or requested > current):
                    effective = requested.isoformat()
                    expiry_extended = True
                    await self._ip_access_request(
                        "PATCH",
                        f"{base}/{rule_id}",
                        payload={
                            "configuration": {
                                "target": target,
                                "value": normalized,
                            },
                            "mode": "block",
                            "notes": access_notes(effective, normalized),
                        },
                    )
            else:
                _, response = await self._ip_access_request(
                    "POST",
                    base,
                    payload={
                        "configuration": {"target": target, "value": normalized},
                        "mode": "block",
                        "notes": access_notes(expires_at, normalized),
                    },
                )
                rule_id = str(
                    ((response or {}).get("result") or {}).get("id") or ""
                )
                if not rule_id:
                    raise CloudflareEnforcementError(
                        "Cloudflare account IP Access rule creation omitted rule id"
                    )
                created = True

            all_hosts = tuple(
                sorted(
                    {
                        host
                        for configured in self.config.targets.values()
                        for host in configured.hosts
                    }
                )
            )
            return [
                self._stored_rule(
                    zone_id="",
                    account_id=account_id,
                    scope="account",
                    ruleset_id="",
                    rule_id=rule_id,
                    action="block",
                    expression=f"ip.src eq {normalized}",
                    hosts=all_hosts,
                    ref=f"hotpot_ip_{recommendation_id[:16]}_account",
                    reused=reused,
                    provider=IP_ACCESS_PROVIDER,
                    target_value=normalized,
                    expires_at=expires_at,
                    shared=reused,
                    expiry_extended=expiry_extended,
                    previous_expires_at=previous_expires_at,
                )
            ]
        except Exception:
            if created:
                try:
                    await self._ip_access_request(
                        "DELETE", f"{base}/{rule_id}", allow_404=True
                    )
                except Exception:
                    pass
            raise

    async def _apply_ip_access(self, recommendation, zone_hosts):
        """Legacy zone-scoped apply path retained for repair/backward compatibility."""
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        expires_at = str(
            recommendation.get("enforcement_expires_at")
            or recommendation.get("expires_at")
            or ""
        )
        target, normalized = access_target(
            str(recommendation.get("target_value") or "")
        )
        stored, created = [], []
        try:
            for zone_id, hosts in zone_hosts.items():
                existing = await self._find_hotpot_access_rule(zone_id, normalized)
                reused = existing is not None
                base = self._access_base("zone", zone_id)
                expiry_extended = False
                previous_expires_at = None
                if reused:
                    rule_id = str(existing.get("id") or "")
                    notes = parse_access_notes(existing.get("notes"))
                    current = parse_iso(notes.get("expires"))
                    requested = parse_iso(expires_at)
                    previous_expires_at = current.isoformat() if current else None
                    effective = current.isoformat() if current else expires_at
                    if requested and (current is None or requested > current):
                        effective = requested.isoformat()
                        expiry_extended = True
                        await self._ip_access_request(
                            "PATCH",
                            f"{base}/{rule_id}",
                            payload={
                                "configuration": {
                                    "target": target,
                                    "value": normalized,
                                },
                                "mode": "block",
                                "notes": access_notes(effective, normalized),
                            },
                        )
                else:
                    _, response = await self._ip_access_request(
                        "POST",
                        base,
                        payload={
                            "configuration": {
                                "target": target,
                                "value": normalized,
                            },
                            "mode": "block",
                            "notes": access_notes(expires_at, normalized),
                        },
                    )
                    rule_id = str(
                        ((response or {}).get("result") or {}).get("id") or ""
                    )
                    if not rule_id:
                        raise CloudflareEnforcementError(
                            "Cloudflare IP Access rule creation omitted rule id"
                        )
                item = self._stored_rule(
                    zone_id=zone_id,
                    scope="zone",
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
                    expiry_extended=expiry_extended,
                    previous_expires_at=previous_expires_at,
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
        rule_id = str(rule.get("rule_id") or "")
        if not rule_id:
            raise CloudflareEnforcementError(
                "stored IP Access rule metadata is incomplete"
            )
        account_id = str(rule.get("account_id") or "")
        if str(rule.get("scope") or "") == "account" or account_id:
            if not account_id:
                account_id = str(getattr(self.config, "account_id", "") or "")
            if not account_id:
                raise CloudflareEnforcementError(
                    "stored account-wide IP Access rule is missing account_id"
                )
            scope, resource_id = "account", account_id
        else:
            scope, resource_id = "zone", str(rule.get("zone_id") or "")
        current = await self._inspect_access_rule(scope, resource_id, rule_id)
        if current is None:
            return
        notes = parse_access_notes(current.get("notes"))
        if not notes:
            raise CloudflareEnforcementError(
                "refusing to remove IP Access rule no longer owned by Hotpot"
            )
        expected = str(rule.get("target_value") or "")
        actual = str((current.get("configuration") or {}).get("value") or "")
        if expected and actual != expected:
            raise CloudflareEnforcementError(
                "IP Access rule target changed since Hotpot applied it"
            )
        remote_expiry = parse_iso(notes.get("expires"))
        stored_expiry = parse_iso(rule.get("expires_at"))
        if remote_expiry and stored_expiry and remote_expiry > stored_expiry:
            return
        base = self._access_base(scope, resource_id)
        await self._ip_access_request(
            "DELETE", f"{base}/{rule_id}", allow_404=True
        )
