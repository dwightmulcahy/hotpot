from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aiohttp import ClientSession


CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
CUSTOM_RULE_PHASE = "http_request_firewall_custom"


class CloudflareEnforcementError(RuntimeError):
    pass


@dataclass(frozen=True)
class CloudflareTarget:
    instance_id: str
    zone_id: str
    hosts: tuple[str, ...]


@dataclass(frozen=True)
class CloudflareConfig:
    enabled: bool
    api_token: str
    targets: dict[str, CloudflareTarget]
    api_base: str = CLOUDFLARE_API_BASE

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.api_token and self.targets)

    @property
    def can_remove(self) -> bool:
        # Removal uses rule metadata persisted at apply time and only needs API auth.
        return bool(self.api_token)

    def public_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "configured": self.configured,
            "target_instances": len(self.targets),
            "zones": len({target.zone_id for target in self.targets.values()}),
            "provider": "Cloudflare Rulesets API",
            "phase": CUSTOM_RULE_PHASE,
            "token_configured": bool(self.api_token),
            "automatic_enforcement": False,
            "approval_required": True,
        }


def parse_cloudflare_targets(raw: str) -> dict[str, CloudflareTarget]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("HOTPOT_CLOUDFLARE_TARGETS must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("HOTPOT_CLOUDFLARE_TARGETS must be a JSON object")

    result: dict[str, CloudflareTarget] = {}
    for instance_id, value in payload.items():
        key = str(instance_id).strip()
        if not key or not isinstance(value, dict):
            raise RuntimeError("Each Cloudflare target requires an instance id and object value")
        zone_id = str(value.get("zone_id") or "").strip()
        hosts_raw = value.get("hosts") or []
        if not zone_id:
            raise RuntimeError(f"Cloudflare target {key!r} requires zone_id")
        if not isinstance(hosts_raw, list) or not hosts_raw:
            raise RuntimeError(f"Cloudflare target {key!r} requires a non-empty hosts list")
        hosts = tuple(
            sorted(
                {
                    str(host).strip().lower()
                    for host in hosts_raw
                    if str(host).strip()
                }
            )
        )
        if not hosts:
            raise RuntimeError(f"Cloudflare target {key!r} requires at least one hostname")
        result[key] = CloudflareTarget(key, zone_id, hosts)
    return result


def _quote_wirefilter_string(value: str) -> str:
    # Cloudflare wirefilter string escaping is compatible with JSON double-quoted
    # strings for the hostname/zone values Hotpot emits here.
    return json.dumps(value, ensure_ascii=True)


def build_expression(
    target_type: str, target_value: str, hosts: tuple[str, ...]
) -> str:
    if target_type == "ip":
        try:
            address = ipaddress.ip_address(target_value)
        except ValueError as exc:
            raise CloudflareEnforcementError("invalid IP enforcement target") from exc
        actor = f"ip.src eq {address.compressed}"
    elif target_type == "cloudflare-worker-zone":
        zone = target_value.strip().lower()
        if not zone:
            raise CloudflareEnforcementError("missing Cloudflare Worker zone target")
        actor = f"cf.worker.upstream_zone eq {_quote_wirefilter_string(zone)}"
    else:
        raise CloudflareEnforcementError(
            f"unsupported enforcement target type: {target_type}"
        )

    if not hosts:
        raise CloudflareEnforcementError(
            "enforcement target has no configured hostnames"
        )
    host_expr = " or ".join(
        f"http.host eq {_quote_wirefilter_string(host)}"
        for host in sorted(set(hosts))
    )
    return f"({actor}) and ({host_expr})"


class CloudflareEnforcer:
    def __init__(self, config: CloudflareConfig, client: ClientSession) -> None:
        self.config = config
        self.client = client

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        allow_404: bool = False,
    ) -> tuple[int, dict[str, Any] | None]:
        url = self.config.api_base.rstrip("/") + path
        headers = {
            "Authorization": f"Bearer {self.config.api_token}",
            "Content-Type": "application/json",
        }
        async with self.client.request(
            method, url, headers=headers, json=payload
        ) as response:
            if allow_404 and response.status == 404:
                return response.status, None
            try:
                data = await response.json(content_type=None)
            except Exception:
                data = None
            if response.status < 200 or response.status >= 300:
                message = f"Cloudflare API returned HTTP {response.status}"
                if isinstance(data, dict):
                    errors = data.get("errors") or []
                    if errors and isinstance(errors, list):
                        detail = (
                            errors[0].get("message")
                            if isinstance(errors[0], dict)
                            else None
                        )
                        if detail:
                            message += f": {detail}"
                raise CloudflareEnforcementError(message)
            if isinstance(data, dict) and data.get("success") is False:
                raise CloudflareEnforcementError(
                    "Cloudflare API reported an unsuccessful operation"
                )
            return response.status, data if isinstance(data, dict) else None

    async def _entrypoint_ruleset(
        self, zone_id: str
    ) -> tuple[str, list[dict[str, Any]]]:
        status, data = await self._request(
            "GET",
            f"/zones/{zone_id}/rulesets/phases/{CUSTOM_RULE_PHASE}/entrypoint",
            allow_404=True,
        )
        if status != 404 and data:
            result = data.get("result") or {}
            ruleset_id = str(result.get("id") or "").strip()
            if ruleset_id:
                rules = [
                    rule for rule in result.get("rules") or [] if isinstance(rule, dict)
                ]
                return ruleset_id, rules
            raise CloudflareEnforcementError(
                "Cloudflare entry point response omitted ruleset id"
            )

        _, created = await self._request(
            "POST",
            f"/zones/{zone_id}/rulesets",
            payload={
                "name": "Hotpot temporary response rules",
                "description": "Zone entry point for Hotpot-approved temporary response rules",
                "kind": "zone",
                "phase": CUSTOM_RULE_PHASE,
                "rules": [],
            },
        )
        result = (created or {}).get("result") or {}
        ruleset_id = str(result.get("id") or "").strip()
        if not ruleset_id:
            raise CloudflareEnforcementError(
                "Cloudflare ruleset creation omitted ruleset id"
            )
        return ruleset_id, []

    @staticmethod
    def _rule_action(recommendation_action: str) -> str:
        if recommendation_action == "recommend_challenge":
            return "managed_challenge"
        if recommendation_action in {
            "recommend_block",
            "recommend_long_block",
        }:
            return "block"
        raise CloudflareEnforcementError("recommendation is not enforceable")

    def _targets_for_recommendation(
        self, recommendation: dict[str, Any]
    ) -> dict[str, tuple[str, ...]]:
        evidence = recommendation.get("evidence") or {}
        instance_ids = [
            str(value)
            for value in evidence.get("instance_ids") or []
            if str(value)
        ]
        if not instance_ids:
            raise CloudflareEnforcementError(
                "recommendation does not include target instance ids"
            )

        missing = sorted(
            {
                instance_id
                for instance_id in instance_ids
                if instance_id not in self.config.targets
            }
        )
        if missing:
            raise CloudflareEnforcementError(
                "missing Cloudflare target mapping for: " + ", ".join(missing)
            )

        by_zone: dict[str, set[str]] = {}
        for instance_id in instance_ids:
            target = self.config.targets[instance_id]
            by_zone.setdefault(target.zone_id, set()).update(target.hosts)
        return {
            zone_id: tuple(sorted(hosts)) for zone_id, hosts in by_zone.items()
        }

    @staticmethod
    def _stored_rule(
        *,
        zone_id: str,
        ruleset_id: str,
        rule_id: str,
        action: str,
        expression: str,
        hosts: tuple[str, ...],
        ref: str,
        reused: bool,
    ) -> dict[str, Any]:
        return {
            "zone_id": zone_id,
            "ruleset_id": ruleset_id,
            "rule_id": rule_id,
            "action": action,
            "expression": expression,
            "hosts": list(hosts),
            "ref": ref,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reused": reused,
        }

    async def apply(self, recommendation: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.config.configured:
            raise CloudflareEnforcementError(
                "Cloudflare enforcement is not fully configured"
            )

        recommendation_id = str(
            recommendation.get("recommendation_id") or ""
        )
        target_type = str(recommendation.get("target_type") or "")
        target_value = str(recommendation.get("target_value") or "")
        cf_action = self._rule_action(
            str(recommendation.get("action") or "")
        )
        expires_at = str(
            recommendation.get("enforcement_expires_at")
            or recommendation.get("expires_at")
            or ""
        )
        zone_hosts = self._targets_for_recommendation(recommendation)
        stored: list[dict[str, Any]] = []
        newly_created: list[dict[str, Any]] = []

        try:
            for zone_id, hosts in zone_hosts.items():
                ruleset_id, existing_rules = await self._entrypoint_ruleset(zone_id)
                expression = build_expression(target_type, target_value, hosts)
                ref = f"hotpot_{recommendation_id[:20]}_{zone_id[:8]}"
                existing = next(
                    (
                        rule
                        for rule in existing_rules
                        if str(rule.get("ref") or "") == ref
                    ),
                    None,
                )
                if existing is not None:
                    rule_id = str(existing.get("id") or "")
                    if not rule_id:
                        raise CloudflareEnforcementError(
                            "existing Hotpot Cloudflare rule omitted rule id"
                        )
                    if (
                        str(existing.get("action") or "") != cf_action
                        or str(existing.get("expression") or "") != expression
                    ):
                        raise CloudflareEnforcementError(
                            "existing Hotpot rule ref conflicts with expected action/expression"
                        )
                    stored.append(
                        self._stored_rule(
                            zone_id=zone_id,
                            ruleset_id=ruleset_id,
                            rule_id=rule_id,
                            action=cf_action,
                            expression=expression,
                            hosts=hosts,
                            ref=ref,
                            reused=True,
                        )
                    )
                    continue

                description = (
                    f"Hotpot temporary {cf_action}; recommendation "
                    f"{recommendation_id}; expires {expires_at}"
                )
                _, response = await self._request(
                    "POST",
                    f"/zones/{zone_id}/rulesets/{ruleset_id}/rules",
                    payload={
                        "action": cf_action,
                        "expression": expression,
                        "description": description,
                        "ref": ref,
                        "enabled": True,
                    },
                )
                result = (response or {}).get("result") or {}
                rule_id = ""
                for rule in result.get("rules") or []:
                    if (
                        isinstance(rule, dict)
                        and str(rule.get("ref") or "") == ref
                    ):
                        rule_id = str(rule.get("id") or "")
                        break
                if not rule_id:
                    raise CloudflareEnforcementError(
                        "Cloudflare rule creation response omitted the new rule id"
                    )
                item = self._stored_rule(
                    zone_id=zone_id,
                    ruleset_id=ruleset_id,
                    rule_id=rule_id,
                    action=cf_action,
                    expression=expression,
                    hosts=hosts,
                    ref=ref,
                    reused=False,
                )
                stored.append(item)
                newly_created.append(item)
            return stored
        except Exception:
            # Approval is atomic from Hotpot's perspective. Roll back only rules
            # created by this attempt. Pre-existing idempotent refs are left intact.
            for rule in reversed(newly_created):
                try:
                    await self.remove_rule(rule)
                except Exception:
                    pass
            raise

    async def remove_rule(self, rule: dict[str, Any]) -> None:
        zone_id = str(rule.get("zone_id") or "")
        ruleset_id = str(rule.get("ruleset_id") or "")
        rule_id = str(rule.get("rule_id") or "")
        if not zone_id or not ruleset_id or not rule_id:
            raise CloudflareEnforcementError(
                "stored Cloudflare rule metadata is incomplete"
            )
        await self._request(
            "DELETE",
            f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
            allow_404=True,
        )

    async def remove(
        self, rules: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        errors: list[dict[str, Any]] = []
        for rule in rules:
            try:
                await self.remove_rule(rule)
            except Exception as exc:
                errors.append(
                    {
                        "zone_id": rule.get("zone_id"),
                        "rule_id": rule.get("rule_id"),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
        return errors
