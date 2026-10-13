from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from aiohttp import ClientSession


CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
CUSTOM_RULE_PHASE = "http_request_firewall_custom"
IP_ACCESS_PROVIDER = "ip_access"
CUSTOM_WAF_PROVIDER = "custom_waf"
HOT_POT_ACCESS_NOTES_PREFIX = "hotpot-long-block"


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
        return bool(self.api_token)

    def public_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "configured": self.configured,
            "target_instances": len(self.targets),
            "zones": len({target.zone_id for target in self.targets.values()}),
            "provider": "Cloudflare Rulesets API",
            "phase": CUSTOM_RULE_PHASE,
            "long_block_provider": "Cloudflare zone IP Access Rules",
            "long_blocks_consume_custom_rule_slots": False,
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
            raise RuntimeError(
                "Each Cloudflare target requires an instance id and object value"
            )
        zone_id = str(value.get("zone_id") or "").strip()
        hosts_raw = value.get("hosts") or []
        if not zone_id:
            raise RuntimeError(f"Cloudflare target {key!r} requires zone_id")
        if not isinstance(hosts_raw, list) or not hosts_raw:
            raise RuntimeError(
                f"Cloudflare target {key!r} requires a non-empty hosts list"
            )
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
            raise RuntimeError(
                f"Cloudflare target {key!r} requires at least one hostname"
            )
        result[key] = CloudflareTarget(key, zone_id, hosts)
    return result


def _quote_wirefilter_string(value: str) -> str:
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
            raise CloudflareEnforcementError(
                "missing Cloudflare Worker zone target"
            )
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


def _parse_iso(value: str | None) -> datetime | None:
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


def _access_notes(expires_at: str, target_value: str) -> str:
    return f"{HOT_POT_ACCESS_NOTES_PREFIX};expires={expires_at};target={target_value}"


def _parse_access_notes(notes: str | None) -> dict[str, str]:
    raw = str(notes or "")
    if not raw.startswith(HOT_POT_ACCESS_NOTES_PREFIX):
        return {}
    result: dict[str, str] = {}
    for part in raw.split(";")[1:]:
        key, sep, value = part.partition("=")
        if sep and key:
            result[key] = value
    return result


def _access_target(target_value: str) -> tuple[str, str]:
    try:
        address = ipaddress.ip_address(target_value)
    except ValueError as exc:
        raise CloudflareEnforcementError("invalid IP enforcement target") from exc
    return ("ip" if address.version == 4 else "ip6", address.compressed)


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

    async def inspect_zone(self, zone_id: str) -> dict[str, Any]:
        """Read the custom-WAF entrypoint without creating or changing anything."""
        status, data = await self._request(
            "GET",
            f"/zones/{zone_id}/rulesets/phases/{CUSTOM_RULE_PHASE}/entrypoint",
            allow_404=True,
        )
        if status == 404:
            return {
                "zone_id": zone_id,
                "entrypoint_exists": False,
                "ruleset_id": None,
                "rules": [],
            }
        result = (data or {}).get("result") or {}
        ruleset_id = str(result.get("id") or "").strip()
        if not ruleset_id:
            raise CloudflareEnforcementError(
                "Cloudflare entry point response omitted ruleset id"
            )
        return {
            "zone_id": zone_id,
            "entrypoint_exists": True,
            "ruleset_id": ruleset_id,
            "rules": [
                rule for rule in result.get("rules") or [] if isinstance(rule, dict)
            ],
        }

    async def inspect_access_rule(
        self, zone_id: str, rule_id: str
    ) -> dict[str, Any] | None:
        status, data = await self._request(
            "GET",
            f"/zones/{zone_id}/firewall/access_rules/rules/{rule_id}",
            allow_404=True,
        )
        if status == 404:
            return None
        result = (data or {}).get("result")
        return result if isinstance(result, dict) else None

    async def _find_hotpot_access_rule(
        self, zone_id: str, target_value: str
    ) -> dict[str, Any] | None:
        access_target, normalized = _access_target(target_value)
        query = urlencode(
            {
                "configuration.target": access_target,
                "configuration.value": normalized,
                "mode": "block",
                "match": "all",
                "per_page": "50",
            }
        )
        _, data = await self._request(
            "GET",
            f"/zones/{zone_id}/firewall/access_rules/rules?{query}",
        )
        for item in (data or {}).get("result") or []:
            if not isinstance(item, dict):
                continue
            configuration = item.get("configuration") or {}
            if str(configuration.get("value") or "") != normalized:
                continue
            if str(item.get("mode") or "") != "block":
                continue
            if not str(item.get("notes") or "").startswith(
                HOT_POT_ACCESS_NOTES_PREFIX
            ):
                continue
            return item
        return None

    async def _entrypoint_ruleset(
        self, zone_id: str
    ) -> tuple[str, list[dict[str, Any]]]:
        inspected = await self.inspect_zone(zone_id)
        ruleset_id = str(inspected.get("ruleset_id") or "")
        if inspected.get("entrypoint_exists") and ruleset_id:
            return ruleset_id, list(inspected.get("rules") or [])

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
        if recommendation_action in {"recommend_block", "recommend_long_block"}:
            return "block"
        raise CloudflareEnforcementError("recommendation is not enforceable")

    @staticmethod
    def _uses_ip_access_rule(recommendation: dict[str, Any]) -> bool:
        return (
            str(recommendation.get("action") or "") == "recommend_long_block"
            and str(recommendation.get("target_type") or "") == "ip"
        )

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
        provider: str = CUSTOM_WAF_PROVIDER,
        target_value: str | None = None,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        return {
            "provider": provider,
            "zone_id": zone_id,
            "ruleset_id": ruleset_id,
            "rule_id": rule_id,
            "action": action,
            "expression": expression,
            "hosts": list(hosts),
            "ref": ref,
            "target_value": target_value,
            "expires_at": expires_at,
            "zone_wide": provider == IP_ACCESS_PROVIDER,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reused": reused,
        }

    async def _apply_ip_access_long_block(
        self,
        recommendation: dict[str, Any],
        zone_hosts: dict[str, tuple[str, ...]],
    ) -> list[dict[str, Any]]:
        target_value = str(recommendation.get("target_value") or "")
        access_target, normalized = _access_target(target_value)
        expires_at = str(
            recommendation.get("enforcement_expires_at")
            or recommendation.get("expires_at")
            or ""
        )
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        stored: list[dict[str, Any]] = []
        newly_created: list[dict[str, Any]] = []

        try:
            for zone_id, hosts in zone_hosts.items():
                existing = await self._find_hotpot_access_rule(zone_id, normalized)
                if existing is not None:
                    rule_id = str(existing.get("id") or "")
                    if not rule_id:
                        raise CloudflareEnforcementError(
                            "existing IP Access rule omitted rule id"
                        )
                    notes = _parse_access_notes(existing.get("notes"))
                    current_expiry = _parse_iso(notes.get("expires"))
                    requested_expiry = _parse_iso(expires_at)
                    effective_expiry = expires_at
                    if current_expiry is not None and (
                        requested_expiry is None or current_expiry > requested_expiry
                    ):
                        effective_expiry = current_expiry.isoformat()
                    elif requested_expiry is not None and (
                        current_expiry is None or requested_expiry > current_expiry
                    ):
                        effective_expiry = requested_expiry.isoformat()
                        await self._request(
                            "PATCH",
                            f"/zones/{zone_id}/firewall/access_rules/rules/{rule_id}",
                            payload={
                                "configuration": {
                                    "target": access_target,
                                    "value": normalized,
                                },
                                "mode": "block",
                                "notes": _access_notes(effective_expiry, normalized),
                            },
                          )
                    stored.append(
                        self._stored_rule(
                            zone_id=zone_id,
                            ruleset_id="",
                            rule_id=rule_id,
                            action="block",
                            expression=f"ip.src eq {normalized}",
                            hosts=hosts,
                            ref=f"hotpot_ip_{recommendation_id[:16]}_{zone_id[:8]}",
                            reused=True,
                            provider=IP_ACCESS_PROVIDER,
                            target_value=normalized,
                            expires_at=expires_at,
                        )
                    )
                    continue

                  _, response = await self._request(
                    "POST",
                    f"/zones/{zone_id}/firewall/access_rules/rules",
                    payload={
                        "configuration": {
                            "target": access_target,
                            "value": normalized,
                        },
                        "mode": "block",
                        "notes": _access_notes(expires_at, normalized),
                    },
                )
                result = (response or {}).get("result") or {}
                rule_id = str(result.get("id") or "")
                if not rule_id:
                    raise CloudflareEnforcementError(
                        "Cloudflare IP Access rule creation omitted the new rule id"
                    )
                item = self._stored_rule(
                    zone_id=zone_id,
                    ruleset_id="",
                    rule_id=rule_id,
                    action="block",
                    expression=f"ip.src eq {normalized}",
                    hosts=hosts,
                    ref=f"hotpot_ip_{recommendation_id[:16]}_{zone_id[:8]}",
                    reused=False,
                    provider=IP_ACCESS_PROVIDER,
                    target_value=normalized,
                    expires_at=expires_at,
                 )
                stored.append(item)
                newly_created.append(item)
            return stored
        except Exception:
            for rule in reversed(newly_created):
                try:
                    await self.remove_rule(rule)
                except Exception:
                    pass
            raise

    async def _apply_custom_waf(
        self,
        recommendation: dict[str, Any],
        zone_hosts: dict[str, tuple[str, ...]],
    ) -> list[dict[str, Any]]:
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        target_type = str(recommendation.get("target_type") or "")
        target_value = str(recommendation.get("target_value") or "")
        cf_action = self._rule_action(str(recommendation.get("action") or ""))
        expires_at = str(
            recommendation.get("enforcement_expires_at")
            or recommendation.get("expires_at")
            or ""
         )
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
                            target_value=target_value,
                            expires_at=expires_at,
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
                    if isinstance(rule, dict) and str(rule.get("ref") or "") == ref:
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
                    target_value=target_value,
                    expires_at=expires_at,
                 )
                stored.append(item)
                newly_created.append(item)
            return stored
        except Exception:
            for rule in reversed(newly_created):
                try:
                    await self.remove_rule(rule)
                except Exception:
                    pass
            raise

    async def apply(self, recommendation: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.config.configured:
            raise CloudflareEnforcementError(
                "Cloudflare enforcement is not fully configured"
            )
        zone_hosts = self._targets_for_recommendation(recommendation)
        if self._uses_ip_access_rule(recommendation):
            return await self._apply_ip_access_long_block(recommendation, zone_hosts)
        return await self._apply_custom_waf(recommendation, zone_hosts)

    async def remove_rule(self, rule: dict[str, Any]) -> None:
        provider = str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
        zone_id = str(rule.get("zone_id") or "")
        rule_id = str(rule.get("rule_id") or "")
        if provider == IP_ACCESS_PROVIDER:
            if not zone_id or not rule_id:
                raise CloudflareEnforcementError(
                    "stored IP Access rule metadata is incomplete"
                )
            current = await self.inspect_access_rule(zone_id, rule_id)
            if current is None:
                return
            notes = _parse_access_notes(current.get("notes"))
            if not notes:
                raise CloudflareEnforcementError(
                    "refusing to remove IP Access rule no longer owned by Hotpot"
                )
            expected_target = str(rule.get("target_value") or "")
            current_target = str((current.get("configuration") or {}).get("value") or "")
            if expected_target and current_target != expected_target:
                raise CloudflareEnforcementError(
                    "IP Access rule target changed since Hotpot applied it"
                )
            remote_expiry = _parse_iso(notes.get("expires"))
            stored_expiry = _parse_iso(rule.get("expires_at"))
            if (
                remote_expiry is not None
                and stored_expiry is not None
                and remote_expiry > stored_expiry
            ):
                return
            await self._request(
                "DELETE",
                f"/zones/{zone_id}/firewall/access_rules/rules/{rule_id}",
                allow_404=True,
            )
            return

        ruleset_id = str(rule.get("ruleset_id") or "")
        if not zone_id or not ruleset_id or not rule_id:
            raise CloudflareEnforcementError(
                "stored Cloudflare rule metadata is incomplete"
            )
        await self._request(
            "DELETE",
            f"/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
            allow_404=True,
        )

    async def remove(self, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
        errors: list[dict[str, Any]] = []
        for rule in rules:
            try:
                await self.remove_rule(rule)
            except Exception as exc:
                errors.append(
                    {
                        "provider": rule.get("provider") or CUSTOM_WAF_PROVIDER,
                        "zone_id": rule.get("zone_id"),
                        "rule_id": rule.get("rule_id"),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
        return errors

    async def reconcile(
        self, recommendations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Compare persisted Hotpot rules with Cloudflare without mutating either."""

        checked_at = datetime.now(timezone.utc).isoformat()
        expected_custom_by_zone: dict[str, list[dict[str, Any]]] = {}
        expected_access_by_zone: dict[str, list[dict[str, Any]]] = {}
        recommendation_results: dict[str, dict[str, Any]] = {}

        for recommendation in recommendations:
            recommendation_id = str(
                recommendation.get("recommendation_id") or ""
            ).strip()
            if not recommendation_id:
                continue
            recommendation_results[recommendation_id] = {
                "recommendation_id": recommendation_id,
                "actor_key": recommendation.get("actor_key"),
                "status": "healthy",
                "rules": [],
            }
            for rule in recommendation.get("enforcement_rules") or []:
                if not isinstance(rule, dict):
                    continue
                provider = str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
                zone_id = str(rule.get("zone_id") or "").trip()
                rule_id = str(rule.get("rule_id") or "").strip()
                ref = str(rule.get("ref") or "").strip()
                if not zone_id or not rule_id:
                    recommendation_results[recommendation_id]["status"] = "drifted"
                    recommendation_results[recommendation_id]["rules"].append(
                        {
                            "provider": provider,
                            "zone_id": zone_id or None,
                            "ref": ref or None,
                            "status": "drifted",
                            "detail": "persisted rule metadata is incomplete",
                        }
                    )
                    continue
                expected = {
                    "recommendation_id": recommendation_id,
                    "provider": provider,
                    "zone_id": zone_id,
                    "ruleset_id": str(rule.get("ruleset_id") or ""),
                    "rule_id": rule_id,
                    "ref": ref,
                    "action": str(rule.get("action") or ""),
                    "expression": str(rule.get("expression") or ""),
                    "target_value": str(rule.get("target_value") or ""),
                    "expires_at": str(rule.get("expires_at") or ""),
                }
                if provider == IP_ACCESS_PROVIDER:
                    expected_access_by_zone.setdefault(zone_id, []).append(expected)
                else:
                    if not ref:
                        recommendation_results[recommendation_id]["status"] = "drifted"
                        recommendation_results[recommendation_id]["rules"].append(
                            {
                                "provider": provider,
                                "zone_id": zone_id,
                                "ref": None,
                                "status": "drifted",
                              "detail": "persisted WAF rule ref is missing",
                            }
                        )
                        continue
                    expected_custom_by_zone.setdefault(zone_id, []).append(expected)

        zones = sorted(set(expected_custom_by_zone) | set(expected_access_by_zone))
        orphans: list[dict[str, Any]] = []
        zone_errors: list[dict[str, Any]] = []
        status_rank = {"healthy": 0, "drifted": 1, "missing": 2, "error": 3}

        def mark_rule(expected: dict[str, Any], status: str, detail: str) -> None:
            recommendation_id = expected["recommendation_id"]
            result = recommendation_results[recommendation_id]
            if status_rank[status] > status_rank[result["status"]]:
                result["status"] = status
            result["rules"].append(
                {
                    "provider": expected["provider"],
                    "zone_id": expected["zne_id"],
                    "ref": expected["ref"],
                    "expected_rule_id": expected["rule_id"],
                    "status": status,
                    "detail": detail,
                }
            )

        for zone_id in zones:
            custom_expected = expected_custom_by_zone.get(zone_id, [])
            if custom_expected:
                try:
                    inspected = await self.inspect_zone(zone_id)
                except Exception as exc:
                    message = f"{type(exc).__name__}: {exc}"
                    zone_errors.append(
                        {"zne_id": zone_id, "provider": CUSTOM_WAF_PROVIDER, "error": message}
                    )
                    for expected in custom_expected:
                        mark_rule(expected, "error", message)
                else:
                    expected_refs = {value["ref"] for value in custom_expected}
                    observed_rules = list(inspected.get("rules") or [])
                    observed_by_ref = {
                        str(rule.get("ref") or ""): rule
                        for rule in observed_rules
                        if str(rule.get("ref") or "")
                    }
                    for expected in custom_expected:
                        observed = observed_by_ref.get(expected["ref"])
                        if observed is None:
                            detail = (
                                "custom WAF entrypoint is missing"
                                if not inspected.get("entrypoint_exists")
                                else "expected Hotpot rule was not found"
                            )
                            mark_rule(expected, "missing", detail)
                            continue
                        differences: list[str] = []
                        if expected["rule_id"] and str(observed.get("id") or "") != expected["rule_id"]:
                            differences.append("rule id changed")
                        if expected["ruleset_id"] and str(inspected.get("ruleset_id") or "") != expected["ruleset_id"]:
                            differences.append("ruleset id changed")
                        if expected["action"] and str(observed.get("action") or "") != expected["action"]:
                            differences.append("action changed")
                        if expected["expression"] and str(observed.get("expression") or "") != expected["expression"]:
                            differences.append("expression changed")
                        if observed.get("enabled") is False:
                            differences.append("rule disabled")
                        if differences :
                            mark_rule(expected, "drifted", "; ".join(differences))
                        else:
                            mark_rule(expected, "healthy", "matches persisted Hotpot WAF rule")
                    for observed in observed_rules:
                        ref = str(observed.get("ref") or "")
                        if not ref.startswith("hotpot_") or ref in expected_refs:
                            continue
                        orphans.append(
                            {
                                "provider": CUSTOM_WAF_PROVIDER,
                                "zone_id": zone_id,
                                "ruleset_id": inspected.get("ruleset_id"),
                                "rule_id": observed.get("id"),
                                "ref": ref,
                                "action": observed.get("action"),
                                "expression": observed.get("expression"),
                                "enabled": observed.get("enabled", True),
                                "description": observed.get("description"),
                            }
                        )

            for expected in expected_access_by_zone.get(zone_id, []):
                try:
                    observed = await self.inspect_access_rule(zone_id, expected["rule_id"])
                except Exception as exc:
                    message = f"{type(exc).__name__}: {exc}"
                    zone_errors.append(
                        {"zne_id": zone_id, "provider": IP_ACCESS_PROVIDER, "error": message}
                    )
                    mark_rule(expected, "error", message)
                    continue
                if observed is None:
                    mark_rule(expected, "missing", "expected Hotpot IP Access rule was not found")
                    continue
                differences: list[str] = []
                if str(observed.get("mode") or "") != "block":
                    differences.append("mode changed")
                current_target = str((observed.get("configuration") or {}).get("value") or "")
                if expected["target_value"] and current_target != expected["target_value"]:
                    differences.append("target changed")
                notes = _parse_access_notes(observed.get("notes"))
                if not notes:
                    differences.append("Hotpot ownership marker missing")
                else:
                    remote_expiry = _parse_iso(notes.get("expires"))
                    expected_expiry = _parse_iso(expected["expires_at"])
                    if (
                        remote_expiry is not None
                        and expected_expiry is not None
                        and remote_expiry < expected_expiry
                    ):
                        differences.append("expiry shortened")
                if differences:
                    mark_rule(expected, "drifted", "; ".join(differences))
                else:
                    mark_rule(expected, "healthy", "matches persisted Hotpot IP Access rule")

        values = list(recommendation_results.values())
        counts = {
            status: sum(1 for value in values if value["status"] == status)
            for status in ("healthy", "drifted", "missing", "error")
        }
        overall = "healthy"
        if zone_errors:
            overall = "error"
        elif counts["missing"] or counts["drifted"] or orphans:
            overall = "drifted"
        return {
            "checked_at": checked_at,
            "status": overall,
            "recommendations": values,
            "counts": counts,
            "orphans": orphans,
            "orphaned": len(orphans),
            "zone_errors": zone_errors,
            "zones_checked": len(zones),
        }
