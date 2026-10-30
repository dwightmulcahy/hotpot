from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

from .cloudflare_enforcement import (
    CUSTOM_WAF_PROVIDER,
    HOT_POT_ACCESS_NOTES_PREFIX,
    IP_ACCESS_PROVIDER,
    POOL_PROVIDER,
    CloudflareEnforcementError,
    CloudflareEnforcer,
    _parse_access_notes,
    _parse_iso,
    build_expression,
)
from .cloudflare_ip_access import access_notes, access_target
from .cloudflare_pool import pool_definition


@dataclass
class CloudflareTransactionError(CloudflareEnforcementError):
    message: str
    residual_rules: list[dict[str, Any]]

    def __str__(self) -> str:
        return self.message


class TransactionalCloudflareEnforcer(CloudflareEnforcer):
    """Add bounded retries and post-operation verification to Cloudflare mutations."""

    def __init__(self, config, client) -> None:
        super().__init__(config, client)
        self.retry_attempts = max(
            1, min(6, int(os.getenv("HOTPOT_CLOUDFLARE_RETRY_ATTEMPTS", "3")))
        )
        self.retry_base_seconds = max(
            0.05, float(os.getenv("HOTPOT_CLOUDFLARE_RETRY_BASE_SECONDS", "0.25"))
        )

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
        message = "Cloudflare API request failed"
        for attempt in range(1, self.retry_attempts + 1):
            async with self.client.request(
                method, url, headers=headers, json=payload
            ) as response:
                if allow_404 and response.status == 404:
                    return 404, None
                try:
                    data = await response.json(content_type=None)
                except Exception:
                    data = None
                if 200 <= response.status < 300:
                    if isinstance(data, dict) and data.get("success") is False:
                        raise CloudflareEnforcementError(
                            "Cloudflare API reported an unsuccessful operation"
                        )
                    return response.status, data if isinstance(data, dict) else None
                message = f"Cloudflare API returned HTTP {response.status}"
                if isinstance(data, dict):
                    errors = data.get("errors") or []
                    if (
                        errors
                        and isinstance(errors[0], dict)
                        and errors[0].get("message")
                    ):
                        message += f": {errors[0]['message']}"
                retryable = response.status == 429 or response.status >= 500
                if not retryable or attempt >= self.retry_attempts:
                    raise CloudflareEnforcementError(message)
                raw_retry = response.headers.get("Retry-After", "").strip()
                try:
                    delay = float(raw_retry) if raw_retry else 0.0
                except ValueError:
                    delay = 0.0
                if delay <= 0:
                    delay = self.retry_base_seconds * (2 ** (attempt - 1))
            await asyncio.sleep(min(delay, 5.0))
        raise CloudflareEnforcementError(message)

    async def _residual_rules(
        self, recommendation: dict[str, Any]
    ) -> list[dict[str, Any]]:
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        residual: list[dict[str, Any]] = []
        try:
            zones = self._targets_for_recommendation(recommendation)
        except Exception:
            zones = {}

        if self._uses_ip_access_rule(recommendation):
            account_id = str(getattr(self.config, "account_id", "") or "")
            if not account_id:
                return residual
            target_value = str(recommendation.get("target_value") or "")
            expires_at = str(
                recommendation.get("enforcement_expires_at")
                or recommendation.get("expires_at")
                or ""
            )
            try:
                current = await self._find_hotpot_account_access_rule(
                    account_id, target_value
                )
            except Exception:
                return residual
            if current is None:
                return residual
            all_hosts = tuple(
                sorted(
                    {
                        host
                        for configured in self.config.targets.values()
                        for host in configured.hosts
                    }
                )
            )
            residual.append(
                self._stored_rule(
                    zone_id="",
                    account_id=account_id,
                    scope="account",
                    ruleset_id="",
                    rule_id=str(current.get("id") or ""),
                    action="block",
                    expression=f"ip.src eq {target_value}",
                    hosts=all_hosts,
                    ref=f"hotpot_ip_{recommendation_id[:16]}_account",
                    reused=True,
                    provider=IP_ACCESS_PROVIDER,
                    target_value=target_value,
                    expires_at=expires_at,
                    shared=True,
                )
            )
            return residual

        if self._uses_pooled_waf(recommendation):
            target_value = str(recommendation.get("target_value") or "")
            action = str(recommendation.get("action") or "")
            cf_action, ref = pool_definition(action)
            for zone_id in zones:
                try:
                    observed = await self.inspect_pool_rule(zone_id, ref)
                except Exception:
                    continue
                if observed is None:
                    continue
                current, members = observed
                if target_value not in members:
                    continue
                inspected = await self.inspect_zone(zone_id)
                residual.append(
                    self._stored_rule(
                        zone_id=zone_id,
                        ruleset_id=str(inspected.get("ruleset_id") or ""),
                        rule_id=str(current.get("id") or ""),
                        action=cf_action,
                        expression=str(current.get("expression") or ""),
                        hosts=self._all_hosts_for_zone(zone_id),
                        ref=ref,
                        reused=True,
                        provider=POOL_PROVIDER,
                        target_value=target_value,
                        scope="configured-hostnames",
                        shared=True,
                    )
                )
            return residual

        for zone_id, hosts in zones.items():
            inspected = await self.inspect_zone(zone_id)
            ruleset_id = str(inspected.get("ruleset_id") or "")
            ref = f"hotpot_{recommendation_id[:20]}_{zone_id[:8]}"
            for row in inspected.get("rules") or []:
                if str(row.get("ref") or "") != ref:
                    continue
                residual.append(
                    {
                        "provider": CUSTOM_WAF_PROVIDER,
                        "zone_id": zone_id,
                        "ruleset_id": ruleset_id,
                        "rule_id": str(row.get("id") or ""),
                        "action": str(row.get("action") or ""),
                        "expression": str(row.get("expression") or ""),
                        "hosts": list(hosts),
                        "ref": ref,
                    }
                )
        return residual

    async def _verify_rules(self, rules: list[dict[str, Any]]) -> None:
        for expected in rules:
            provider = str(expected.get("provider") or CUSTOM_WAF_PROVIDER)
            zone_id = str(expected.get("zone_id") or "")
            if provider == IP_ACCESS_PROVIDER:
                current = await self.inspect_access_rule_for_metadata(expected)
                if current is None:
                    raise CloudflareEnforcementError(
                        "Cloudflare verification could not find an applied IP Access rule"
                    )
                configuration = current.get("configuration") or {}
                if (
                    str(current.get("mode") or "") != "block"
                    or str(configuration.get("value") or "")
                    != str(expected.get("target_value") or "")
                    or not str(current.get("notes") or "").startswith(
                        HOT_POT_ACCESS_NOTES_PREFIX
                    )
                ):
                    raise CloudflareEnforcementError(
                        "Cloudflare verification found a drifted IP Access rule"
                    )
                continue

            if provider == POOL_PROVIDER:
                observed = await self.inspect_pool_rule(
                    zone_id, str(expected.get("ref") or "")
                )
                if observed is None:
                    raise CloudflareEnforcementError(
                        "Cloudflare verification could not find a pooled WAF rule"
                    )
                current, members = observed
                target = str(expected.get("target_value") or "")
                if (
                    target not in members
                    or str(current.get("action") or "")
                    != str(expected.get("action") or "")
                    or current.get("enabled", True) is False
                ):
                    raise CloudflareEnforcementError(
                        "Cloudflare verification found a drifted pooled WAF membership"
                    )
                continue

            inspected = await self.inspect_zone(zone_id)
            current = next(
                (
                    row
                    for row in inspected.get("rules") or []
                    if str(row.get("ref") or "")
                    == str(expected.get("ref") or "")
                ),
                None,
            )
            if current is None:
                raise CloudflareEnforcementError(
                    "Cloudflare verification could not find an applied rule"
                )
            if (
                str(current.get("action") or "")
                != str(expected.get("action") or "")
                or str(current.get("expression") or "")
                != str(expected.get("expression") or "")
                or current.get("enabled", True) is False
            ):
                raise CloudflareEnforcementError(
                    "Cloudflare verification found a drifted applied rule"
                )

    async def _rollback_verified_apply(
        self, rule: dict[str, Any]
    ) -> None:
        provider = str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
        if provider == POOL_PROVIDER:
            if rule.get("membership_added"):
                await super().remove_rule(rule)
            return

        if provider == IP_ACCESS_PROVIDER:
            if not rule.get("reused"):
                await super().remove_rule(rule)
                return
            if not rule.get("expiry_extended"):
                return
            previous = str(rule.get("previous_expires_at") or "")
            if not previous:
                return
            target_kind, normalized = access_target(
                str(rule.get("target_value") or "")
            )
            account_id = str(rule.get("account_id") or "")
            if str(rule.get("scope") or "") == "account" or account_id:
                resource_id = account_id or str(self.config.account_id or "")
                scope = "account"
            else:
                resource_id = str(rule.get("zone_id") or "")
                scope = "zone"
            if not resource_id:
                return
            current = await self.inspect_access_rule_for_metadata(rule)
            if current is None:
                return
            await self._ip_access_request(
                "PATCH",
                f"{self._access_base(scope, resource_id)}/{rule.get('rule_id')}",
                payload={
                    "configuration": {
                        "target": target_kind,
                        "value": normalized,
                    },
                    "mode": "block",
                    "notes": access_notes(previous, normalized),
                },
            )
            return

        if not rule.get("reused"):
            await super().remove_rule(rule)

    async def apply(self, recommendation: dict[str, Any]) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        try:
            rules = await super().apply(recommendation)
            await self._verify_rules(rules)
            return rules
        except Exception as exc:
            for rule in reversed(rules):
                try:
                    await self._rollback_verified_apply(rule)
                except Exception:
                    pass
            residual = await self._residual_rules(recommendation)
            if residual:
                raise CloudflareTransactionError(
                    f"{type(exc).__name__}: {exc}; residual Cloudflare rules require cleanup",
                    residual,
                ) from exc
            raise

    async def remove_rule(self, rule: dict[str, Any]) -> None:
        provider = str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
        await super().remove_rule(rule)

        if provider == IP_ACCESS_PROVIDER:
            current = await self.inspect_access_rule_for_metadata(rule)
            if current is None:
                return
            notes = _parse_access_notes(current.get("notes"))
            remote_expiry = _parse_iso(notes.get("expires")) if notes else None
            stored_expiry = _parse_iso(rule.get("expires_at"))
            if (
                remote_expiry is not None
                and stored_expiry is not None
                and remote_expiry > stored_expiry
            ):
                return
            raise CloudflareEnforcementError(
                "Cloudflare IP Access rule still exists after deletion"
            )

        zone_id = str(rule.get("zone_id") or "")
        if provider == POOL_PROVIDER:
            observed = await self.inspect_pool_rule(
                zone_id, str(rule.get("ref") or "")
            )
            if observed is None:
                return
            _, members = observed
            target = str(rule.get("target_value") or "")
            if target and target not in members:
                return
            raise CloudflareEnforcementError(
                "Cloudflare pooled WAF membership still exists after removal"
            )

        inspected = await self.inspect_zone(zone_id)
        rule_id = str(rule.get("rule_id") or "")
        ref = str(rule.get("ref") or "")
        for current in inspected.get("rules") or []:
            if rule_id and str(current.get("id") or "") == rule_id:
                raise CloudflareEnforcementError(
                    "Cloudflare rule still exists after deletion"
                )
            if ref and str(current.get("ref") or "") == ref:
                raise CloudflareEnforcementError(
                    "Cloudflare rule ref still exists after deletion"
                )

    async def repair(self, recommendation: dict[str, Any]) -> list[dict[str, Any]]:
        persisted_rules = [
            rule
            for rule in recommendation.get("enforcement_rules") or []
            if isinstance(rule, dict)
        ]
        providers = {
            str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
            for rule in persisted_rules
        }

        if not persisted_rules or POOL_PROVIDER in providers:
            rules = await super().apply(recommendation)
            await self._verify_rules(rules)
            return rules

        if IP_ACCESS_PROVIDER in providers:
            account_scoped = any(
                str(rule.get("scope") or "") == "account"
                or bool(str(rule.get("account_id") or ""))
                for rule in persisted_rules
                if str(rule.get("provider") or "") == IP_ACCESS_PROVIDER
            )
            if account_scoped:
                rules = await self._apply_account_ip_access(recommendation)
            else:
                zones = self._targets_for_recommendation(recommendation)
                rules = await self._apply_ip_access(recommendation, zones)
            await self._verify_rules(rules)
            return rules

        # Preserve pre-pool custom-WAF enforcement until it expires. Repairing a
        # legacy record must not silently move it into a shared pool behind the
        # store's persisted ownership metadata.
        target_type = str(recommendation.get("target_type") or "")
        target_value = str(recommendation.get("target_value") or "")
        action = self._rule_action(str(recommendation.get("action") or ""))
        recommendation_id = str(recommendation.get("recommendation_id") or "")
        zones = self._targets_for_recommendation(recommendation)
        for zone_id, hosts in zones.items():
            inspected = await self.inspect_zone(zone_id)
            ref = f"hotpot_{recommendation_id[:20]}_{zone_id[:8]}"
            expression = build_expression(target_type, target_value, hosts)
            for current in inspected.get("rules") or []:
                if str(current.get("ref") or "") != ref:
                    continue
                if (
                    str(current.get("action") or "") == action
                    and str(current.get("expression") or "") == expression
                    and current.get("enabled", True) is not False
                ):
                    break
                await super().remove_rule(
                    {
                        "provider": CUSTOM_WAF_PROVIDER,
                        "zone_id": zone_id,
                        "ruleset_id": str(inspected.get("ruleset_id") or ""),
                        "rule_id": str(current.get("id") or ""),
                        "ref": ref,
                    }
                )
                break

        rules = await self._apply_custom_waf(recommendation, zones)
        await self._verify_rules(rules)
        return rules

