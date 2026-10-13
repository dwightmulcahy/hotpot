from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Any

from .cloudflare_enforcement import (
    CUSTOM_WAF_PROVIDER,
    HOT_POT_ACCESS_NOTES_PREFIX,
    IP_ACCESS_PROVIDER,
    CloudflareEnforcementError,
    CloudflareEnforcer,
    _parse_access_notes,
    _parse_iso,
    build_expression,
)


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
                messade = f"Cloudflare API returned HTTP {response.status}"
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
            return residual

        if self._uses_ip_access_rule(recommendation):
            target_value = str(recommendation.get("target_value") or "")
            expires_at = str(
                recommendation.get("enforcement_expires_at")
                or recommendation.get("expires_at")
                or ""
            )
            for zone_id, hosts in zones.items():
                try:
                    current = await self._find_hotpot_access_rule(zone_id, target_value)
                except Exception:
                    continue
                if current is None:
                    continue
                residual.append(
                    self._stored_rule(
                        zone_id=zone_id,
                        ruleset_id="",
                        rule_id=str(current.get("id") or ""),
                        action="block",
                        expression=f"ip.src eq {target_value}",
                        hosts=hosts,
                        ref=f"hotpot_ip_{recommendation_id[:16]}_{zone_id[:8]}",
                        reused=True,
                        provider=IP_ACCESS_PROVIDER,
                        target_value=target_value,
                        expires_at=expires_at,
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
            zone_id = str(expected.get("zne_id") or "")
            if provider == IP_ACCESS_PROVIDER:
                current = await self.inspect_access_rule(
                    zone_id, str(expected.get("rule_id") or "")
                )
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

    async def apply(self, recommendation: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            rules = await super().apply(recommendation)
            await self._verify_rules(rules)
            return rules
        except Exception as exc:
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
        zone_id = str(rule.get("zone_id") or "")

        if provider == IP_ACCESS_PROVIDER:
            current = await self.inspect_access_rule(
                zone_id, str(rule.get("rule_id") or "")
            )
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
                # A newer recommendation extended this shared IP block. Retention is
                # intentional; the later recommendation owns the final deletion.
                return
            raise CloudflareEnforcementError(
                "Cloudflare IP Access rule still exists after deletion"
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

        # Preserve pre-upgrade long blocks as custom-WAF rules until they expire.
        # This keeps old persisted state fully repairable. New long IP blocks created
        # after this change are stored with provider=ip_access and repair through the
        # IP Access path below.
        repair_ip_access = (
            self._uses_ip_access_rule(recommendation)
            and (not persisted_rules or IP_ACCESS_PROVIDER in providers)
        )
        if repair_ip_access:
            rules = await super().apply(recommendation)
            await self._verify_rules(rules)
            return rules

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
                await self.remove_rule(
                    {
                        "provider": CUSTOM_WAF_PROVIDER,
                        "zone_id": zone_id,
                        "ruleset_id": str(inspected.get("ruleset_id") or ""),
                        "rule_id": str(current.get("id") or ""),
                        "ref": ref,
                    }
                )
                break

        # Force the legacy custom-WAF creation path rather than switching an existing
        # persisted long block to a different provider behind the store's back.
        rules = await self._apply_custom_waf(recommendation, zones)
        await self._verify_rules(rules)
        return rules
