from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .cloudflare_enforcement_legacy import (
    CLOUDFLARE_API_BASE,
    CUSTOM_RULE_PHASE,
    CloudflareConfig as _LegacyConfig,
    CloudflareEnforcementError,
    CloudflareEnforcer as _LegacyEnforcer,
    CloudflareTarget,
    build_expression,
    parse_cloudflare_targets,
)
from .cloudflare_ip_access import (
    CUSTOM_WAF_PROVIDER,
    HOT_POT_ACCESS_NOTES_PREFIX,
    IP_ACCESS_PROVIDER,
    IPAccessMixin,
    parse_access_notes as _parse_access_notes,
    parse_iso as _parse_iso,
)


__all__ = [
    "CLOUDFLARE_API_BASE",
    "CUSTOM_RULE_PHASE",
    "CUSTOM_WAF_PROVIDER",
    "HOT_POT_ACCESS_NOTES_PREFIX",
    "IP_ACCESS_PROVIDER",
    "CloudflareConfig",
    "CloudflareEnforcementError",
    "CloudflareEnforcer",
    "CloudflareTarget",
    "build_expression",
    "parse_cloudflare_targets",
]


@dataclass(frozen=True)
class CloudflareConfig(_LegacyConfig):
    def public_status(self) -> dict[str, Any]:
        result = super().public_status()
        result["long_block_provider"] = "Cloudflare zone WAF custom rule"
        result["long_blocks_consume_custom_rule_slots"] = True
        return result


class CloudflareEnforcer(IPAccessMixin, _LegacyEnforcer):
    def _expression_for_recommendation(
        self, recommendation: dict[str, Any], hosts: tuple[str, ...]
    ) -> str:
        if (
            str(recommendation.get("action") or "") == "recommend_long_block"
            and str(recommendation.get("target_type") or "") == "ip"
        ):
            try:
                address = ipaddress.ip_address(
                    str(recommendation.get("target_value") or "")
                )
            except ValueError as exc:
                raise CloudflareEnforcementError(
                    "invalid IP enforcement target"
                ) from exc
            return f"ip.src eq {address.compressed}"
        return super()._expression_for_recommendation(recommendation, hosts)

    @staticmethod
    def _stored_rule(
        *,
        zone_id,
        ruleset_id,
        rule_id,
        action,
        expression,
        hosts,
        ref,
        reused,
        provider=CUSTOM_WAF_PROVIDER,
        target_value=None,
        expires_at=None,
    ):
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
            "zone_wide": (
                provider == IP_ACCESS_PROVIDER
                or (
                    provider == CUSTOM_WAF_PROVIDER
                    and str(expression).startswith("ip.src eq ")
                    and "http.host" not in str(expression)
                )
            ),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reused": reused,
        }

    async def apply(self, recommendation):
        # New long blocks deliberately use the same zone Rulesets/WAF path as
        # challenges and 24-hour blocks. Legacy IP Access rules remain supported
        # below for reconciliation and removal of already-persisted enforcement.
        return await super().apply(recommendation)

    async def remove_rule(self, rule):
        if str(rule.get("provider") or CUSTOM_WAF_PROVIDER) == IP_ACCESS_PROVIDER:
            await self._remove_ip_access(rule)
            return
        await super().remove_rule(rule)

    async def reconcile(self, recommendations):
        custom, access = [], []
        for recommendation in recommendations:
            rules = [
                rule
                for rule in recommendation.get("enforcement_rules") or []
                if isinstance(rule, dict)
            ]
            if any(
                str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
                == IP_ACCESS_PROVIDER
                for rule in rules
            ):
                access.append(recommendation)
            else:
                custom.append(recommendation)

        if custom or not access:
            base = await super().reconcile(custom)
        else:
            base = {
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "status": "healthy",
                "recommendations": [],
                "counts": {
                    "healthy": 0,
                    "drifted": 0,
                    "missing": 0,
                    "error": 0,
                },
                "orphans": [],
                "orphaned": 0,
                "zone_errors": [],
                "zones_checked": 0,
            }

        results = list(base.get("recommendations") or [])
        errors = list(base.get("zone_errors") or [])
        zones = set()
        for recommendation in access:
            result = {
                "recommendation_id": recommendation.get("recommendation_id"),
                "actor_key": recommendation.get("actor_key"),
                "status": "healthy",
                "rules": [],
            }
            for expected in recommendation.get("enforcement_rules") or []:
                if (
                    not isinstance(expected, dict)
                    or str(expected.get("provider") or CUSTOM_WAF_PROVIDER)
                    != IP_ACCESS_PROVIDER
                ):
                    continue
                zone_id = str(expected.get("zone_id") or "")
                zones.add(zone_id)
                try:
                    observed = await self.inspect_access_rule(
                        zone_id, str(expected.get("rule_id") or "")
                    )
                except Exception as exc:
                    result["status"] = "error"
                    detail = f"{type(exc).__name__}: {exc}"
                    errors.append(
                        {
                            "zone_id": zone_id,
                            "provider": IP_ACCESS_PROVIDER,
                            "error": detail,
                        }
                    )
                    result["rules"].append(
                        {
                            "provider": IP_ACCESS_PROVIDER,
                            "zone_id": zone_id,
                            "status": "error",
                            "detail": detail,
                        }
                    )
                    continue
                if observed is None:
                    result["status"] = "missing"
                    result["rules"].append(
                        {
                            "provider": IP_ACCESS_PROVIDER,
                            "zone_id": zone_id,
                            "status": "missing",
                            "detail": "expected Hotpot IP Access rule was not found",
                        }
                    )
                    continue
                differences = []
                if str(observed.get("mode") or "") != "block":
                    differences.append("mode changed")
                current_target = str(
                    (observed.get("configuration") or {}).get("value") or ""
                )
                if (
                    str(expected.get("target_value") or "")
                    and current_target != str(expected.get("target_value") or "")
                ):
                    differences.append("target changed")
                notes = _parse_access_notes(observed.get("notes"))
                if not notes:
                    differences.append("Hotpot ownership marker missing")
                remote = _parse_iso(notes.get("expires"))
                wanted = _parse_iso(expected.get("expires_at"))
                if remote and wanted and remote < wanted:
                    differences.append("expiry shortened")
                status = "drifted" if differences else "healthy"
                if differences and result["status"] == "healthy":
                    result["status"] = "drifted"
                result["rules"].append(
                    {
                        "provider": IP_ACCESS_PROVIDER,
                        "zone_id": zone_id,
                        "status": status,
                        "detail": "; ".join(differences)
                        if differences
                        else "matches persisted Hotpot IP Access rule",
                    }
                )
            results.append(result)

        counts = {
            status: sum(1 for row in results if row.get("status") == status)
            for status in ("healthy", "drifted", "missing", "error")
        }
        overall = (
            "error"
            if errors or counts["error"]
            else "drifted"
            if counts["missing"] or counts["drifted"] or base.get("orphans")
            else "healthy"
        )
        return {
            **base,
            "status": overall,
            "recommendations": results,
            "counts": counts,
            "zone_errors": errors,
            "zones_checked": int(base.get("zones_checked") or 0) + len(zones),
        }
