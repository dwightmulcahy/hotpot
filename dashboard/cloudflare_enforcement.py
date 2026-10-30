from __future__ import annotations

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
from .cloudflare_pool import (
    POOL_PROVIDER,
    POOL_REF_PREFIX,
    PooledWAFMixin,
    pool_expression,
    pool_members,
)


__all__ = [
    "CLOUDFLARE_API_BASE",
    "CUSTOM_RULE_PHASE",
    "CUSTOM_WAF_PROVIDER",
    "HOT_POT_ACCESS_NOTES_PREFIX",
    "IP_ACCESS_PROVIDER",
    "POOL_PROVIDER",
    "CloudflareConfig",
    "CloudflareEnforcementError",
    "CloudflareEnforcer",
    "CloudflareTarget",
    "build_expression",
    "parse_cloudflare_targets",
]


@dataclass(frozen=True)
class CloudflareConfig(_LegacyConfig):
    account_id: str = ""

    @property
    def long_block_ready(self) -> bool:
        return bool(self.configured and self.account_id.strip())

    def public_status(self) -> dict[str, Any]:
        result = super().public_status()
        result["account_id_configured"] = bool(self.account_id.strip())
        result["long_block_ready"] = self.long_block_ready
        result["challenge_provider"] = "Cloudflare pooled zone WAF custom rule"
        result["short_block_provider"] = "Cloudflare pooled zone WAF custom rule"
        result["long_block_provider"] = "Cloudflare account IP Access Rule"
        result["long_block_scope"] = "account"
        result["long_blocks_consume_custom_rule_slots"] = False
        result["pooled_waf_rules_per_zone"] = 2
        return result


class CloudflareEnforcer(PooledWAFMixin, IPAccessMixin, _LegacyEnforcer):
    @staticmethod
    def _uses_ip_access_rule(recommendation: dict[str, Any]) -> bool:
        return (
            str(recommendation.get("action") or "") == "recommend_long_block"
            and str(recommendation.get("target_type") or "") == "ip"
        )

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
        account_id="",
        scope=None,
        shared=False,
    ):
        if scope is None:
            if provider == IP_ACCESS_PROVIDER and account_id:
                scope = "account"
            elif provider == IP_ACCESS_PROVIDER:
                scope = "zone"
            else:
                scope = "configured-hostnames"
        return {
            "provider": provider,
            "zone_id": zone_id,
            "account_id": account_id,
            "scope": scope,
            "ruleset_id": ruleset_id,
            "rule_id": rule_id,
            "action": action,
            "expression": expression,
            "hosts": list(hosts),
            "ref": ref,
            "target_value": target_value,
            "expires_at": expires_at,
            "zone_wide": provider == IP_ACCESS_PROVIDER and scope == "zone",
            "account_wide": provider == IP_ACCESS_PROVIDER and scope == "account",
            "shared": bool(shared or provider == POOL_PROVIDER),
            "pool_action": (
                "recommend_block"
                if provider == POOL_PROVIDER and action == "block"
                else "recommend_challenge"
                if provider == POOL_PROVIDER
                else None
            ),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "reused": reused,
        }

    async def _apply_custom_waf(self, recommendation, zone_hosts):
        return await super().apply(recommendation)

    async def apply(self, recommendation):
        if not self.config.configured:
            raise CloudflareEnforcementError(
                "Cloudflare enforcement is not fully configured"
            )
        if self._uses_ip_access_rule(recommendation):
            return await self._apply_account_ip_access(recommendation)
        if self._uses_pooled_waf(recommendation):
            return await self._apply_pooled_waf(recommendation)
        return await super().apply(recommendation)

    async def remove_rule(self, rule):
        provider = str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
        if provider == IP_ACCESS_PROVIDER:
            await self._remove_ip_access(rule)
            return
        if provider == POOL_PROVIDER:
            await self._remove_pool_membership(rule)
            return
        await super().remove_rule(rule)

    async def _reconcile_pooled(
        self,
        recommendations: list[dict[str, Any]],
        *,
        results: list[dict[str, Any]],
        errors: list[dict[str, Any]],
        orphans: list[dict[str, Any]],
    ) -> set[str]:
        status_rank = {"healthy": 0, "drifted": 1, "missing": 2, "error": 3}
        expected: dict[
            tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]
        ] = {}
        result_by_id: dict[str, dict[str, Any]] = {}

        for recommendation in recommendations:
            recommendation_id = str(
                recommendation.get("recommendation_id") or ""
            )
            result = {
                "recommendation_id": recommendation_id,
                "actor_key": recommendation.get("actor_key"),
                "status": "healthy",
                "rules": [],
            }
            result_by_id[recommendation_id] = result
            for rule in recommendation.get("enforcement_rules") or []:
                if (
                    not isinstance(rule, dict)
                    or str(rule.get("provider") or "") != POOL_PROVIDER
                ):
                    continue
                key = (
                    str(rule.get("zone_id") or ""),
                    str(rule.get("ref") or ""),
                )
                expected.setdefault(key, []).append((recommendation, rule))

        zones = {
            target.zone_id
            for target in self.config.targets.values()
            if target.zone_id
        } | {zone_id for zone_id, _ in expected if zone_id}
        observed_by_key: dict[tuple[str, str], tuple[dict[str, Any], set[str], str]] = {}

        for zone_id in sorted(zones):
            try:
                inspected = await self.inspect_zone(zone_id)
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                errors.append(
                    {
                        "zone_id": zone_id,
                        "provider": POOL_PROVIDER,
                        "error": detail,
                    }
                )
                for (expected_zone, _), entries in expected.items():
                    if expected_zone != zone_id:
                        continue
                    for recommendation, rule in entries:
                        result = result_by_id[
                            str(recommendation.get("recommendation_id") or "")
                        ]
                        result["status"] = "error"
                        result["rules"].append(
                            {
                                "provider": POOL_PROVIDER,
                                "zone_id": zone_id,
                                "ref": rule.get("ref"),
                                "status": "error",
                                "detail": detail,
                            }
                        )
                continue

            ruleset_id = str(inspected.get("ruleset_id") or "")
            for current in inspected.get("rules") or []:
                ref = str(current.get("ref") or "")
                if not ref.startswith(POOL_REF_PREFIX):
                    continue
                try:
                    members = pool_members(current.get("expression"))
                except Exception as exc:
                    detail = f"{type(exc).__name__}: {exc}"
                    errors.append(
                        {
                            "zone_id": zone_id,
                            "provider": POOL_PROVIDER,
                            "ref": ref,
                            "error": detail,
                        }
                    )
                    continue
                observed_by_key[(zone_id, ref)] = (current, members, ruleset_id)

        for key, entries in expected.items():
            zone_id, ref = key
            observed = observed_by_key.get(key)
            expected_targets = {
                str(rule.get("target_value") or "")
                for _, rule in entries
                if str(rule.get("target_value") or "")
            }
            if observed is None:
                for recommendation, rule in entries:
                    result = result_by_id[
                        str(recommendation.get("recommendation_id") or "")
                    ]
                    result["status"] = "missing"
                    result["rules"].append(
                        {
                            "provider": POOL_PROVIDER,
                            "zone_id": zone_id,
                            "ref": ref,
                            "status": "missing",
                            "detail": "expected Hotpot pooled WAF rule was not found",
                        }
                    )
                continue

            current, members, ruleset_id = observed
            host_expression = None
            try:
                host_expression = pool_expression(
                    members, self._all_hosts_for_zone(zone_id)
                )
            except Exception:
                host_expression = None

            for recommendation, rule in entries:
                recommendation_id = str(
                    recommendation.get("recommendation_id") or ""
                )
                result = result_by_id[recommendation_id]
                differences: list[str] = []
                target = str(rule.get("target_value") or "")
                if target not in members:
                    result["status"] = "missing"
                    result["rules"].append(
                        {
                            "provider": POOL_PROVIDER,
                            "zone_id": zone_id,
                            "ref": ref,
                            "status": "missing",
                            "detail": "IP is missing from the pooled WAF rule",
                        }
                    )
                    continue
                if (
                    rule.get("rule_id")
                    and str(current.get("id") or "")
                    != str(rule.get("rule_id") or "")
                ):
                    differences.append("shared rule id changed")
                if (
                    rule.get("ruleset_id")
                    and ruleset_id != str(rule.get("ruleset_id") or "")
                ):
                    differences.append("ruleset id changed")
                if (
                    rule.get("action")
                    and str(current.get("action") or "")
                    != str(rule.get("action") or "")
                ):
                    differences.append("action changed")
                if current.get("enabled") is False:
                    differences.append("rule disabled")
                if (
                    host_expression is not None
                    and str(current.get("expression") or "") != host_expression
                ):
                    differences.append("pooled expression or hostname scope changed")
                status = "drifted" if differences else "healthy"
                if status_rank[status] > status_rank[result["status"]]:
                    result["status"] = status
                result["rules"].append(
                    {
                        "provider": POOL_PROVIDER,
                        "zone_id": zone_id,
                        "ref": ref,
                        "expected_rule_id": rule.get("rule_id"),
                        "status": status,
                        "detail": (
                            "; ".join(differences)
                            if differences
                            else "IP is present in the shared Hotpot WAF pool"
                        ),
                    }
                )

            extras = members - expected_targets
            for target in sorted(extras):
                orphans.append(
                    {
                        "provider": POOL_PROVIDER,
                        "zone_id": zone_id,
                        "ruleset_id": ruleset_id,
                        "rule_id": current.get("id"),
                        "ref": ref,
                        "action": current.get("action"),
                        "expression": current.get("expression"),
                        "target_value": target,
                        "scope": "configured-hostnames",
                        "shared": True,
                        "description": (
                            "Hotpot pooled WAF member has no applied recommendation"
                        ),
                    }
                )

        for key, observed in observed_by_key.items():
            if key in expected:
                continue
            zone_id, ref = key
            current, members, ruleset_id = observed
            if members:
                for target in sorted(members):
                    orphans.append(
                        {
                            "provider": POOL_PROVIDER,
                            "zone_id": zone_id,
                            "ruleset_id": ruleset_id,
                            "rule_id": current.get("id"),
                            "ref": ref,
                            "action": current.get("action"),
                            "expression": current.get("expression"),
                            "target_value": target,
                            "scope": "configured-hostnames",
                            "shared": True,
                            "description": "Untracked Hotpot pooled WAF member",
                        }
                    )
            else:
                orphans.append(
                    {
                        "provider": POOL_PROVIDER,
                        "zone_id": zone_id,
                        "ruleset_id": ruleset_id,
                        "rule_id": current.get("id"),
                        "ref": ref,
                        "action": current.get("action"),
                        "expression": current.get("expression"),
                        "target_value": None,
                        "scope": "configured-hostnames",
                        "shared": True,
                        "description": "Empty untracked Hotpot pooled WAF rule",
                    }
                )

        results.extend(result_by_id.values())
        return zones

    async def _reconcile_access(
        self,
        recommendations: list[dict[str, Any]],
        *,
        results: list[dict[str, Any]],
        errors: list[dict[str, Any]],
    ) -> None:
        for recommendation in recommendations:
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
                account_id = str(expected.get("account_id") or "")
                try:
                    observed = await self.inspect_access_rule_for_metadata(expected)
                except Exception as exc:
                    result["status"] = "error"
                    detail = f"{type(exc).__name__}: {exc}"
                    errors.append(
                        {
                            "zone_id": zone_id or None,
                            "account_id": account_id or None,
                            "provider": IP_ACCESS_PROVIDER,
                            "error": detail,
                        }
                    )
                    result["rules"].append(
                        {
                            "provider": IP_ACCESS_PROVIDER,
                            "zone_id": zone_id or None,
                            "account_id": account_id or None,
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
                            "zone_id": zone_id or None,
                            "account_id": account_id or None,
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
                        "zone_id": zone_id or None,
                        "account_id": account_id or None,
                        "status": status,
                        "detail": (
                            "; ".join(differences)
                            if differences
                            else "matches persisted Hotpot IP Access rule"
                        ),
                    }
                )
            results.append(result)

    async def reconcile(self, recommendations):
        legacy_custom: list[dict[str, Any]] = []
        pooled: list[dict[str, Any]] = []
        access: list[dict[str, Any]] = []
        for recommendation in recommendations:
            rules = [
                rule
                for rule in recommendation.get("enforcement_rules") or []
                if isinstance(rule, dict)
            ]
            providers = {
                str(rule.get("provider") or CUSTOM_WAF_PROVIDER)
                for rule in rules
            }
            if IP_ACCESS_PROVIDER in providers:
                access.append(recommendation)
            elif POOL_PROVIDER in providers:
                pooled.append(recommendation)
            else:
                legacy_custom.append(recommendation)

        base = await super().reconcile(legacy_custom)
        results = list(base.get("recommendations") or [])
        errors = list(base.get("zone_errors") or [])
        orphans = list(base.get("orphans") or [])

        pooled_zones = await self._reconcile_pooled(
            pooled, results=results, errors=errors, orphans=orphans
        )
        await self._reconcile_access(access, results=results, errors=errors)

        counts = {
            status: sum(1 for row in results if row.get("status") == status)
            for status in ("healthy", "drifted", "missing", "error")
        }
        overall = (
            "error"
            if errors or counts["error"]
            else "drifted"
            if counts["missing"] or counts["drifted"] or orphans
            else "healthy"
        )
        return {
            **base,
            "status": overall,
            "recommendations": results,
            "counts": counts,
            "zone_errors": errors,
            "orphans": orphans,
            "orphaned": len(orphans),
            "zones_checked": max(
                int(base.get("zones_checked") or 0), len(pooled_zones)
            ),
        }
