from __future__ import annotations

from typing import Any

from .cloudflare_enforcement import (
    IP_ACCESS_PROVIDER,
    POOL_PROVIDER,
    CloudflareConfig,
    build_expression,
)
from .cloudflare_ip_access import access_target
from .cloudflare_pool import pool_definition, pool_expression


def _cloudflare_action(recommendation_action: str) -> str:
    if recommendation_action == "recommend_challenge":
        return "managed_challenge"
    if recommendation_action in {"recommend_block", "recommend_long_block"}:
        return "block"
    raise ValueError("recommendation is not enforceable")


def build_enforcement_plan(
    recommendation: dict[str, Any], config: CloudflareConfig
) -> dict[str, Any]:
    """Build the exact Cloudflare enforcement plan without making API requests."""

    recommendation_id = str(recommendation.get("recommendation_id") or "").strip()
    if not recommendation_id:
        raise ValueError("recommendation id is missing")
    action = str(recommendation.get("action") or "")
    cf_action = _cloudflare_action(action)
    target_type = str(recommendation.get("target_type") or "")
    target_value = str(recommendation.get("target_value") or "")
    evidence = recommendation.get("evidence") or {}
    instance_ids = sorted(
        {str(value) for value in evidence.get("instance_ids") or [] if str(value)}
    )
    if not instance_ids:
        raise ValueError("recommendation does not include target instance ids")

    missing = [value for value in instance_ids if value not in config.targets]
    if missing:
        raise ValueError("missing Cloudflare target mapping for: " + ", ".join(missing))

    by_zone: dict[str, set[str]] = {}
    for instance_id in instance_ids:
        target = config.targets[instance_id]
        by_zone.setdefault(target.zone_id, set()).update(target.hosts)

    long_ip = action == "recommend_long_block" and target_type == "ip"
    pooled_ip = (
        action in {"recommend_challenge", "recommend_block"}
        and target_type == "ip"
    )

    if long_ip:
        account_id = str(config.account_id or "").strip()
        if not account_id:
            raise ValueError(
                "HOTPOT_CLOUDFLARE_ACCOUNT_ID is required for account-wide long blocks"
            )
        _, normalized = access_target(target_value)
        all_hosts = sorted(
            {
                host
                for configured in config.targets.values()
                for host in configured.hosts
            }
        )
        zones = [
            {
                "zone_id": None,
                "account_id": account_id,
                "hosts": all_hosts,
                "action": "block",
                "provider": IP_ACCESS_PROVIDER,
                "scope": "account",
                "expression": f"ip.src eq {normalized}",
                "ref": None,
                "expected_effect": (
                    "Cloudflare account-wide IP Access block across every zone "
                    "in the configured Cloudflare account"
                ),
            }
        ]
        provider = IP_ACCESS_PROVIDER
    else:
        zones = []
        for zone_id, host_values in sorted(by_zone.items()):
            if pooled_ip:
                all_zone_hosts = tuple(
                    sorted(
                        {
                            host
                            for configured in config.targets.values()
                            if configured.zone_id == zone_id
                            for host in configured.hosts
                        }
                    )
                )
                _, normalized = access_target(target_value)
                _, ref = pool_definition(action)
                expression = pool_expression({normalized}, all_zone_hosts)
                zones.append(
                    {
                        "zone_id": zone_id,
                        "account_id": None,
                        "hosts": list(all_zone_hosts),
                        "action": cf_action,
                        "provider": POOL_PROVIDER,
                        "scope": "configured-hostnames",
                        "expression": expression,
                        "ref": ref,
                        "shared_rule": True,
                        "expected_effect": (
                            "Add this IP to Hotpot's shared per-zone "
                            + (
                                "managed-challenge"
                                if action == "recommend_challenge"
                                else "24-hour block"
                            )
                            + " WAF pool"
                        ),
                    }
                )
                continue

            hosts = tuple(sorted(host_values))
            expression = build_expression(target_type, target_value, hosts)
            ref = f"hotpot_{recommendation_id[:20]}_{zone_id[:8]}"
            zones.append(
                {
                    "zone_id": zone_id,
                    "account_id": None,
                    "hosts": list(hosts),
                    "action": cf_action,
                    "provider": "custom_waf",
                    "scope": "configured-hostnames",
                    "expression": expression,
                    "ref": ref,
                    "shared_rule": False,
                    "expected_effect": (
                        "Cloudflare managed challenge for matching requests"
                        if cf_action == "managed_challenge"
                        else "Cloudflare block for matching requests"
                    ),
                }
            )
        provider = POOL_PROVIDER if pooled_ip else "custom_waf"

    return {
        "recommendation_id": recommendation_id,
        "actor_key": recommendation.get("actor_key"),
        "recommendation_action": action,
        "cloudflare_action": cf_action,
        "provider": provider,
        "target_type": target_type,
        "target_value": target_value,
        "duration_hours": recommendation.get("duration_hours"),
        "expires_at": recommendation.get("enforcement_expires_at")
        or recommendation.get("expires_at"),
        "instance_ids": instance_ids,
        "zones": zones,
        "zone_count": len(by_zone),
        "account_wide": long_ip,
        "automatic_enforcement": False,
        "approval_required": True,
        "writes_performed": False,
        "network_calls_performed": False,
        "note": "Simulation only. No Cloudflare rule was created, changed, or removed.",
    }
