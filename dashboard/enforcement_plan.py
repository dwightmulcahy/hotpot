from __future__ import annotations

from typing import Any

from .cloudflare_enforcement import CloudflareConfig, build_expression


def _cloudflare_action(recommendation_action: str) -> str:
    if recommendation_action == "recommend_challenge":
        return "managed_challenge"
    if recommendation_action in {"recommend_block", "recommend_long_block"}:
        return "block"
    raise ValueError("recommendation is not enforceable")


def build_enforcement_plan(
    recommendation: dict[str, Any], config: CloudflareConfig
) -> dict[str, Any]:
    """Build the exact Cloudflare rule plan without making any API requests."""

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

    zones: list[dict[str, Any]] = []
    for zone_id, host_values in sorted(by_zone.items()):
        hosts = tuple(sorted(host_values))
        expression = build_expression(target_type, target_value, hosts)
        ref = f"hotpot_{recommendation_id[:20]}_{zone_id[:8]}"
        zones.append(
            {
                "zone_id": zone_id,
                "hosts": list(hosts),
                "action": cf_action,
                "expression": expression,
                "ref": ref,
                "expected_effect": (
                    "Cloudflare managed challenge for matching requests"
                    if cf_action == "managed_challenge"
                    else "Cloudflare block for matching requests"
                ),
            }
        )

    return {
        "recommendation_id": recommendation_id,
        "actor_key": recommendation.get("actor_key"),
        "recommendation_action": action,
        "cloudflare_action": cf_action,
        "target_type": target_type,
        "target_value": target_value,
        "duration_hours": recommendation.get("duration_hours"),
        "expires_at": recommendation.get("enforcement_expires_at")
        or recommendation.get("expires_at"),
        "instance_ids": instance_ids,
        "zones": zones,
        "zone_count": len(zones),
        "automatic_enforcement": False,
        "approval_required": True,
        "writes_performed": False,
        "network_calls_performed": False,
        "note": "Simulation only. No Cloudflare rule was created, changed, or removed.",
    }
