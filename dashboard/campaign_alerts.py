from __future__ import annotations

from typing import Any


async def process_campaign_notifications(
    dashboard: Any, campaigns: list[dict[str, Any]]
) -> dict[str, int]:
    """Queue meaningful campaign alerts without changing enforcement decisions.

    Campaign alerts are deduplicated by campaign ID and severity band. A warning can
    therefore later escalate to one critical alert, but repeated dashboard refreshes
    do not resend the same campaign state. Campaigns remain observational: this
    function never creates or approves a response recommendation.
    """

    client = getattr(dashboard, "client", None)
    store = getattr(dashboard, "store", None)
    notifications = getattr(dashboard, "notifications", None)
    config = getattr(dashboard, "notification_config", None)
    if client is None or store is None or notifications is None or config is None:
        return {"considered": 0, "queued": 0, "delivered": 0}

    considered = 0
    queued = 0
    for campaign in campaigns:
        severity = str(campaign.get("notification_severity") or "").lower()
        if severity not in {"warning", "critical"}:
            continue
        campaign_id = str(campaign.get("campaign_id") or "").strip()
        if not campaign_id:
            continue
        considered += 1
        actors = int(campaign.get("actor_count", 0) or 0)
        hits = int(campaign.get("hits", 0) or 0)
        apps = int(campaign.get("app_count", 0) or 0)
        level = int(campaign.get("max_level", 1) or 1)
        label = str(campaign.get("label") or campaign_id)
        categories = [str(v) for v in campaign.get("categories") or []]
        scanners = [str(v) for v in campaign.get("scanners") or []]
        top_paths = [
            str(item.get("path") or "")
            for item in campaign.get("top_paths") or []
            if isinstance(item, dict) and item.get("path")
        ][:5]

        _, created = await store.queue_notification(
            event_key=f"campaign:{campaign_id}:{severity}",
            event_type="attack_campaign_detected",
            severity=severity,
            subject=(
                f"Distributed attack campaign: {label}"
                if severity == "critical"
                else f"Distributed scan campaign: {label}"
            ),
            message=(
                f"Hotpot correlated {hits} hit(s) from {actors} actor(s) across "
                f"{apps} app(s), reaching level {level}. Campaign correlation is "
                "observational and did not automatically change scoring or enforcement."
            ),
            channels=list(config.channels),
            payload={
                "campaign_id": campaign_id,
                "label": label,
                "actor_count": actors,
                "source_ip_count": int(campaign.get("source_ip_count", 0) or 0),
                "hits": hits,
                "app_count": apps,
                "apps": list(campaign.get("apps") or []),
                "categories": categories,
                "scanners": scanners,
                "top_paths": top_paths,
                "first_seen": campaign.get("first_seen"),
                "last_seen": campaign.get("last_seen"),
                "max_level": level,
                "max_severity": int(campaign.get("max_severity", 1) or 1),
                "scoring_effect": "none",
                "automatic_enforcement": False,
            },
        )
        queued += int(created)

    delivered = await notifications.deliver_due(client)
    return {"considered": considered, "queued": queued, "delivered": delivered}
