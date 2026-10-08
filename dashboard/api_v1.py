from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from aiohttp import web

API_VERSION = 1
API_HEADER = "X-Hotpot-API-Version"
NO_STORE = {"Cache-Control": "no-store", API_HEADER: str(API_VERSION)}


def _normalize(value: Any) -> Any:
    """Normalize v1 identity fields while preserving unknown payload fields."""

    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if not isinstance(value, dict):
        return value

    actor_key = value.get("actor_key") or value.get("identity_key")
    observed_ip = value.get("observed_ip") or value.get("client_ip") or value.get("ip")

    normalized: dict[str, Any] = {}
    for key, item in value.items():
        if key in {"identity_key", "client_ip", "ip"}:
            continue
        normalized[key] = _normalize(item)

    if actor_key not in {None, ""}:
        normalized["actor_key"] = str(actor_key)
    if observed_ip not in {None, ""}:
        normalized["observed_ip"] = str(observed_ip)
    if "source_type" in value:
        normalized["source_type"] = value.get("source_type")
    if "worker_zone" in value:
        normalized["worker_zone"] = value.get("worker_zone")
    return normalized


def _envelope(resource: str, data: Any) -> dict[str, Any]:
    return {
        "schema_version": API_VERSION,
        "resource": resource,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data": _normalize(data),
    }


def _json(resource: str, data: Any, *, status: int = 200) -> web.Response:
    return web.json_response(
        _envelope(resource, data),
        status=status,
        headers=NO_STORE,
    )


def _response_payload(response: web.Response) -> Any:
    text = response.text or ""
    if not text:
        return None
    try:
        return json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return {"message": text}


async def _wrap(
    resource: str,
    handler: Callable[[web.Request], Awaitable[web.Response]],
    request: web.Request,
) -> web.Response:
    response = await handler(request)
    return _json(resource, _response_payload(response), status=response.status)


def _limit(request: web.Request, *, default: int, maximum: int) -> int:
    try:
        return max(1, min(maximum, int(request.query.get("limit", str(default)))))
    except ValueError as exc:
        raise web.HTTPBadRequest(text="limit must be an integer") from exc


async def _legacy_campaign(dashboard: Any, request: web.Request) -> web.Response:
    dashboard.require_auth(request)
    campaign_id = request.match_info.get("campaign_id", "").strip()
    if not campaign_id:
        raise web.HTTPBadRequest(text="campaign_id is required")
    detail = await dashboard.campaigns.campaign(
        campaign_id,
        timeline_limit=_limit(request, default=200, maximum=1000),
    )
    if detail is None:
        raise web.HTTPNotFound(text="campaign not found")
    return web.json_response(detail, headers={"Cache-Control": "no-store"})


async def _v1_campaigns(dashboard: Any, request: web.Request) -> web.Response:
    dashboard.require_auth(request)
    rows = await dashboard.campaigns.analyze(
        limit=_limit(request, default=20, maximum=100)
    )
    return _json(
        "campaign_collection",
        {
            "count": len(rows),
            "campaigns": rows,
            "policy": dashboard.campaigns.public_policy(),
        },
    )


async def _v1_campaign(dashboard: Any, request: web.Request) -> web.Response:
    dashboard.require_auth(request)
    campaign_id = request.match_info.get("campaign_id", "").strip()
    detail = await dashboard.campaigns.campaign(
        campaign_id,
        timeline_limit=_limit(request, default=200, maximum=1000),
    )
    if detail is None:
        raise web.HTTPNotFound(text="campaign not found")
    return _json("campaign", detail)


async def _v1_attacker(dashboard: Any, request: web.Request) -> web.Response:
    dashboard.require_auth(request)
    actor_key = request.match_info.get("actor_key", "").strip()
    if not actor_key:
        raise web.HTTPBadRequest(text="actor_key is required")
    result = await dashboard.store.attacker_snapshot(actor_key)
    if result is None:
        raise web.HTTPNotFound(text="attacker not found")
    dashboard.geoip.reload_if_changed()
    result = dashboard.enrich_attacker(result)
    result["timeline"] = await dashboard.store.attacker_timeline(actor_key)
    result["actor_key"] = actor_key
    return _json("attacker", result)


async def _v1_meta(dashboard: Any, request: web.Request) -> web.Response:
    dashboard.require_auth(request)
    return _json(
        "api_meta",
        {
            "api_version": API_VERSION,
            "identity_fields": {
                "actor_key": "stable scoring/investigation identity",
                "observed_ip": "network address observed for the event or actor",
                "source_type": "identity source such as ip or cloudflare-worker",
                "worker_zone": "Cloudflare Worker upstream zone when applicable",
                "campaign_id": "observational distributed-campaign identity",
            },
            "legacy_api": {
                "status": "supported",
                "note": (
                    "Existing /api/* endpoints remain compatibility shims. "
                    "New integrations should prefer /api/v1/*."
                ),
            },
            "session_bootstrap": "/api/session",
            "campaign_enforcement": "observational-only",
        },
    )


def register_api_routes(app: web.Application, dashboard: Any) -> None:
    """Register campaign investigation plus versioned API compatibility routes."""

    app.router.add_get(
        "/api/campaign/{campaign_id}",
        lambda request: _legacy_campaign(dashboard, request),
    )
    app.router.add_get(
        "/api/v1/meta",
        lambda request: _v1_meta(dashboard, request),
    )
    app.router.add_get(
        "/api/v1/campaigns",
        lambda request: _v1_campaigns(dashboard, request),
    )
    app.router.add_get(
        "/api/v1/campaigns/{campaign_id}",
        lambda request: _v1_campaign(dashboard, request),
    )
    app.router.add_get(
        "/api/v1/attackers/{actor_key}",
        lambda request: _v1_attacker(dashboard, request),
    )

    # Authentication/session bootstrap intentionally stays on /api/session. Wrapping
    # it would discard the Set-Cookie side effect. Versioning applies to data/action
    # resources while preserving the existing secure browser session contract.
    read_routes = (
        ("/api/v1/overview", "overview", dashboard.api_overview),
        ("/api/v1/network", "network", dashboard.api_network),
        (
            "/api/v1/recommendations",
            "recommendation_collection",
            dashboard.api_recommendations,
        ),
        ("/api/v1/recommendation", "recommendation", dashboard.api_recommendation),
        ("/api/v1/audit", "audit_collection", dashboard.api_audit),
        (
            "/api/v1/notifications",
            "notification_collection",
            dashboard.api_notifications,
        ),
        (
            "/api/v1/enforcement/cleanup-jobs",
            "enforcement_cleanup_collection",
            dashboard.api_cleanup_jobs,
        ),
    )
    for path, resource, handler in read_routes:
        app.router.add_get(
            path,
            lambda request, r=resource, h=handler: _wrap(r, h, request),
        )

    write_routes = (
        (
            "/api/v1/notifications/test",
            "notification_test",
            dashboard.api_notification_test,
        ),
        (
            "/api/v1/recommendations/{recommendation_id}/dismiss",
            "recommendation",
            dashboard.api_dismiss_recommendation,
        ),
        (
            "/api/v1/recommendations/{recommendation_id}/approve",
            "recommendation",
            dashboard.api_approve_recommendation,
        ),
        (
            "/api/v1/recommendations/{recommendation_id}/remove",
            "recommendation",
            dashboard.api_remove_enforcement,
        ),
        (
            "/api/v1/recommendations/{recommendation_id}/repair",
            "recommendation",
            dashboard.api_repair_enforcement,
        ),
        (
            "/api/v1/enforcement/orphans/remove",
            "enforcement_orphan_removal",
            dashboard.api_remove_orphan,
        ),
        (
            "/api/v1/enforcement/reconcile",
            "enforcement_reconciliation",
            dashboard.api_reconcile_enforcement,
        ),
        ("/api/v1/system-check", "system_check", dashboard.api_system_check),
    )
    for path, resource, handler in write_routes:
        app.router.add_post(
            path,
            lambda request, r=resource, h=handler: _wrap(r, h, request),
        )
