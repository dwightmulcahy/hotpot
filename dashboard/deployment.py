from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backups import DashboardBackupManager
from .preflight import run_preflight


DEPLOYMENT_REPORT_SCHEMA_VERSION = 1
DEFAULT_COMPOSE_FILE = "/share/Data/config/cloudflared/docker-compose.yml"
DEFAULT_SERVICES = (
    "hotpot-monkeyhead",
    "hotpot-watersolver",
    "hotpot-hvac",
    "hotpot-tapmenu",
    "hotpot-dashboard",
)


def _known(value: Any) -> bool:
    return str(value or "").strip().lower() not in {"", "unknown", "dev", "none"}


def _fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _csv(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    return values or default


def dashboard_build_identity() -> dict[str, str]:
    return {
        "version": os.getenv("HOTPOT_VERSION", "dev").strip() or "dev",
        "git_sha": os.getenv("HOTPOT_GIT_SHA", "unknown").strip() or "unknown",
        "build_date": os.getenv("HOTPOT_BUILD_DATE", "unknown").strip() or "unknown",
    }


def dashboard_config_fingerprint(dashboard: Any) -> str:
    payload = {
        "instances": [
            {"id": item.instance_id, "name": item.name, "url": item.url}
            for item in dashboard.instances
        ],
        "refresh_seconds": int(getattr(dashboard, "refresh_seconds", 0) or 0),
        "timeout": float(getattr(dashboard, "timeout", 0) or 0),
        "max_pages": int(getattr(dashboard, "max_pages", 0) or 0),
        "policy_reconcile_seconds": int(
            getattr(getattr(dashboard, "policy_manager", None), "reconcile_seconds", 0)
            or 0
        ),
        "cloudflare_enabled": bool(
            getattr(getattr(dashboard, "cloudflare", None), "enabled", False)
        ),
        "notifications_enabled": bool(
            getattr(getattr(dashboard, "notification_config", None), "enabled", False)
        ),
    }
    return _fingerprint(payload)


def _check(check_id: str, status: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "status": status, "detail": detail}


def _status_for_bool(
    value: bool | None, *, unknown: str = "warning"
) -> str:
    if value is True:
        return "pass"
    if value is False:
        return "fail"
    return unknown


def _upgrade_plan(build: dict[str, str]) -> dict[str, Any]:
    compose_file = (
        os.getenv("HOTPOT_DASHBOARD_COMPOSE_FILE", DEFAULT_COMPOSE_FILE).strip()
        or DEFAULT_COMPOSE_FILE
    )
    target_tag = os.getenv("HOTPOT_DASHBOARD_DEPLOY_TAG", "latest").strip() or "latest"
    services = _csv("HOTPOT_DASHBOARD_DEPLOY_SERVICES", DEFAULT_SERVICES)
    quoted_file = shlex.quote(compose_file)
    quoted_tag = shlex.quote(target_tag)
    quoted_services = " ".join(shlex.quote(item) for item in services)
    core_services = tuple(item for item in services if item != "hotpot-dashboard")
    steps = [
        {
            "id": "validate",
            "label": "Validate Compose",
            "command": f"docker compose -f {quoted_file} config -q",
        },
        {
            "id": "pull",
            "label": f"Pull Hotpot {target_tag}",
            "command": (
                f"HOTPOT_IMAGE_TAG={quoted_tag} docker compose -f {quoted_file} "
                f"pull {quoted_services}"
            ),
        },
    ]
    for service in core_services:
        steps.append(
            {
                "id": f"recreate-{service}",
                "label": f"Recreate {service}",
                "command": (
                    f"HOTPOT_IMAGE_TAG={quoted_tag} docker compose -f {quoted_file} "
                    f"up -d --no-deps --force-recreate {shlex.quote(service)}"
                ),
            }
        )
    if "hotpot-dashboard" in services:
        steps.append(
            {
                "id": "recreate-dashboard",
                "label": "Recreate dashboard last",
                "command": (
                    f"HOTPOT_IMAGE_TAG={quoted_tag} docker compose -f {quoted_file} "
                    "up -d --no-deps --force-recreate hotpot-dashboard"
                ),
            }
        )
    steps.append(
        {
            "id": "verify",
            "label": "Verify all health endpoints",
            "command": (
                "curl -fsS http://127.0.0.1:18088/_hotpot/health && "
                "curl -fsS http://127.0.0.1:12120/_hotpot/health && "
                "curl -fsS http://127.0.0.1:18080/_hotpot/health && "
                "curl -fsS http://127.0.0.1:18111/_hotpot/health && "
                "curl -fsS http://127.0.0.1:19090/health"
            ),
        }
    )
    return {
        "compose_file": compose_file,
        "target_tag": target_tag,
        "mutable_tag": target_tag == "latest",
        "services": list(services),
        "current_dashboard_build": build,
        "steps": steps,
    }


async def _fetch_instance(dashboard: Any, instance: Any) -> dict[str, Any]:
    try:
        status = await dashboard.fetch_json(f"{instance.url}/_hotpot/status")
    except Exception as exc:
        return {
            "id": instance.instance_id,
            "name": instance.name,
            "url": instance.url,
            "reachable": False,
            "healthy": False,
            "error": f"{type(exc).__name__}: {exc}",
            "identity_ok": False,
            "version": "unknown",
            "git_sha": "unknown",
            "build_date": "unknown",
            "config_fingerprint": None,
            "shared_config_fingerprint": None,
            "policy_revision": None,
            "admin_token_source": "unknown",
        }

    deployment = status.get("deployment") if isinstance(status, dict) else None
    if not isinstance(deployment, dict):
        deployment = {}
    remote_id = str(
        deployment.get("instance_id") or status.get("instance_id") or ""
    ).strip()
    remote_name = str(
        deployment.get("instance_name") or status.get("instance_name") or ""
    ).strip()
    secret_sources = deployment.get("secret_sources")
    if not isinstance(secret_sources, dict):
        secret_sources = {}
    policy = status.get("policy")
    if not isinstance(policy, dict):
        policy = {}
    upstream_health = status.get("upstream_health")
    if not isinstance(upstream_health, dict):
        upstream_health = {}
    return {
        "id": instance.instance_id,
        "name": instance.name,
        "url": instance.url,
        "reachable": True,
        "healthy": bool(status.get("healthy", False)),
        "upstream_healthy": bool(upstream_health.get("healthy", False)),
        "error": None,
        "remote_instance_id": remote_id or None,
        "remote_instance_name": remote_name or None,
        "identity_ok": remote_id == instance.instance_id,
        "version": str(deployment.get("version") or status.get("version") or "unknown"),
        "git_sha": str(deployment.get("git_sha") or status.get("git_sha") or "unknown"),
        "build_date": str(
            deployment.get("build_date") or status.get("build_date") or "unknown"
        ),
        "config_fingerprint": deployment.get("config_fingerprint")
        or status.get("config_fingerprint"),
        "shared_config_fingerprint": deployment.get("shared_config_fingerprint")
        or status.get("shared_config_fingerprint"),
        "policy_revision": deployment.get("policy_revision")
        or policy.get("revision"),
        "policy_updated_at": deployment.get("policy_updated_at")
        or policy.get("updated_at"),
        "admin_token_source": str(secret_sources.get("admin_token") or "unknown"),
        "config": deployment.get("config") if isinstance(deployment.get("config"), dict) else {},
    }


async def collect_deployment_report(dashboard: Any) -> dict[str, Any]:
    build = dashboard_build_identity()
    instances = await asyncio.gather(
        *(_fetch_instance(dashboard, instance) for instance in dashboard.instances)
    )

    manager = getattr(dashboard, "policy_manager", None)
    if manager is not None:
        try:
            policy_sync = await manager.sync_status()
        except Exception as exc:
            policy_sync = {"instances": [], "in_sync": False, "error": f"{type(exc).__name__}: {exc}"}
    else:
        policy_sync = {"instances": [], "in_sync": None}
    sync_by_id = {
        str(item.get("instance_id") or ""): item
        for item in policy_sync.get("instances", [])
        if isinstance(item, dict)
    }
    for row in instances:
        sync = sync_by_id.get(row["id"])
        row["policy_sync"] = sync
        row["policy_in_sync"] = sync.get("in_sync") if sync else None

    reachable = [row for row in instances if row["reachable"]]
    all_healthy = len(reachable) == len(instances) and all(
        row["healthy"] and row.get("upstream_healthy", True) for row in reachable
    )
    identity_ok = len(reachable) == len(instances) and all(
        row["identity_ok"] for row in reachable
    )

    release_keys = {
        (row["version"], row["git_sha"])
        for row in reachable
        if _known(row["version"]) or _known(row["git_sha"])
    }
    release_coverage = sum(
        1
        for row in reachable
        if _known(row["version"]) or _known(row["git_sha"])
    )
    release_consistent: bool | None
    if release_coverage != len(instances):
        release_consistent = None
    else:
        release_consistent = len(release_keys) == 1

    shared_fingerprints = [
        str(row["shared_config_fingerprint"])
        for row in reachable
        if row.get("shared_config_fingerprint")
    ]
    if len(shared_fingerprints) != len(instances):
        shared_config_consistent: bool | None = None
    else:
        shared_config_consistent = len(set(shared_fingerprints)) == 1

    core_shas = {
        str(row["git_sha"])
        for row in reachable
        if _known(row.get("git_sha"))
    }
    if _known(build["git_sha"]) and len(core_shas) == 1 and len(reachable) == len(instances):
        dashboard_matches_cores: bool | None = build["git_sha"] in core_shas
    elif _known(build["version"]) and release_consistent is True and reachable:
        dashboard_matches_cores = all(row["version"] == build["version"] for row in reachable)
    else:
        dashboard_matches_cores = None

    sync_rows = [row for row in instances if row.get("policy_in_sync") is not None]
    if len(sync_rows) != len(instances):
        policy_in_sync: bool | None = None
    else:
        policy_in_sync = all(bool(row["policy_in_sync"]) for row in sync_rows)

    preflight = run_preflight(check_bind=False)
    data_dir = Path(os.getenv("HOTPOT_DASHBOARD_DATA_DIR", "/data"))
    try:
        backups = await DashboardBackupManager(data_dir).status()
    except Exception as exc:
        backups = {
            "enabled": True,
            "count": 0,
            "latest": None,
            "last_error": f"{type(exc).__name__}: {exc}",
        }
    latest_backup = backups.get("latest") if isinstance(backups, dict) else None
    backup_ready = bool(
        not backups.get("enabled", True)
        or (
            isinstance(latest_backup, dict)
            and latest_backup.get("verified")
            and latest_backup.get("present", True)
        )
    )

    checks = [
        _check(
            "dashboard-preflight",
            "pass" if preflight.get("ok") else "fail",
            "Dashboard configuration preflight passes"
            if preflight.get("ok")
            else f"Dashboard preflight reports {preflight.get('failures', 0)} failure(s)",
        ),
        _check(
            "core-health",
            "pass" if all_healthy else "fail",
            f"{sum(1 for row in instances if row['healthy'])}/{len(instances)} Hotpot cores healthy",
        ),
        _check(
            "instance-identity",
            "pass" if identity_ok else "fail",
            "Every remote instance ID matches dashboard configuration"
            if identity_ok
            else "One or more remote instance IDs are unreachable or mismatched",
        ),
        _check(
            "core-release",
            _status_for_bool(release_consistent),
            "All cores run the same release build"
            if release_consistent is True
            else "Core release skew detected"
            if release_consistent is False
            else "Release identity metadata is incomplete",
        ),
        _check(
            "dashboard-release",
            _status_for_bool(dashboard_matches_cores),
            "Dashboard and cores run the same build"
            if dashboard_matches_cores is True
            else "Dashboard build differs from the core build"
            if dashboard_matches_cores is False
            else "Dashboard/core release comparison is unavailable",
        ),
        _check(
            "shared-config",
            _status_for_bool(shared_config_consistent),
            "Common Hotpot configuration is consistent across all cores"
            if shared_config_consistent is True
            else "Common hotpot.env configuration drift detected"
            if shared_config_consistent is False
            else "Config fingerprint metadata is incomplete until all cores run this release",
        ),
        _check(
            "policy-sync",
            _status_for_bool(policy_in_sync),
            "Dashboard policy revisions are synchronized"
            if policy_in_sync is True
            else "Dashboard policy revision drift detected"
            if policy_in_sync is False
            else "Policy synchronization has not completed for every core",
        ),
        _check(
            "verified-backup",
            "pass" if backup_ready else "fail",
            "A restore-verified backup is available"
            if backup_ready and backups.get("enabled", True)
            else "Operational backups are disabled"
            if not backups.get("enabled", True)
            else "No restore-verified operational backup is available",
        ),
    ]

    ready = all(item["status"] == "pass" for item in checks)
    return {
        "schema_version": DEPLOYMENT_REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ready": ready,
        "status": "ready" if ready else "attention",
        "dashboard": {
            **build,
            "config_fingerprint": dashboard_config_fingerprint(dashboard),
        },
        "instances": instances,
        "summary": {
            "instances": len(instances),
            "healthy": sum(1 for row in instances if row["healthy"]),
            "identity_ok": identity_ok,
            "release_consistent": release_consistent,
            "dashboard_matches_cores": dashboard_matches_cores,
            "shared_config_consistent": shared_config_consistent,
            "policy_in_sync": policy_in_sync,
            "backup_ready": backup_ready,
            "preflight_ok": bool(preflight.get("ok")),
        },
        "checks": checks,
        "preflight": preflight,
        "backups": backups,
        "policy_sync": policy_sync,
        "upgrade_plan": _upgrade_plan(build),
    }
