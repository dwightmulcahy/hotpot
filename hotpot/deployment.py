from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .config import Settings


DEPLOYMENT_SCHEMA_VERSION = 2


def _fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _secret_source(name: str, *, configured: bool = False) -> str:
    if os.getenv(f"{name}_FILE", "").strip():
        return "file"
    if os.getenv(name, "").strip():
        return "environment"
    if configured and os.getenv("HOTPOT_APP_REGISTRY", "").strip():
        return "registry-file"
    if configured:
        return "configured"
    return "unset"


def _global_policy_config(settings: Settings) -> dict[str, Any]:
    """Return settings that are intentionally expected to match across cores."""

    return {
        "max_request_body": int(settings.max_request_body),
        "upstream_timeout": float(settings.upstream_timeout),
        "tarpit": {
            "enabled": bool(settings.tarpit_enabled),
            "max_concurrent": int(settings.tarpit_max_concurrent),
            "initial_delay": float(settings.tarpit_initial_delay),
            "chunk_delay": float(settings.tarpit_chunk_delay),
            "max_seconds": float(settings.tarpit_max_seconds),
            "escalated_max_seconds": float(settings.tarpit_escalated_max_seconds),
        },
        "retention_days": int(settings.retention_days),
        "attacker_retention_days": int(settings.attacker_retention_days),
        "housekeeping_interval_seconds": int(settings.housekeeping_interval_seconds),
        "notify_min_level": int(settings.notify_min_level),
        "notify_cooldown_seconds": int(settings.notify_cooldown_seconds),
    }


def _runtime_config(settings: Settings) -> dict[str, Any]:
    """Return transport/source-identity settings that may legitimately vary by app."""

    return {
        "client_ip_mode": settings.client_ip_mode,
        "trusted_proxy_cidrs": sorted(settings.trusted_proxy_cidrs),
    }


def deployment_snapshot(
    settings: Settings,
    *,
    version: str,
    git_sha: str,
    build_date: str,
) -> dict[str, Any]:
    """Describe one running core without exposing credential values.

    Fingerprints intentionally have different scopes:
    - global_policy_fingerprint covers policy expected to match across cores.
    - runtime_fingerprint covers source-identity/runtime wiring that may vary.
    - instance_fingerprint covers the complete effective instance deployment.

    config_fingerprint and shared_config_fingerprint remain compatibility aliases
    for older dashboards. The latter now has corrected global-policy semantics so
    per-app profiles, allowlists, and proxy wiring do not look like fleet drift.
    """

    global_policy = _global_policy_config(settings)
    runtime = _runtime_config(settings)
    instance_config = {
        "global_policy": global_policy,
        "runtime": runtime,
        "profiles": list(settings.enabled_profiles),
        "allow_cidrs": sorted(settings.allow_cidrs),
        "instance_id": settings.instance_id,
        "instance_name": settings.instance_name,
        "bind": settings.bind,
        "port": int(settings.port),
        "upstream": settings.upstream,
    }
    global_policy_fingerprint = _fingerprint(global_policy)
    runtime_fingerprint = _fingerprint(runtime)
    instance_fingerprint = _fingerprint(instance_config)
    return {
        "schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "instance_id": settings.instance_id,
        "instance_name": settings.instance_name,
        "version": version,
        "git_sha": git_sha,
        "build_date": build_date,
        "instance_fingerprint": instance_fingerprint,
        "runtime_fingerprint": runtime_fingerprint,
        "global_policy_fingerprint": global_policy_fingerprint,
        "config_fingerprint": instance_fingerprint,
        "shared_config_fingerprint": global_policy_fingerprint,
        "config": {
            "bind": settings.bind,
            "port": int(settings.port),
            "upstream": settings.upstream,
            "profiles": list(settings.enabled_profiles),
            "client_ip_mode": settings.client_ip_mode,
            "trusted_proxy_cidrs": sorted(settings.trusted_proxy_cidrs),
            "allow_cidrs": sorted(settings.allow_cidrs),
        },
        "secret_sources": {
            "admin_token": _secret_source("HOTPOT_ADMIN_TOKEN"),
            "collector_token": _secret_source(
                "HOTPOT_COLLECTOR_TOKEN",
                configured=bool(settings.collector_token),
            ),
            "policy_token": _secret_source(
                "HOTPOT_POLICY_TOKEN",
                configured=bool(settings.policy_token),
            ),
            "smtp_password": _secret_source("HOTPOT_SMTP_PASSWORD"),
            "webhook_bearer": _secret_source("HOTPOT_NOTIFY_WEBHOOK_BEARER"),
        },
    }
