from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from .config import Settings


DEPLOYMENT_SCHEMA_VERSION = 1


def _fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _secret_source(name: str) -> str:
    if os.getenv(f"{name}_FILE", "").strip():
        return "file"
    if os.getenv(name, "").strip():
        return "environment"
    return "unset"


def _shared_config(settings: Settings) -> dict[str, Any]:
    """Return the secret-free settings expected to be common across Hotpot peers."""

    return {
        "profiles": list(settings.enabled_profiles),
        "max_request_body": int(settings.max_request_body),
        "upstream_timeout": float(settings.upstream_timeout),
        "client_ip_mode": settings.client_ip_mode,
        "trusted_proxy_cidrs": sorted(settings.trusted_proxy_cidrs),
        "allow_cidrs": sorted(settings.allow_cidrs),
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


def deployment_snapshot(
    settings: Settings,
    *,
    version: str,
    git_sha: str,
    build_date: str,
) -> dict[str, Any]:
    """Describe one running core without exposing credential values.

    Two hashes are intentionally emitted:
    - ``config_fingerprint`` includes identity/listener/upstream fields and identifies
      the complete effective deployment configuration for one instance.
    - ``shared_config_fingerprint`` omits instance-specific fields so the dashboard
      can spot accidental drift in the common hotpot.env policy across peers.
    """

    shared = _shared_config(settings)
    instance_config = {
        **shared,
        "instance_id": settings.instance_id,
        "instance_name": settings.instance_name,
        "bind": settings.bind,
        "port": int(settings.port),
        "upstream": settings.upstream,
    }
    return {
        "schema_version": DEPLOYMENT_SCHEMA_VERSION,
        "instance_id": settings.instance_id,
        "instance_name": settings.instance_name,
        "version": version,
        "git_sha": git_sha,
        "build_date": build_date,
        "config_fingerprint": _fingerprint(instance_config),
        "shared_config_fingerprint": _fingerprint(shared),
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
            "smtp_password": _secret_source("HOTPOT_SMTP_PASSWORD"),
            "webhook_bearer": _secret_source("HOTPOT_NOTIFY_WEBHOOK_BEARER"),
        },
    }
