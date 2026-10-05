from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_csv(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(v.strip() for v in os.getenv(name, default).split(",") if v.strip())


@dataclass(frozen=True)
class Settings:
    bind: str
    port: int
    upstream: str
    data_dir: Path
    profiles_dir: Path
    enabled_profiles: tuple[str, ...]
    max_request_body: int
    upstream_timeout: float
    client_ip_mode: str
    trusted_proxy_cidrs: tuple[str, ...]
    tarpit_enabled: bool
    tarpit_max_concurrent: int
    tarpit_initial_delay: float
    tarpit_chunk_delay: float
    tarpit_max_seconds: float
    tarpit_escalated_max_seconds: float
    admin_token: str | None
    allow_cidrs: tuple[str, ...]
    retention_days: int
    attacker_retention_days: int
    housekeeping_interval_seconds: int
    notify_min_level: int
    notify_cooldown_seconds: int
    notify_webhook_url: str | None
    notify_webhook_bearer: str | None
    smtp_host: str | None
    smtp_port: int
    smtp_starttls: bool
    smtp_username: str | None
    smtp_password: str | None
    smtp_from: str | None
    smtp_to: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "Settings":
        upstream = os.getenv("HOTPOT_UPSTREAM", "").rstrip("/")
        if not upstream:
            raise RuntimeError("HOTPOT_UPSTREAM is required, e.g. http://myapp:8080")
        profiles = env_csv("HOTPOT_PROFILES", "wordpress,secrets,git,php,generic")
        return cls(
            bind=os.getenv("HOTPOT_BIND", "0.0.0.0"),
            port=int(os.getenv("HOTPOT_PORT", "8080")),
            upstream=upstream,
            data_dir=Path(os.getenv("HOTPOT_DATA_DIR", "/data")),
            profiles_dir=Path(os.getenv("HOTPOT_PROFILES_DIR", "/app/profiles")),
            enabled_profiles=profiles,
            max_request_body=int(os.getenv("HOTPOT_MAX_REQUEST_BODY", str(8 * 1024 * 1024))),
            upstream_timeout=float(os.getenv("HOTPOT_UPSTREAM_TIMEOUT", "60")),
            client_ip_mode=os.getenv("HOTPOT_CLIENT_IP_MODE", "direct"),
            trusted_proxy_cidrs=env_csv("HOTPOT_TRUSTED_PROXY_CIDRS"),
            tarpit_enabled=env_bool("HOTPOT_TARPIT_ENABLED", True),
            tarpit_max_concurrent=int(os.getenv("HOTPOT_TARPIT_MAX_CONCURRENT", "10")),
            tarpit_initial_delay=float(os.getenv("HOTPOT_TARPIT_INITIAL_DELAY", "1.0")),
            tarpit_chunk_delay=float(os.getenv("HOTPOT_TARPIT_CHUNK_DELAY", "2.0")),
            tarpit_max_seconds=float(os.getenv("HOTPOT_TARPIT_MAX_SECONDS", "20")),
            tarpit_escalated_max_seconds=float(os.getenv("HOTPOT_TARPIT_ESCALATED_MAX_SECONDS", "60")),
            admin_token=os.getenv("HOTPOT_ADMIN_TOKEN") or None,
            allow_cidrs=env_csv("HOTPOT_ALLOW_CIDRS"),
            retention_days=max(1, int(os.getenv("HOTPOT_RETENTION_DAYS", "30"))),
            attacker_retention_days=max(1, int(os.getenv("HOTPOT_ATTACKER_RETENTION_DAYS", "90"))),
            housekeeping_interval_seconds=max(300, int(os.getenv("HOTPOT_HOUSEKEEPING_INTERVAL_SECONDS", "21600"))),
            notify_min_level=min(4, max(1, int(os.getenv("HOTPOT_NOTIFY_MIN_LEVEL", "3")))),
            notify_cooldown_seconds=max(60, int(os.getenv("HOTPOT_NOTIFY_COOLDOWN_SECONDS", "3600"))),
            notify_webhook_url=os.getenv("HOTPOT_NOTIFY_WEBHOOK_URL") or None,
            notify_webhook_bearer=os.getenv("HOTPOT_NOTIFY_WEBHOOK_BEARER") or None,
            smtp_host=os.getenv("HOTPOT_SMTP_HOST") or None,
            smtp_port=int(os.getenv("HOTPOT_SMTP_PORT", "587")),
            smtp_starttls=env_bool("HOTPOT_SMTP_STARTTLS", True),
            smtp_username=os.getenv("HOTPOT_SMTP_USERNAME") or None,
            smtp_password=os.getenv("HOTPOT_SMTP_PASSWORD") or None,
            smtp_from=os.getenv("HOTPOT_SMTP_FROM") or None,
            smtp_to=env_csv("HOTPOT_SMTP_TO"),
        )
