from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from hotpot_common.app_registry import RegistryApp, load_app_registry


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_csv(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(v.strip() for v in os.getenv(name, default).split(",") if v.strip())


def _file_secret(path: str, *, label: str) -> str | None:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"Could not read {label}: {exc}") from exc
    return value or None


def env_secret(name: str) -> str | None:
    """Read a secret from NAME_FILE when configured, otherwise from NAME.

    The file-backed form intentionally takes precedence so Docker/Container Station
    deployments can keep credentials out of the container environment shown by
    ``docker inspect``. Empty values are treated as unset.
    """

    file_name = os.getenv(f"{name}_FILE", "").strip()
    if file_name:
        return _file_secret(file_name, label=f"{name}_FILE")
    return os.getenv(name, "").strip() or None


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
    collector_token: str | None = None
    policy_token: str | None = None
    instance_id: str = "hotpot"
    instance_name: str = "hotpot"

    @classmethod
    def from_env(cls) -> "Settings":
        upstream = os.getenv("HOTPOT_UPSTREAM", "").rstrip("/")
        if not upstream:
            raise RuntimeError("HOTPOT_UPSTREAM is required, e.g. http://myapp:8080")
        instance_id = os.getenv("HOTPOT_INSTANCE_ID", "hotpot").strip() or "hotpot"
        registry_app: RegistryApp | None = None
        registry_path = os.getenv("HOTPOT_APP_REGISTRY", "").strip()
        if registry_path:
            registry = load_app_registry(registry_path)
            registry_app = registry.by_id().get(instance_id)
            if registry_app is None:
                raise RuntimeError(
                    f"HOTPOT_INSTANCE_ID {instance_id!r} is not present in app registry"
                )
            if not registry_app.profiles:
                raise RuntimeError(
                    f"App registry entry {instance_id!r} must define at least one profile"
                )
            profiles = registry_app.profiles
            instance_name_default = registry_app.name
        else:
            profiles = env_csv(
                "HOTPOT_PROFILES", "wordpress,secrets,git,php,generic"
            )
            instance_name_default = instance_id
        instance_name = (
            os.getenv("HOTPOT_INSTANCE_NAME", instance_name_default).strip()
            or instance_name_default
        )

        collector_token = env_secret("HOTPOT_COLLECTOR_TOKEN")
        policy_token = env_secret("HOTPOT_POLICY_TOKEN")
        if registry_app is not None and registry_app.credentials is not None:
            if collector_token is None:
                collector_token = _file_secret(
                    registry_app.credentials.collector_token_file,
                    label=(
                        f"collector token for registry app {registry_app.instance_id!r}"
                    ),
                )
            if policy_token is None:
                policy_token = _file_secret(
                    registry_app.credentials.policy_token_file,
                    label=(
                        f"policy token for registry app {registry_app.instance_id!r}"
                    ),
                )
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
            admin_token=env_secret("HOTPOT_ADMIN_TOKEN"),
            allow_cidrs=env_csv("HOTPOT_ALLOW_CIDRS"),
            retention_days=max(1, int(os.getenv("HOTPOT_RETENTION_DAYS", "30"))),
            attacker_retention_days=max(1, int(os.getenv("HOTPOT_ATTACKER_RETENTION_DAYS", "90"))),
            housekeeping_interval_seconds=max(300, int(os.getenv("HOTPOT_HOUSEKEEPING_INTERVAL_SECONDS", "21600"))),
            notify_min_level=min(4, max(1, int(os.getenv("HOTPOT_NOTIFY_MIN_LEVEL", "3")))),
            notify_cooldown_seconds=max(60, int(os.getenv("HOTPOT_NOTIFY_COOLDOWN_SECONDS", "3600"))),
            notify_webhook_url=os.getenv("HOTPOT_NOTIFY_WEBHOOK_URL") or None,
            notify_webhook_bearer=env_secret("HOTPOT_NOTIFY_WEBHOOK_BEARER"),
            smtp_host=os.getenv("HOTPOT_SMTP_HOST") or None,
            smtp_port=int(os.getenv("HOTPOT_SMTP_PORT", "587")),
            smtp_starttls=env_bool("HOTPOT_SMTP_STARTTLS", True),
            smtp_username=os.getenv("HOTPOT_SMTP_USERNAME") or None,
            smtp_password=env_secret("HOTPOT_SMTP_PASSWORD"),
            smtp_from=os.getenv("HOTPOT_SMTP_FROM") or None,
            smtp_to=env_csv("HOTPOT_SMTP_TO"),
            collector_token=collector_token,
            policy_token=policy_token,
            instance_id=instance_id,
            instance_name=instance_name,
        )
