from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True)
class RegistryCloudflare:
    zone_id: str
    hosts: tuple[str, ...]


@dataclass(frozen=True)
class RegistryCredentials:
    collector_token_file: str
    policy_token_file: str


@dataclass(frozen=True)
class RegistryApp:
    instance_id: str
    name: str
    url: str
    profiles: tuple[str, ...]
    service: str | None
    cloudflare: RegistryCloudflare | None
    credentials: RegistryCredentials | None


@dataclass(frozen=True)
class AppRegistry:
    apps: tuple[RegistryApp, ...]
    source: str

    def by_id(self) -> dict[str, RegistryApp]:
        return {app.instance_id: app for app in self.apps}


def _required_table(value: object, *, context: str) -> dict:
    if not isinstance(value, dict):
        raise RuntimeError(f"{context} must be a TOML table")
    return value


def _clean_id(value: object) -> str:
    instance_id = str(value or "").strip()
    if not instance_id:
        raise RuntimeError("Each app requires a non-empty id")
    if not _ID_RE.fullmatch(instance_id):
        raise RuntimeError(
            f"Invalid app id {instance_id!r}; use lowercase letters, digits, '.', '_' or '-'"
        )
    return instance_id


def _clean_url(value: object, *, instance_id: str) -> str:
    url = str(value or "").strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError(
            f"App {instance_id!r} dashboard.url must be an absolute http(s) URL"
        )
    if parsed.username or parsed.password:
        raise RuntimeError(
            f"App {instance_id!r} dashboard.url must not contain credentials"
        )
    return url


def _clean_profiles(value: object, *, instance_id: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise RuntimeError(f"App {instance_id!r} profiles must be a TOML array")
    profiles: list[str] = []
    seen: set[str] = set()
    for item in value:
        profile = str(item or "").strip()
        if not profile:
            raise RuntimeError(f"App {instance_id!r} profiles may not contain blanks")
        if profile not in seen:
            profiles.append(profile)
            seen.add(profile)
    return tuple(profiles)


def _clean_service(value: object, *, instance_id: str) -> str | None:
    if value is None:
        return None
    service = str(value).strip()
    if not service:
        raise RuntimeError(
            f"App {instance_id!r} deployment.service must not be blank"
        )
    return service


def _clean_secret_path(value: object, *, instance_id: str, field: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise RuntimeError(f"App {instance_id!r} credentials.{field} is required")
    path = Path(raw)
    if not path.is_absolute():
        raise RuntimeError(
            f"App {instance_id!r} credentials.{field} must be an absolute path"
        )
    return str(path)


def _clean_hosts(value: object, *, instance_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RuntimeError(
            f"App {instance_id!r} cloudflare.hosts must be a non-empty TOML array"
        )
    hosts: set[str] = set()
    for item in value:
        host = str(item or "").strip().lower().rstrip(".")
        if (
            not host
            or "://" in host
            or "/" in host
            or any(ch.isspace() for ch in host)
        ):
            raise RuntimeError(
                f"App {instance_id!r} has invalid Cloudflare hostname {item!r}"
            )
        hosts.add(host)
    return tuple(sorted(hosts))


def _parse_app(value: object) -> RegistryApp:
    raw = _required_table(value, context="Each apps entry")
    instance_id = _clean_id(raw.get("id"))
    name = str(raw.get("name") or instance_id).strip()
    if not name:
        raise RuntimeError(f"App {instance_id!r} name must not be blank")

    dashboard = _required_table(
        raw.get("dashboard"), context=f"App {instance_id!r} dashboard"
    )
    url = _clean_url(dashboard.get("url"), instance_id=instance_id)
    profiles = _clean_profiles(raw.get("profiles"), instance_id=instance_id)

    deployment_raw = raw.get("deployment")
    service = None
    if deployment_raw is not None:
        deployment = _required_table(
            deployment_raw, context=f"App {instance_id!r} deployment"
        )
        service = _clean_service(
            deployment.get("service"), instance_id=instance_id
        )

    cloudflare_raw = raw.get("cloudflare")
    cloudflare = None
    if cloudflare_raw is not None:
        cloudflare_table = _required_table(
            cloudflare_raw, context=f"App {instance_id!r} cloudflare"
        )
        zone_id = str(cloudflare_table.get("zone_id") or "").strip()
        if not zone_id:
            raise RuntimeError(
                f"App {instance_id!r} cloudflare.zone_id is required"
            )
        hosts = _clean_hosts(
            cloudflare_table.get("hosts"), instance_id=instance_id
        )
        cloudflare = RegistryCloudflare(zone_id=zone_id, hosts=hosts)

    credentials_raw = raw.get("credentials")
    credentials = None
    if credentials_raw is not None:
        credentials_table = _required_table(
            credentials_raw, context=f"App {instance_id!r} credentials"
        )
        collector_token_file = _clean_secret_path(
            credentials_table.get("collector_token_file"),
            instance_id=instance_id,
            field="collector_token_file",
        )
        policy_token_file = _clean_secret_path(
            credentials_table.get("policy_token_file"),
            instance_id=instance_id,
            field="policy_token_file",
        )
        if collector_token_file == policy_token_file:
            raise RuntimeError(
                f"App {instance_id!r} collector and policy token files must differ"
            )
        credentials = RegistryCredentials(
            collector_token_file=collector_token_file,
            policy_token_file=policy_token_file,
        )

    return RegistryApp(
        instance_id=instance_id,
        name=name,
        url=url,
        profiles=profiles,
        service=service,
        cloudflare=cloudflare,
        credentials=credentials,
    )


def parse_app_registry(raw: bytes | str, *, source: str = "<memory>") -> AppRegistry:
    try:
        payload = tomllib.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError(f"App registry {source} is not valid TOML: {exc}") from exc

    apps_raw = payload.get("apps")
    if not isinstance(apps_raw, list) or not apps_raw:
        raise RuntimeError("App registry requires at least one [[apps]] entry")

    apps: list[RegistryApp] = []
    seen: set[str] = set()
    for value in apps_raw:
        app = _parse_app(value)
        if app.instance_id in seen:
            raise RuntimeError(f"Duplicate app id: {app.instance_id}")
        seen.add(app.instance_id)
        apps.append(app)

    return AppRegistry(apps=tuple(apps), source=source)


def load_app_registry(path: str | Path | None = None) -> AppRegistry:
    selected = (
        Path(path)
        if path is not None
        else Path(os.getenv("HOTPOT_APP_REGISTRY", "/config/apps.toml"))
    )
    try:
        raw = selected.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read app registry {selected}: {exc}") from exc
    return parse_app_registry(raw, source=str(selected))


def _legacy_cloudflare(raw: str) -> dict[str, RegistryCloudflare]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("HOTPOT_CLOUDFLARE_TARGETS must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("HOTPOT_CLOUDFLARE_TARGETS must be a JSON object")
    result: dict[str, RegistryCloudflare] = {}
    for instance_id, value in payload.items():
        key = _clean_id(instance_id)
        table = _required_table(
            value, context=f"Cloudflare target {key!r}"
        )
        zone_id = str(table.get("zone_id") or "").strip()
        if not zone_id:
            raise RuntimeError(f"Cloudflare target {key!r} requires zone_id")
        result[key] = RegistryCloudflare(
            zone_id=zone_id,
            hosts=_clean_hosts(table.get("hosts"), instance_id=key),
        )
    return result


def registry_from_environment() -> AppRegistry:
    """Load the registry, with legacy dashboard env as a migration fallback."""

    configured = os.getenv("HOTPOT_APP_REGISTRY", "").strip()
    if configured:
        return load_app_registry(configured)

    legacy_raw = os.getenv("HOTPOT_DASHBOARD_INSTANCES", "").strip()
    if legacy_raw:
        try:
            values = json.loads(legacy_raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "HOTPOT_DASHBOARD_INSTANCES must be valid JSON"
            ) from exc
        if not isinstance(values, list) or not values:
            raise RuntimeError(
                "HOTPOT_DASHBOARD_INSTANCES must be a non-empty JSON list"
            )
        cloudflare = _legacy_cloudflare(
            os.getenv("HOTPOT_CLOUDFLARE_TARGETS", "")
        )
        apps: list[RegistryApp] = []
        seen: set[str] = set()
        for value in values:
            table = _required_table(
                value, context="Each dashboard instance"
            )
            instance_id = _clean_id(table.get("id"))
            if instance_id in seen:
                raise RuntimeError(f"Duplicate app id: {instance_id}")
            seen.add(instance_id)
            name = str(table.get("name") or instance_id).strip()
            if not name:
                raise RuntimeError(
                    f"App {instance_id!r} name must not be blank"
                )
            apps.append(
                RegistryApp(
                    instance_id=instance_id,
                    name=name,
                    url=_clean_url(
                        table.get("url"), instance_id=instance_id
                    ),
                    profiles=(),
                    service=None,
                    cloudflare=cloudflare.get(instance_id),
                    credentials=None,
                )
            )
        return AppRegistry(apps=tuple(apps), source="legacy-environment")

    default_path = Path("/config/apps.toml")
    if default_path.is_file():
        return load_app_registry(default_path)
    raise RuntimeError(
        "Configure HOTPOT_APP_REGISTRY or legacy HOTPOT_DASHBOARD_INSTANCES"
    )
