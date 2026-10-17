#!/usr/bin/env python3
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_DIR = Path("/share/Data/config/cloudflared")
DEFAULT_PROFILES = ("wordpress", "secrets", "git", "php", "generic")
INSTANCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SERVICE_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_.-]+):(?:\s*(?:#.*)?)?$")
PROPERTY_RE = re.compile(r"^    ([A-Za-z0-9_.-]+):")
SECRET_KEY_RE = re.compile(r"(?:TOKEN|PASSWORD|BEARER|SECRET)", re.IGNORECASE)

CORE_SHARED_SECRET_KEYS = {
    "HOTPOT_NOTIFY_WEBHOOK_BEARER": "notify_webhook_bearer",
    "HOTPOT_SMTP_PASSWORD": "smtp_password",
}


class MigrationError(RuntimeError):
    pass


@dataclass(frozen=True)
class AppSpec:
    service: str
    instance_id: str
    name: str
    profiles: tuple[str, ...]
    dashboard_url: str
    port: str
    upstream: str
    cloudflare: dict[str, Any] | None


@dataclass(frozen=True)
class Discovery:
    apps: tuple[AppSpec, ...]
    dashboard_service: str
    compose_config: dict[str, Any]
    secrets_dir: Path
    container_uid: int | None
    container_gid: int | None


@dataclass(frozen=True)
class Candidate:
    compose: str
    hotpot_env: str
    dashboard_env: str
    registry: str
    copied_secret_values: dict[str, str]


def _run(
    command: list[str],
    *,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise MigrationError(
            f"Command failed ({result.returncode}): {' '.join(command)}"
            + (f"\n{detail}" if detail else "")
        )
    return result


def _compose_config(compose: Path, docker_bin: str) -> dict[str, Any]:
    result = _run(
        [
            docker_bin,
            "compose",
            "-f",
            str(compose),
            "config",
            "--format",
            "json",
        ]
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise MigrationError(
            "docker compose config --format json did not return valid JSON"
        ) from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("services"), dict):
        raise MigrationError("Compose config JSON does not contain a services object")
    return payload


def _validate_compose_text(compose: Path, text: str, docker_bin: str) -> None:
    compose.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix=".hotpot-migrate-",
        suffix=compose.suffix or ".yml",
        dir=compose.parent,
        delete=False,
    )
    candidate = Path(handle.name)
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _run([docker_bin, "compose", "-f", str(candidate), "config", "-q"])
    finally:
        candidate.unlink(missing_ok=True)


def _read_text(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MigrationError(f"Could not read {label} {path}: {exc}") from exc


def _env_map(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        values[key] = value
    return values


def _rewrite_env(
    text: str,
    *,
    remove: set[str],
    additions: dict[str, str] | None = None,
    note: str | None = None,
) -> str:
    additions = additions or {}
    remove = set(remove) | set(additions)
    output: list[str] = []
    key_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
    for line in text.splitlines():
        match = key_re.match(line)
        if match and match.group(1) in remove:
            continue
        output.append(line.rstrip())
    while output and output[-1] == "":
        output.pop()
    if note or additions:
        output.append("")
        if note:
            output.append(f"# {note}")
        for key, value in additions.items():
            output.append(f"{key}={value}")
    return "\n".join(output) + "\n"


def _service_spans(text: str) -> dict[str, tuple[int, int]]:
    lines = text.splitlines(keepends=True)
    services_line = None
    for index, line in enumerate(lines):
        if line.rstrip() == "services:":
            services_line = index
            break
    if services_line is None:
        raise MigrationError("Compose file does not contain a top-level services: block")

    headers: list[tuple[str, int]] = []
    end = len(lines)
    for index in range(services_line + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.startswith((" ", "\t", "#")):
            end = index
            break
        match = SERVICE_HEADER_RE.match(line.rstrip("\n"))
        if match:
            headers.append((match.group(1), index))
    spans: dict[str, tuple[int, int]] = {}
    for pos, (name, start) in enumerate(headers):
        stop = headers[pos + 1][1] if pos + 1 < len(headers) else end
        spans[name] = (start, stop)
    return spans


def _section_range(lines: list[str], name: str) -> tuple[int, int] | None:
    header = f"    {name}:"
    for index, line in enumerate(lines):
        if line.rstrip().startswith(header):
            for stop in range(index + 1, len(lines)):
                if PROPERTY_RE.match(lines[stop]):
                    return index, stop
            return index, len(lines)
    return None


def _remove_env_keys_from_block(lines: list[str], keys: set[str]) -> list[str]:
    section = _section_range(lines, "environment")
    if section is None:
        return lines
    start, stop = section
    result = lines[: start + 1]
    mapping_re = re.compile(r"^      ([A-Za-z_][A-Za-z0-9_]*)\s*:")
    list_re = re.compile(r"^      -\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
    for line in lines[start + 1 : stop]:
        match = mapping_re.match(line) or list_re.match(line)
        if match and match.group(1) in keys:
            continue
        result.append(line)
    result.extend(lines[stop:])
    return result


def _set_environment(lines: list[str], values: dict[str, str]) -> list[str]:
    lines = _remove_env_keys_from_block(lines, set(values))
    section = _section_range(lines, "environment")
    if section is None:
        insert = len(lines)
        while insert > 1 and not lines[insert - 1].strip():
            insert -= 1
        block = ["    environment:\n"]
        block.extend(
            f"      {key}: {json.dumps(value)}\n" for key, value in values.items()
        )
        return lines[:insert] + block + lines[insert:]

    start, stop = section
    content = lines[start + 1 : stop]
    list_style = any(line.startswith("      - ") for line in content if line.strip())
    additions = (
        [f"      - {key}={value}\n" for key, value in values.items()]
        if list_style
        else [
            f"      {key}: {json.dumps(value)}\n"
            for key, value in values.items()
        ]
    )
    return lines[:stop] + additions + lines[stop:]


def _volume_line_targets(line: str, target: str) -> bool:
    stripped = line.strip().strip('"').strip("'")
    if not stripped.startswith("- "):
        return False
    item = stripped[2:].strip().strip('"').strip("'")
    parts = item.split(":")
    if len(parts) < 2:
        return False
    if parts[-1] in {"ro", "rw"} and len(parts) >= 3:
        actual = parts[-2]
    else:
        actual = parts[-1]
    return actual == target


def _set_volumes(
    lines: list[str],
    *,
    remove_targets: set[str],
    additions: list[str],
) -> list[str]:
    section = _section_range(lines, "volumes")
    if section is None:
        insert = len(lines)
        while insert > 1 and not lines[insert - 1].strip():
            insert -= 1
        block = ["    volumes:\n"]
        block.extend(f"      - {item}\n" for item in additions)
        return lines[:insert] + block + lines[insert:]

    start, stop = section
    content = lines[start + 1 : stop]
    if any(line.startswith("      - type:") for line in content):
        raise MigrationError(
            "Long-syntax Compose volumes are not automatically rewritten. "
            "Convert Hotpot registry/secret mounts to short syntax or migrate them manually."
        )
    kept = [
        line
        for line in content
        if not any(_volume_line_targets(line, target) for target in remove_targets)
    ]
    existing = {line.strip()[2:].strip().strip('"').strip("'") for line in kept if line.strip().startswith("- ")}
    for item in additions:
        if item not in existing:
            kept.append(f"      - {item}\n")
    return lines[: start + 1] + kept + lines[stop:]


def _set_labels(lines: list[str], values: dict[str, str]) -> list[str]:
    section = _section_range(lines, "labels")
    if section is None:
        insert = len(lines)
        while insert > 1 and not lines[insert - 1].strip():
            insert -= 1
        block = ["    labels:\n"]
        block.extend(
            f"      - {json.dumps(f'{key}={value}')}\n"
            for key, value in values.items()
        )
        return lines[:insert] + block + lines[insert:]

    start, stop = section
    content = lines[start + 1 : stop]
    list_style = any(line.startswith("      - ") for line in content if line.strip())
    keys = set(values)
    kept: list[str] = []
    for line in content:
        stripped = line.strip().strip('"').strip("'")
        if list_style and stripped.startswith("- "):
            pair = stripped[2:].split("=", 1)[0]
            if pair in keys:
                continue
        if not list_style:
            match = re.match(r"^      ([A-Za-z0-9_.-]+)\s*:", line)
            if match and match.group(1) in keys:
                continue
        kept.append(line)
    if list_style:
        kept.extend(
            f"      - {json.dumps(f'{key}={value}')}\n"
            for key, value in values.items()
        )
    else:
        kept.extend(
            f"      {key}: {json.dumps(value)}\n" for key, value in values.items()
        )
    return lines[: start + 1] + kept + lines[stop:]


def _modify_core_block(
    block: str,
    *,
    app: AppSpec,
    registry: Path,
    secrets_dir: Path,
    per_service_secret_files: dict[str, str],
) -> str:
    lines = block.splitlines(keepends=True)
    lines = _remove_env_keys_from_block(
        lines, {"HOTPOT_INSTANCE_NAME", "HOTPOT_PROFILES"}
    )
    environment = {"HOTPOT_APP_REGISTRY": "/config/apps.toml"}
    environment.update(per_service_secret_files)
    lines = _set_environment(lines, environment)
    lines = _set_volumes(
        lines,
        remove_targets={"/config/apps.toml", "/run/secrets"},
        additions=[
            f"{registry}:/config/apps.toml:ro",
            (
                f"{secrets_dir / app.instance_id}:"
                f"/run/secrets/{app.instance_id}:ro"
            ),
        ],
    )
    lines = _set_labels(
        lines,
        {
            "io.hotpot.managed": "true",
            "io.hotpot.role": "core",
            "io.hotpot.instance-id": app.instance_id,
        },
    )
    return "".join(lines)


def _modify_dashboard_block(
    block: str,
    *,
    registry: Path,
    secrets_dir: Path,
) -> str:
    lines = block.splitlines(keepends=True)
    lines = _set_environment(lines, {"HOTPOT_APP_REGISTRY": "/config/apps.toml"})
    lines = _set_volumes(
        lines,
        remove_targets={"/config/apps.toml"},
        additions=[
            f"{registry}:/config/apps.toml:ro",
            f"{secrets_dir}:/run/secrets:ro",
        ],
    )
    lines = _set_labels(
        lines,
        {
            "io.hotpot.managed": "true",
            "io.hotpot.role": "dashboard",
        },
    )
    return "".join(lines)


def _replace_service_blocks(
    text: str,
    replacements: dict[str, str],
) -> str:
    spans = _service_spans(text)
    lines = text.splitlines(keepends=True)
    for service, replacement in sorted(
        replacements.items(),
        key=lambda item: spans.get(item[0], (-1, -1))[0],
        reverse=True,
    ):
        if service not in spans:
            raise MigrationError(
                f"Could not locate raw Compose service block for {service!r}"
            )
        start, stop = spans[service]
        lines[start:stop] = replacement.splitlines(keepends=True)
    return "".join(lines)


def _normalized_environment(service: dict[str, Any]) -> dict[str, str]:
    raw = service.get("environment") or {}
    if not isinstance(raw, dict):
        raise MigrationError("docker compose config returned a non-object environment")
    return {
        str(key): "" if value is None else str(value)
        for key, value in raw.items()
    }


def _parse_json_object(raw: str, label: str) -> dict[str, Any]:
    raw = raw.strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MigrationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise MigrationError(f"{label} must be a JSON object")
    return value


def _parse_json_list(raw: str, label: str) -> list[Any]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MigrationError(f"{label} is not valid JSON") from exc
    if not isinstance(value, list):
        raise MigrationError(f"{label} must be a JSON list")
    return value


def _unique_profiles(raw: str) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        profile = item.strip()
        if profile and profile not in seen:
            result.append(profile)
            seen.add(profile)
    return tuple(result)


def _volume_source_for_target(service: dict[str, Any], target: str) -> str | None:
    volumes = service.get("volumes") or []
    if not isinstance(volumes, list):
        return None
    for volume in volumes:
        if not isinstance(volume, dict):
            continue
        if str(volume.get("target") or "") != target:
            continue
        source = str(volume.get("source") or "").strip()
        if source:
            return source
    return None


def _parse_numeric_user(value: object) -> tuple[int | None, int | None]:
    raw = str(value or "").strip()
    if not raw:
        return None, None
    parts = raw.split(":", 1)
    try:
        uid = int(parts[0])
    except ValueError:
        return None, None
    gid = None
    if len(parts) == 2:
        try:
            gid = int(parts[1])
        except ValueError:
            gid = None
    return uid, gid


def _discover(
    config: dict[str, Any],
    *,
    requested_secrets_dir: Path | None,
) -> Discovery:
    services: dict[str, Any] = config["services"]
    cores: list[tuple[str, dict[str, Any], dict[str, str]]] = []
    dashboard_candidates: list[tuple[str, dict[str, Any], dict[str, str]]] = []

    for service_name, service_value in services.items():
        if not isinstance(service_value, dict):
            continue
        env = _normalized_environment(service_value)
        if env.get("HOTPOT_INSTANCE_ID") and env.get("HOTPOT_UPSTREAM"):
            cores.append((service_name, service_value, env))
            continue
        image = str(service_value.get("image") or "").lower()
        if (
            "hotpot-dashboard" in image
            or "HOTPOT_DASHBOARD_DATA_DIR" in env
            or "HOTPOT_DASHBOARD_INSTANCES" in env
        ):
            dashboard_candidates.append((service_name, service_value, env))

    if not cores:
        raise MigrationError("No legacy Hotpot core services were discovered")
    if len(dashboard_candidates) != 1:
        raise MigrationError(
            "Expected exactly one Hotpot dashboard service; found "
            f"{len(dashboard_candidates)}"
        )

    dashboard_service, dashboard_config, dashboard_env = dashboard_candidates[0]
    instances_raw = _parse_json_list(
        dashboard_env.get("HOTPOT_DASHBOARD_INSTANCES", ""),
        "HOTPOT_DASHBOARD_INSTANCES",
    )
    instances: dict[str, dict[str, Any]] = {}
    for item in instances_raw:
        if not isinstance(item, dict):
            raise MigrationError("Each dashboard instance must be a JSON object")
        instance_id = str(item.get("id") or "").strip()
        if not instance_id:
            raise MigrationError("Dashboard instance is missing id")
        if instance_id in instances:
            raise MigrationError(f"Duplicate dashboard instance id {instance_id!r}")
        instances[instance_id] = item

    cloudflare = _parse_json_object(
        dashboard_env.get("HOTPOT_CLOUDFLARE_TARGETS", ""),
        "HOTPOT_CLOUDFLARE_TARGETS",
    )

    ids: set[str] = set()
    apps: list[AppSpec] = []
    secret_sources: set[str] = set()
    users: set[tuple[int | None, int | None]] = set()

    for service_name, service_config, env in cores:
        instance_id = env["HOTPOT_INSTANCE_ID"].strip()
        if not INSTANCE_ID_RE.fullmatch(instance_id):
            raise MigrationError(
                f"Core {service_name!r} has invalid HOTPOT_INSTANCE_ID {instance_id!r}"
            )
        if instance_id in ids:
            raise MigrationError(f"Duplicate core instance id {instance_id!r}")
        ids.add(instance_id)

        dashboard_item = instances.get(instance_id, {})
        name = (
            env.get("HOTPOT_INSTANCE_NAME", "").strip()
            or str(dashboard_item.get("name") or "").strip()
            or instance_id
        )
        profiles = _unique_profiles(env.get("HOTPOT_PROFILES", ""))
        if not profiles:
            profiles = DEFAULT_PROFILES
        port = env.get("HOTPOT_PORT", "8080").strip() or "8080"
        try:
            if int(port) < 1:
                raise ValueError
        except ValueError as exc:
            raise MigrationError(
                f"Core {service_name!r} has invalid HOTPOT_PORT {port!r}"
            ) from exc
        dashboard_url = str(dashboard_item.get("url") or "").strip().rstrip("/")
        if not dashboard_url:
            dashboard_url = f"http://127.0.0.1:{port}"

        target = cloudflare.get(instance_id)
        if target is not None and not isinstance(target, dict):
            raise MigrationError(
                f"Cloudflare mapping for {instance_id!r} must be an object"
            )

        apps.append(
            AppSpec(
                service=service_name,
                instance_id=instance_id,
                name=name,
                profiles=profiles,
                dashboard_url=dashboard_url,
                port=port,
                upstream=env["HOTPOT_UPSTREAM"].strip(),
                cloudflare=target,
            )
        )

        source = _volume_source_for_target(service_config, "/run/secrets")
        if source:
            secret_sources.add(source)
        users.add(_parse_numeric_user(service_config.get("user")))

    unknown_instances = sorted(set(instances) - ids)
    if unknown_instances:
        raise MigrationError(
            "Dashboard instance configuration contains apps with no core service: "
            + ", ".join(unknown_instances)
        )
    unknown_cloudflare = sorted(set(cloudflare) - ids)
    if unknown_cloudflare:
        raise MigrationError(
            "Cloudflare target configuration contains apps with no core service: "
            + ", ".join(unknown_cloudflare)
        )

    dashboard_secret_source = _volume_source_for_target(
        dashboard_config, "/run/secrets"
    )
    if dashboard_secret_source:
        secret_sources.add(dashboard_secret_source)

    if requested_secrets_dir is not None:
        secrets_dir = requested_secrets_dir
    elif len(secret_sources) == 1:
        secrets_dir = Path(next(iter(secret_sources)))
    elif not secret_sources:
        secrets_dir = DEFAULT_CONFIG_DIR / "secrets"
    else:
        raise MigrationError(
            "Multiple legacy /run/secrets bind sources were found. "
            "Pass --secrets-dir explicitly."
        )

    concrete_users = {item for item in users if item != (None, None)}
    if len(concrete_users) > 1:
        raise MigrationError(
            "Hotpot cores use different numeric container users. "
            "Normalize them or migrate secret ownership manually."
        )
    uid, gid = next(iter(concrete_users), (None, None))

    return Discovery(
        apps=tuple(apps),
        dashboard_service=dashboard_service,
        compose_config=config,
        secrets_dir=secrets_dir,
        container_uid=uid,
        container_gid=gid,
    )


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _registry_text(apps: tuple[AppSpec, ...]) -> str:
    output = [
        "# Generated by scripts/migrate_qnap_registry.py",
        "# Application identity/control-plane configuration only; no secret values.",
        "",
    ]
    for app in apps:
        output.extend(
            [
                "[[apps]]",
                f"id = {_toml_string(app.instance_id)}",
                f"name = {_toml_string(app.name)}",
                "profiles = ["
                + ", ".join(_toml_string(item) for item in app.profiles)
                + "]",
                "",
                "[apps.dashboard]",
                f"url = {_toml_string(app.dashboard_url)}",
                "",
                "[apps.deployment]",
                f"service = {_toml_string(app.service)}",
            ]
        )
        if app.cloudflare:
            zone_id = str(app.cloudflare.get("zone_id") or "").strip()
            hosts_raw = app.cloudflare.get("hosts")
            if not zone_id or not isinstance(hosts_raw, list) or not hosts_raw:
                raise MigrationError(
                    f"Cloudflare mapping for {app.instance_id!r} requires zone_id and hosts"
                )
            hosts = sorted(
                {
                    str(item).strip().lower().rstrip(".")
                    for item in hosts_raw
                    if str(item).strip()
                }
            )
            if not hosts:
                raise MigrationError(
                    f"Cloudflare mapping for {app.instance_id!r} has no usable hosts"
                )
            output.extend(
                [
                    "",
                    "[apps.cloudflare]",
                    f"zone_id = {_toml_string(zone_id)}",
                    "hosts = ["
                    + ", ".join(_toml_string(item) for item in hosts)
                    + "]",
                ]
            )
        output.extend(
            [
                "",
                "[apps.credentials]",
                (
                    "collector_token_file = "
                    + _toml_string(
                        f"/run/secrets/{app.instance_id}/collector_token"
                    )
                ),
                (
                    "policy_token_file = "
                    + _toml_string(
                        f"/run/secrets/{app.instance_id}/policy_token"
                    )
                ),
                "",
            ]
        )
    return "\n".join(output).rstrip() + "\n"


def _container_secret_source(path: str, secrets_dir: Path) -> Path:
    prefix = "/run/secrets/"
    if not path.startswith(prefix):
        raise MigrationError(
            f"Cannot automatically migrate secret file outside {prefix}: {path}"
        )
    relative = path[len(prefix) :]
    if not relative or ".." in Path(relative).parts:
        raise MigrationError(f"Unsafe secret-file path: {path}")
    return secrets_dir / relative


def _shared_core_secret_values(
    hotpot_env: str,
    *,
    secrets_dir: Path,
) -> dict[str, str]:
    env = _env_map(hotpot_env)
    result: dict[str, str] = {}
    for key, filename in CORE_SHARED_SECRET_KEYS.items():
        file_key = f"{key}_FILE"
        file_value = env.get(file_key, "").strip()
        direct_value = env.get(key, "")
        if file_value:
            source = _container_secret_source(file_value, secrets_dir)
            try:
                value = source.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise MigrationError(
                    f"Could not read legacy shared secret {file_key} from {source}: {exc}"
                ) from exc
            if not value:
                raise MigrationError(f"Legacy shared secret {source} is empty")
            result[filename] = value
        elif direct_value:
            result[filename] = direct_value
    return result


def _per_service_secret_env(
    app: AppSpec,
    copied_secret_values: dict[str, str],
) -> dict[str, str]:
    by_filename = {value: key for key, value in CORE_SHARED_SECRET_KEYS.items()}
    return {
        f"{by_filename[filename]}_FILE": f"/run/secrets/{app.instance_id}/{filename}"
        for filename in copied_secret_values
    }


def _build_candidate(
    *,
    compose_text: str,
    hotpot_env_text: str,
    dashboard_env_text: str,
    discovery: Discovery,
    registry: Path,
) -> Candidate:
    copied_secret_values = _shared_core_secret_values(
        hotpot_env_text, secrets_dir=discovery.secrets_dir
    )
    replacements: dict[str, str] = {}
    spans = _service_spans(compose_text)
    lines = compose_text.splitlines(keepends=True)

    for app in discovery.apps:
        if app.service not in spans:
            raise MigrationError(
                f"Compose config service {app.service!r} is not present in source YAML"
            )
        start, stop = spans[app.service]
        block = "".join(lines[start:stop])
        replacements[app.service] = _modify_core_block(
            block,
            app=app,
            registry=registry,
            secrets_dir=discovery.secrets_dir,
            per_service_secret_files=_per_service_secret_env(
                app, copied_secret_values
            ),
        )

    if discovery.dashboard_service not in spans:
        raise MigrationError(
            f"Dashboard service {discovery.dashboard_service!r} is not present in source YAML"
        )
    start, stop = spans[discovery.dashboard_service]
    replacements[discovery.dashboard_service] = _modify_dashboard_block(
        "".join(lines[start:stop]),
        registry=registry,
        secrets_dir=discovery.secrets_dir,
    )

    compose_candidate = _replace_service_blocks(compose_text, replacements)
    hotpot_remove = {
        "HOTPOT_ADMIN_TOKEN",
        "HOTPOT_ADMIN_TOKEN_FILE",
        "HOTPOT_PROFILES",
    }
    for key in CORE_SHARED_SECRET_KEYS:
        hotpot_remove.add(key)
        hotpot_remove.add(f"{key}_FILE")
    hotpot_candidate = _rewrite_env(
        hotpot_env_text,
        remove=hotpot_remove,
        note=(
            "App names, profiles and scoped credentials are now defined in "
            "hotpot-apps.toml."
        ),
    )
    dashboard_candidate = _rewrite_env(
        dashboard_env_text,
        remove={
            "HOTPOT_ADMIN_TOKEN",
            "HOTPOT_ADMIN_TOKEN_FILE",
            "HOTPOT_DASHBOARD_INSTANCES",
            "HOTPOT_CLOUDFLARE_TARGETS",
            "HOTPOT_APP_REGISTRY",
        },
        additions={"HOTPOT_APP_REGISTRY": "/config/apps.toml"},
        note="Protected-app discovery now comes from hotpot-apps.toml.",
    )
    return Candidate(
        compose=compose_candidate,
        hotpot_env=hotpot_candidate,
        dashboard_env=dashboard_candidate,
        registry=_registry_text(discovery.apps),
        copied_secret_values=copied_secret_values,
    )


def _redact_text(text: str) -> str:
    result: list[str] = []
    env_re = re.compile(
        r"^(\s*(?:-\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*)(.*)$"
    )
    for line in text.splitlines():
        match = env_re.match(line)
        if match and SECRET_KEY_RE.search(match.group(2)):
            result.append(match.group(1) + "<redacted>")
        else:
            result.append(line)
    return "\n".join(result) + ("\n" if text.endswith("\n") else "")


def _print_diff(label: str, before: str, after: str, *, redact: bool = False) -> None:
    if before == after:
        print(f"\n{label}: no changes")
        return
    if redact:
        before = _redact_text(before)
        after = _redact_text(after)
    print(f"\n--- {label} ---")
    sys.stdout.writelines(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"{label}.before",
            tofile=f"{label}.after",
        )
    )


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _atomic_write(path: Path, text: str, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    prior_mode = None
    try:
        prior_mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        pass
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode if mode is not None else prior_mode or 0o600)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _apply_owner(path: Path, uid: int | None, gid: int | None) -> None:
    if uid is None:
        return
    target_gid = -1 if gid is None else gid
    try:
        os.chown(path, uid, target_gid)
    except PermissionError:
        current = path.stat()
        if current.st_uid != uid or (gid is not None and current.st_gid != gid):
            raise MigrationError(
                f"{path} must be readable by container user "
                f"{uid}:{gid if gid is not None else current.st_gid}; "
                "run the migration with sufficient permissions or fix ownership manually"
            )


def _ensure_secret_file(
    path: Path,
    *,
    value: str,
    uid: int | None,
    gid: int | None,
    created: list[Path],
) -> None:
    if path.exists():
        current = path.read_text(encoding="utf-8").strip()
        if not current:
            raise MigrationError(f"Existing secret file is empty: {path}")
        if current != value:
            raise MigrationError(
                f"Existing secret file differs from the migration value: {path}. "
                "Refusing to overwrite it."
            )
        os.chmod(path, 0o600)
        _apply_owner(path, uid, gid)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    _apply_owner(path.parent, uid, gid)
    _atomic_write(path, value + "\n", mode=0o600)
    _apply_owner(path, uid, gid)
    created.append(path)


def _backup_files(
    backup_root: Path,
    paths: list[Path],
) -> tuple[Path, dict[Path, Path | None]]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = backup_root / stamp
    suffix = 0
    while target.exists():
        suffix += 1
        target = backup_root / f"{stamp}-{suffix}"
    target.mkdir(parents=True, exist_ok=False)
    backups: dict[Path, Path | None] = {}
    for path in paths:
        if path.exists():
            backup = target / path.name
            shutil.copy2(path, backup)
            backups[path] = backup
        else:
            backups[path] = None
    return target, backups


def _restore_backups(backups: dict[Path, Path | None]) -> None:
    for original, backup in backups.items():
        if backup is None:
            original.unlink(missing_ok=True)
        else:
            shutil.copy2(backup, original)


def _already_migrated(config: dict[str, Any], registry: Path) -> bool:
    services = config.get("services") or {}
    cores = []
    dashboards = []
    for service in services.values():
        if not isinstance(service, dict):
            continue
        env = _normalized_environment(service)
        if env.get("HOTPOT_INSTANCE_ID") and env.get("HOTPOT_UPSTREAM"):
            cores.append(env)
        image = str(service.get("image") or "").lower()
        if "hotpot-dashboard" in image or "HOTPOT_DASHBOARD_DATA_DIR" in env:
            dashboards.append(env)
    return bool(
        registry.exists()
        and cores
        and all(env.get("HOTPOT_APP_REGISTRY") for env in cores)
        and dashboards
        and all(env.get("HOTPOT_APP_REGISTRY") for env in dashboards)
    )


def _print_plan(
    discovery: Discovery,
    candidate: Candidate,
    *,
    compose: Path,
    hotpot_env: Path,
    dashboard_env: Path,
    registry: Path,
    before_compose: str,
    before_hotpot_env: str,
    before_dashboard_env: str,
) -> None:
    print("Hotpot QNAP app-registry migration plan")
    print(f"  compose:       {compose}")
    print(f"  hotpot env:    {hotpot_env}")
    print(f"  dashboard env: {dashboard_env}")
    print(f"  registry:      {registry}")
    print(f"  secrets root:  {discovery.secrets_dir}")
    print(f"  applications:  {len(discovery.apps)}")
    for app in discovery.apps:
        print(
            f"    - {app.instance_id}: service={app.service}, "
            f"profiles={','.join(app.profiles)}, dashboard={app.dashboard_url}"
        )
    print(
        "  credentials:   generate unique collector + policy tokens per app "
        "(values are never printed)"
    )
    if candidate.copied_secret_values:
        print(
            "  shared secrets: copy "
            + ", ".join(sorted(candidate.copied_secret_values))
            + " into each app's scoped secret directory"
        )
    print("  restart policy: none; this tool only changes configuration")

    _print_diff(
        str(compose),
        before_compose,
        candidate.compose,
        redact=True,
    )
    _print_diff(
        str(hotpot_env),
        before_hotpot_env,
        candidate.hotpot_env,
        redact=True,
    )
    _print_diff(
        str(dashboard_env),
        before_dashboard_env,
        candidate.dashboard_env,
        redact=True,
    )
    print(f"\n--- {registry} (new) ---")
    print(candidate.registry, end="")


def _apply(
    *,
    discovery: Discovery,
    candidate: Candidate,
    compose: Path,
    hotpot_env: Path,
    dashboard_env: Path,
    registry: Path,
    backup_root: Path,
    docker_bin: str,
) -> Path:
    backup_dir, backups = _backup_files(
        backup_root,
        [compose, hotpot_env, dashboard_env, registry],
    )
    created_secret_files: list[Path] = []
    try:
        for app in discovery.apps:
            app_dir = discovery.secrets_dir / app.instance_id
            app_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(app_dir, 0o700)
            _apply_owner(
                app_dir, discovery.container_uid, discovery.container_gid
            )

            collector = app_dir / "collector_token"
            policy = app_dir / "policy_token"
            collector_value = (
                collector.read_text(encoding="utf-8").strip()
                if collector.exists()
                else secrets.token_urlsafe(32)
            )
            policy_value = (
                policy.read_text(encoding="utf-8").strip()
                if policy.exists()
                else secrets.token_urlsafe(32)
            )
            if collector_value == policy_value:
                raise MigrationError(
                    f"Collector and policy tokens must differ for {app.instance_id}"
                )
            _ensure_secret_file(
                collector,
                value=collector_value,
                uid=discovery.container_uid,
                gid=discovery.container_gid,
                created=created_secret_files,
            )
            _ensure_secret_file(
                policy,
                value=policy_value,
                uid=discovery.container_uid,
                gid=discovery.container_gid,
                created=created_secret_files,
            )
            for filename, value in candidate.copied_secret_values.items():
                _ensure_secret_file(
                    app_dir / filename,
                    value=value,
                    uid=discovery.container_uid,
                    gid=discovery.container_gid,
                    created=created_secret_files,
                )

        _atomic_write(registry, candidate.registry, mode=0o644)
        _atomic_write(hotpot_env, candidate.hotpot_env)
        _atomic_write(dashboard_env, candidate.dashboard_env)
        _atomic_write(compose, candidate.compose)

        _run([docker_bin, "compose", "-f", str(compose), "config", "-q"])

        manifest = {
            "schema_version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "compose": str(compose),
            "hotpot_env": str(hotpot_env),
            "dashboard_env": str(dashboard_env),
            "registry": str(registry),
            "applications": [
                {
                    "id": app.instance_id,
                    "service": app.service,
                    "profiles": list(app.profiles),
                }
                for app in discovery.apps
            ],
            "post_migration_sha256": {
                str(compose): _sha256_text(candidate.compose),
                str(hotpot_env): _sha256_text(candidate.hotpot_env),
                str(dashboard_env): _sha256_text(candidate.dashboard_env),
                str(registry): _sha256_text(candidate.registry),
            },
        }
        _atomic_write(
            backup_dir / "migration-manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            mode=0o600,
        )
        return backup_dir
    except Exception:
        _restore_backups(backups)
        for path in reversed(created_secret_files):
            path.unlink(missing_ok=True)
        for app in discovery.apps:
            app_dir = discovery.secrets_dir / app.instance_id
            try:
                app_dir.rmdir()
            except OSError:
                pass
        raise


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Migrate a legacy QNAP Hotpot deployment to the centralized app "
            "registry and per-app scoped credentials. Default mode is read-only."
        )
    )
    parser.add_argument(
        "--compose",
        type=Path,
        default=DEFAULT_CONFIG_DIR / "docker-compose.yml",
    )
    parser.add_argument(
        "--hotpot-env",
        type=Path,
        default=DEFAULT_CONFIG_DIR / "hotpot.env",
    )
    parser.add_argument(
        "--dashboard-env",
        type=Path,
        default=DEFAULT_CONFIG_DIR / "dashboard.env",
    )
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--secrets-dir", type=Path)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--docker-bin", default="docker")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Atomically replace the current config after backup and validation.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rebuild candidates even when the deployment already appears migrated.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    compose = args.compose.expanduser().resolve()
    hotpot_env = args.hotpot_env.expanduser().resolve()
    dashboard_env = args.dashboard_env.expanduser().resolve()
    registry = (
        args.registry.expanduser().resolve()
        if args.registry
        else compose.parent / "hotpot-apps.toml"
    )
    backup_root = (
        args.backup_dir.expanduser().resolve()
        if args.backup_dir
        else compose.parent / "hotpot-migration-backups"
    )
    requested_secrets = (
        args.secrets_dir.expanduser().resolve() if args.secrets_dir else None
    )

    try:
        compose_text = _read_text(compose, "Compose file")
        hotpot_env_text = _read_text(hotpot_env, "Hotpot env file")
        dashboard_env_text = _read_text(dashboard_env, "dashboard env file")
        config = _compose_config(compose, args.docker_bin)

        if _already_migrated(config, registry) and not args.force:
            print(
                "Hotpot already appears to use HOTPOT_APP_REGISTRY for all cores "
                f"and the dashboard. Registry: {registry}"
            )
            return 0

        discovery = _discover(
            config, requested_secrets_dir=requested_secrets
        )
        candidate = _build_candidate(
            compose_text=compose_text,
            hotpot_env_text=hotpot_env_text,
            dashboard_env_text=dashboard_env_text,
            discovery=discovery,
            registry=registry,
        )

        _validate_compose_text(compose, candidate.compose, args.docker_bin)
        _print_plan(
            discovery,
            candidate,
            compose=compose,
            hotpot_env=hotpot_env,
            dashboard_env=dashboard_env,
            registry=registry,
            before_compose=compose_text,
            before_hotpot_env=hotpot_env_text,
            before_dashboard_env=dashboard_env_text,
        )

        if not args.apply:
            print(
                "\nPLAN ONLY: no files were changed. Re-run with --apply after "
                "reviewing this plan."
            )
            return 0

        backup_dir = _apply(
            discovery=discovery,
            candidate=candidate,
            compose=compose,
            hotpot_env=hotpot_env,
            dashboard_env=dashboard_env,
            registry=registry,
            backup_root=backup_root,
            docker_bin=args.docker_bin,
        )
        print("\n✓ Configuration migration completed.")
        print(f"  backup: {backup_dir}")
        print("  containers were NOT restarted.")
        print("\nNext:")
        print(
            f"  scripts/qnap-upgrade.sh --compose {compose} --dry-run"
        )
        print(
            f"  scripts/qnap-upgrade.sh --compose {compose}"
        )
        print(
            "Then verify Deployment and Policy in the dashboard before removing "
            "the backup."
        )
        return 0
    except MigrationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(
            f"ERROR: unexpected {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
