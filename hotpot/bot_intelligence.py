from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


DEFAULT_CRAWLERS_URL = (
    "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/crawlers.json"
)
DEFAULT_MONITORING_URL = (
    "https://raw.githubusercontent.com/ipverse/bot-ip-blocks/master/monitoring.json"
)
MAX_FEED_BYTES = 10 * 1024 * 1024
MAX_SERVICES = 2000
MAX_PREFIXES = 100_000
MAX_UA_PATTERNS = 20_000


@dataclass(frozen=True)
class BotObservation:
    source: str | None = None
    identity: str | None = None
    category: str | None = None
    claimed_identity: str | None = None
    claimed_category: str | None = None
    ip_identity: str | None = None
    ip_category: str | None = None
    verified: bool = False
    claim_verified: bool = False
    spoofed: bool = False
    authoritative_claim: bool = False

    def event_fields(self) -> dict[str, Any]:
        return {
            "bot_source": self.source,
            "bot_identity": self.identity,
            "bot_category": self.category,
            "bot_claimed_identity": self.claimed_identity,
            "bot_claimed_category": self.claimed_category,
            "bot_ip_identity": self.ip_identity,
            "bot_ip_category": self.ip_category,
            "bot_verified": self.verified,
            "bot_claim_verified": self.claim_verified,
            "bot_spoofed": self.spoofed,
            "bot_authoritative_claim": self.authoritative_claim,
        }


@dataclass(frozen=True)
class _Service:
    name: str
    category: str
    authoritative: bool


class IPverseBotIntelligence:
    """Local, cached attribution for IPverse crawler and monitor prefixes.

    The feed is enrichment only. A verified bot never bypasses deception or an
    existing Hotpot policy. A claimed crawler UA outside an authoritative published
    range is marked as spoofed and can contribute a small severity bonus.
    """

    def __init__(self, data_dir: Path) -> None:
        self.enabled = _env_bool("HOTPOT_IPVERSE_ENABLED", True)
        self.crawlers_url = os.getenv(
            "HOTPOT_IPVERSE_CRAWLERS_URL", DEFAULT_CRAWLERS_URL
        ).strip()
        self.monitoring_url = os.getenv(
            "HOTPOT_IPVERSE_MONITORING_URL", DEFAULT_MONITORING_URL
        ).strip()
        self.refresh_seconds = max(
            3600, int(float(os.getenv("HOTPOT_IPVERSE_REFRESH_HOURS", "24")) * 3600)
        )
        self.request_timeout = max(
            1.0, float(os.getenv("HOTPOT_IPVERSE_TIMEOUT_SECONDS", "10"))
        )
        self.cache_path = data_dir / "ipverse-bot-ip-blocks.json"
        self._services: dict[str, _Service] = {}
        self._networks_v4: list[tuple[ipaddress.IPv4Network, _Service]] = []
        self._networks_v6: list[tuple[ipaddress.IPv6Network, _Service]] = []
        self._ua_patterns: list[tuple[str, _Service]] = []
        self._fetched_at: float | None = None
        self._loaded_at: float | None = None
        self._last_error: str | None = None
        self._refresh_task: asyncio.Task | None = None
        self._load_cache()

    @property
    def loaded(self) -> bool:
        return bool(self._services)

    @property
    def stale(self) -> bool:
        if self._fetched_at is None:
            return True
        return time.time() - self._fetched_at >= self.refresh_seconds

    def status(self) -> dict[str, Any]:
        age_seconds = None
        if self._fetched_at is not None:
            age_seconds = max(0, int(time.time() - self._fetched_at))
        return {
            "enabled": self.enabled,
            "loaded": self.loaded,
            "source": "ipverse/bot-ip-blocks",
            "services": len(self._services),
            "ipv4_prefixes": len(self._networks_v4),
            "ipv6_prefixes": len(self._networks_v6),
            "ua_patterns": len(self._ua_patterns),
            "fetched_at_epoch": self._fetched_at,
            "age_seconds": age_seconds,
            "stale": self.stale,
            "refresh_seconds": self.refresh_seconds,
            "last_error": self._last_error,
        }

    async def start(self) -> None:
        if not self.enabled or self._refresh_task is not None:
            return
        self._refresh_task = asyncio.create_task(
            self._refresh_loop(), name="hotpot-ipverse-refresh"
        )

    async def stop(self) -> None:
        if self._refresh_task is None:
            return
        self._refresh_task.cancel()
        await asyncio.gather(self._refresh_task, return_exceptions=True)
        self._refresh_task = None

    async def _refresh_loop(self) -> None:
        while True:
            try:
                if self.stale:
                    await asyncio.to_thread(self.refresh)
                await asyncio.sleep(min(self.refresh_seconds, 3600))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._last_error = f"{type(exc).__name__}: {exc}"
                await asyncio.sleep(min(self.refresh_seconds, 3600))

    def refresh(self) -> bool:
        if not self.enabled:
            return False
        try:
            payload = {
                "fetched_at": time.time(),
                "feeds": {
                    "crawler": self._fetch_json(self.crawlers_url),
                    "monitor": self._fetch_json(self.monitoring_url),
                },
            }
            self._apply_payload(payload)
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, self.cache_path)
            self._last_error = None
            return True
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"
            return False

    def _fetch_json(self, url: str) -> dict[str, Any]:
        if not url.lower().startswith("https://"):
            raise ValueError("IPverse feed URL must use https")
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "hotpot-ipverse-intelligence/1"},
        )
        with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
            raw = response.read(MAX_FEED_BYTES + 1)
        if len(raw) > MAX_FEED_BYTES:
            raise ValueError("IPverse feed exceeded maximum size")
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict) or not isinstance(parsed.get("services"), dict):
            raise ValueError("IPverse feed did not contain a services object")
        return parsed

    def _load_cache(self) -> None:
        if not self.enabled or not self.cache_path.is_file():
            return
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            self._apply_payload(payload)
        except Exception as exc:
            self._last_error = f"cache {type(exc).__name__}: {exc}"

    def _apply_payload(self, payload: dict[str, Any]) -> None:
        feeds = payload.get("feeds")
        if not isinstance(feeds, dict):
            raise ValueError("IPverse cache is missing feeds")

        services: dict[str, _Service] = {}
        networks_v4: list[tuple[ipaddress.IPv4Network, _Service]] = []
        networks_v6: list[tuple[ipaddress.IPv6Network, _Service]] = []
        ua_patterns: list[tuple[str, _Service]] = []
        prefix_count = 0
        pattern_count = 0

        for category in ("crawler", "monitor"):
            document = feeds.get(category, {})
            raw_services = document.get("services") if isinstance(document, dict) else None
            if not isinstance(raw_services, dict):
                raise ValueError(f"IPverse {category} feed is missing services")
            for name, raw in raw_services.items():
                if len(services) >= MAX_SERVICES:
                    raise ValueError("IPverse service limit exceeded")
                if not isinstance(name, str) or not isinstance(raw, dict):
                    continue
                service = _Service(
                    name=name[:160],
                    category=category,
                    authoritative=bool(raw.get("ip_list_authoritative", False)),
                )
                services[service.name.lower()] = service

                patterns = raw.get("user_agent_patterns") or []
                if isinstance(patterns, list):
                    for pattern in patterns:
                        if not isinstance(pattern, str) or not pattern.strip():
                            continue
                        pattern_count += 1
                        if pattern_count > MAX_UA_PATTERNS:
                            raise ValueError("IPverse user-agent pattern limit exceeded")
                        ua_patterns.append((pattern.strip().lower()[:512], service))

                for key in ("ipv4", "ipv6"):
                    values = raw.get(key) or []
                    if not isinstance(values, list):
                        continue
                    for cidr in values:
                        if not isinstance(cidr, str):
                            continue
                        try:
                            network = ipaddress.ip_network(cidr.strip(), strict=False)
                        except ValueError:
                            continue
                        prefix_count += 1
                        if prefix_count > MAX_PREFIXES:
                            raise ValueError("IPverse prefix limit exceeded")
                        if isinstance(network, ipaddress.IPv4Network):
                            networks_v4.append((network, service))
                        else:
                            networks_v6.append((network, service))

        networks_v4.sort(key=lambda item: item[0].prefixlen, reverse=True)
        networks_v6.sort(key=lambda item: item[0].prefixlen, reverse=True)
        ua_patterns.sort(key=lambda item: len(item[0]), reverse=True)

        self._services = services
        self._networks_v4 = networks_v4
        self._networks_v6 = networks_v6
        self._ua_patterns = ua_patterns
        fetched_at = payload.get("fetched_at")
        self._fetched_at = float(fetched_at) if fetched_at is not None else None
        self._loaded_at = time.time()
        self._identify_cached.cache_clear()
        self._ip_service.cache_clear()
        self._ua_service.cache_clear()

    def identify(self, client_ip: str, user_agent: str) -> BotObservation:
        if not self.enabled or not self.loaded:
            return BotObservation()
        return self._identify_cached(client_ip.strip(), user_agent.strip()[:1024])

    @lru_cache(maxsize=8192)
    def _identify_cached(self, client_ip: str, user_agent: str) -> BotObservation:
        ip_service = self._ip_service(client_ip)
        ua_service = self._ua_service(user_agent)

        same_claim = bool(
            ip_service is not None
            and ua_service is not None
            and ip_service.name.lower() == ua_service.name.lower()
        )
        spoofed = bool(
            ua_service is not None
            and ua_service.authoritative
            and not same_claim
        )
        identity = ip_service or ua_service
        return BotObservation(
            source="ipverse" if identity is not None else None,
            identity=identity.name if identity is not None else None,
            category=identity.category if identity is not None else None,
            claimed_identity=ua_service.name if ua_service is not None else None,
            claimed_category=ua_service.category if ua_service is not None else None,
            ip_identity=ip_service.name if ip_service is not None else None,
            ip_category=ip_service.category if ip_service is not None else None,
            verified=ip_service is not None,
            claim_verified=same_claim,
            spoofed=spoofed,
            authoritative_claim=bool(ua_service and ua_service.authoritative),
        )

    @lru_cache(maxsize=8192)
    def _ip_service(self, client_ip: str) -> _Service | None:
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return None
        networks = self._networks_v4 if address.version == 4 else self._networks_v6
        for network, service in networks:
            if address in network:
                return service
        return None

    @lru_cache(maxsize=2048)
    def _ua_service(self, user_agent: str) -> _Service | None:
        lowered = user_agent.lower()
        if not lowered:
            return None
        for pattern, service in self._ua_patterns:
            if fnmatch.fnmatchcase(lowered, pattern):
                return service
        return None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
