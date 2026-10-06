from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


CLOUDFLARE_WORKER_SHARED_IP = "2a06:98c0:3600::103"
_WORKER_ZONE_RE = re.compile(r"^[a-z0-9.-]+$")


class NetworkSet:
    def __init__(self, cidrs: tuple[str, ...], *, env_name: str):
        networks = []
        for value in cidrs:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise RuntimeError(f"Invalid {env_name} entry: {value}") from exc
        self.networks = tuple(networks)

    def contains(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address.version == network.version and address in network for network in self.networks)


class Allowlist(NetworkSet):
    def __init__(self, cidrs: tuple[str, ...]):
        super().__init__(cidrs, env_name="HOTPOT_ALLOW_CIDRS")


@dataclass(frozen=True)
class ClientIdentity:
    client_ip: str
    proxy_ip: str
    source: str
    trusted_proxy: bool
    actor_key: str
    source_type: str = "ip"
    worker_zone: str | None = None


def _valid_ip(value: str) -> str | None:
    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _normalize_worker_zone(value: str) -> str | None:
    zone = value.strip().lower().rstrip(".")
    if not zone or len(zone) > 253 or not _WORKER_ZONE_RE.fullmatch(zone):
        return None
    if ".." in zone or zone.startswith("-") or zone.endswith("-"):
        return None
    return zone


def _identity(
    client_ip: str,
    proxy_ip: str,
    source: str,
    trusted_proxy: bool,
    *,
    headers=None,
) -> ClientIdentity:
    actor_key = client_ip
    source_type = "ip"
    worker_zone = None

    # Cloudflare documents 2a06:98c0:3600::103 as the synthetic
    # CF-Connecting-IP value used for cross-zone Worker subrequests. It is a
    # shared Cloudflare address, not a stable end-user identity. CF-Worker is
    # only trusted here because this path is reached after the TCP peer has
    # passed HOTPOT_TRUSTED_PROXY_CIDRS.
    if trusted_proxy and client_ip == CLOUDFLARE_WORKER_SHARED_IP:
        raw_zone = headers.get("CF-Worker", "") if headers is not None else ""
        worker_zone = _normalize_worker_zone(raw_zone)
        source_type = "cloudflare-worker"
        actor_key = f"cf-worker:{worker_zone or 'unknown'}"
        source = "cf-worker"

    return ClientIdentity(
        client_ip=client_ip,
        proxy_ip=proxy_ip,
        source=source,
        trusted_proxy=trusted_proxy,
        actor_key=actor_key,
        source_type=source_type,
        worker_zone=worker_zone,
    )


class ClientIPResolver:
    """Resolve the real client while refusing untrusted forwarding headers.

    Modes:
      direct:          always use the TCP peer.
      cloudflare:      use CF-Connecting-IP only from HOTPOT_TRUSTED_PROXY_CIDRS.
      x-forwarded-for: use the left-most X-Forwarded-For IP only from trusted proxies.

    In Cloudflare mode, the documented cross-zone Worker synthetic address is
    split into a separate actor identity using the trusted CF-Worker header.
    """

    VALID_MODES = {"direct", "cloudflare", "x-forwarded-for"}

    def __init__(self, mode: str, trusted_proxy_cidrs: tuple[str, ...]):
        normalized = mode.strip().lower()
        if normalized not in self.VALID_MODES:
            allowed = ", ".join(sorted(self.VALID_MODES))
            raise RuntimeError(f"Invalid HOTPOT_CLIENT_IP_MODE: {mode}. Expected one of: {allowed}")
        self.mode = normalized
        self.trusted_proxies = NetworkSet(
            trusted_proxy_cidrs, env_name="HOTPOT_TRUSTED_PROXY_CIDRS"
        )
        if self.mode != "direct" and not self.trusted_proxies.networks:
            raise RuntimeError(
                "HOTPOT_TRUSTED_PROXY_CIDRS is required when HOTPOT_CLIENT_IP_MODE "
                f"is {self.mode!r}; refusing to trust spoofable forwarding headers"
            )

    def resolve(self, peer_ip: str, headers) -> ClientIdentity:
        peer = _valid_ip(peer_ip) or "unknown"
        trusted = peer != "unknown" and self.trusted_proxies.contains(peer)
        if self.mode == "direct" or not trusted:
            return _identity(peer, peer, "peer", trusted)

        if self.mode == "cloudflare":
            value = headers.get("CF-Connecting-IP", "")
            client = _valid_ip(value)
            if client:
                return _identity(
                    client,
                    peer,
                    "cf-connecting-ip",
                    True,
                    headers=headers,
                )
            return _identity(peer, peer, "peer-invalid-cf-connecting-ip", True)

        # x-forwarded-for mode: only the left-most value represents the original client.
        value = headers.get("X-Forwarded-For", "")
        first = value.split(",", 1)[0].strip() if value else ""
        client = _valid_ip(first)
        if client:
            return _identity(client, peer, "x-forwarded-for", True)
        return _identity(peer, peer, "peer-invalid-x-forwarded-for", True)
