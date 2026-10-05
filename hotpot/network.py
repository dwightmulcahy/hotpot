from __future__ import annotations

import ipaddress
from dataclasses import dataclass


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


def _valid_ip(value: str) -> str | None:
    candidate = value.strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


class ClientIPResolver:
    """Resolve the real client while refusing untrusted forwarding headers.

    Modes:
      direct:          always use the TCP peer.
      cloudflare:      use CF-Connecting-IP only from HOTPOT_TRUSTED_PROXY_CIDRS.
      x-forwarded-for: use the left-most X-Forwarded-For IP only from trusted proxies.
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
            return ClientIdentity(peer, peer, "peer", trusted)

        if self.mode == "cloudflare":
            value = headers.get("CF-Connecting-IP", "")
            client = _valid_ip(value)
            if client:
                return ClientIdentity(client, peer, "cf-connecting-ip", True)
            return ClientIdentity(peer, peer, "peer-invalid-cf-connecting-ip", True)

        # x-forwarded-for mode: only the left-most value represents the original client.
        value = headers.get("X-Forwarded-For", "")
        first = value.split(",", 1)[0].strip() if value else ""
        client = _valid_ip(first)
        if client:
            return ClientIdentity(client, peer, "x-forwarded-for", True)
        return ClientIdentity(peer, peer, "peer-invalid-x-forwarded-for", True)
