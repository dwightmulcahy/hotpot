from __future__ import annotations

import ipaddress


class Allowlist:
    def __init__(self, cidrs: tuple[str, ...]):
        networks = []
        for value in cidrs:
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError as exc:
                raise RuntimeError(f"Invalid HOTPOT_ALLOW_CIDRS entry: {value}") from exc
        self.networks = tuple(networks)

    def contains(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address.version == network.version and address in network for network in self.networks)
