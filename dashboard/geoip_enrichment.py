from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ImportError:  # pragma: no cover - exercised through disabled status in minimal installs
    geoip2 = None  # type: ignore[assignment]
    AddressNotFoundError = LookupError  # type: ignore[assignment,misc]


class GeoIPEnricher:
    """Optional local MaxMind enrichment for centralized attacker intelligence.

    No external API calls are performed. Enrichment is enabled only when one or more
    configured MMDB files exist. GeoLite2 ASN, Country, and City databases are
    supported; City takes precedence over Country for geographic fields.
    """

    def __init__(
        self,
        *,
        asn_db: str | Path | None = None,
        country_db: str | Path | None = None,
        city_db: str | Path | None = None,
    ) -> None:
        self.asn_path = self._normalize_path(
            asn_db if asn_db is not None else os.getenv("HOTPOT_GEOIP_ASN_DB", "")
        )
        self.country_path = self._normalize_path(
            country_db if country_db is not None else os.getenv("HOTPOT_GEOIP_COUNTRY_DB", "")
        )
        self.city_path = self._normalize_path(
            city_db if city_db is not None else os.getenv("HOTPOT_GEOIP_CITY_DB", "")
        )

        self.asn_reader = None
        self.country_reader = None
        self.city_reader = None
        self.errors: list[str] = []

        if geoip2 is None:
            self.errors.append("geoip2 package is unavailable")
            return

        self.asn_reader = self._open(self.asn_path, "asn")
        self.country_reader = self._open(self.country_path, "country")
        self.city_reader = self._open(self.city_path, "city")

    @staticmethod
    def _normalize_path(value: str | Path | None) -> Path | None:
        if value is None:
            return None
        raw = str(value).strip()
        return Path(raw) if raw else None

    def _open(self, path: Path | None, label: str):
        if path is None:
            return None
        if not path.is_file():
            self.errors.append(f"{label} database not found: {path}")
            return None
        try:
            return geoip2.database.Reader(str(path))  # type: ignore[union-attr]
        except Exception as exc:
            self.errors.append(f"{label} database failed to open: {type(exc).__name__}")
            return None

    @property
    def enabled(self) -> bool:
        return any((self.asn_reader, self.country_reader, self.city_reader))

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "asn": self._db_status(self.asn_path, self.asn_reader),
            "country": self._db_status(self.country_path, self.country_reader),
            "city": self._db_status(self.city_path, self.city_reader),
            "errors": list(self.errors),
            "source": "MaxMind local MMDB",
        }

    @staticmethod
    def _db_status(path: Path | None, reader) -> dict[str, Any]:
        result: dict[str, Any] = {
            "configured": path is not None,
            "loaded": reader is not None,
            "path": str(path) if path is not None else None,
        }
        if path is not None and path.exists():
            stat = path.stat()
            result["size_bytes"] = stat.st_size
            result["modified_epoch"] = int(stat.st_mtime)
        return result

    @lru_cache(maxsize=20_000)
    def lookup(self, ip: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ip": ip,
            "asn": None,
            "provider": None,
            "country_code": None,
            "country": None,
            "city": None,
            "continent": None,
            "latitude": None,
            "longitude": None,
            "accuracy_radius_km": None,
            "enriched": False,
        }

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            result["reason"] = "invalid_ip"
            return result

        if not address.is_global:
            result["reason"] = "non_global_ip"
            return result

        if self.asn_reader is not None:
            try:
                record = self.asn_reader.asn(ip)
                result["asn"] = record.autonomous_system_number
                result["provider"] = record.autonomous_system_organization
                result["enriched"] = True
            except AddressNotFoundError:
                pass
            except Exception:
                result["asn_error"] = True

        # City includes country and continent data, so use it preferentially when
        # available and fall back to the smaller Country database otherwise.
        if self.city_reader is not None:
            try:
                record = self.city_reader.city(ip)
                result.update(
                    country_code=record.country.iso_code,
                    country=record.country.name,
                    city=record.city.name,
                    continent=record.continent.name,
                    latitude=record.location.latitude,
                    longitude=record.location.longitude,
                    accuracy_radius_km=record.location.accuracy_radius,
                    enriched=True,
                )
            except AddressNotFoundError:
                pass
            except Exception:
                result["geo_error"] = True
        elif self.country_reader is not None:
            try:
                record = self.country_reader.country(ip)
                result.update(
                    country_code=record.country.iso_code,
                    country=record.country.name,
                    continent=record.continent.name,
                    enriched=True,
                )
            except AddressNotFoundError:
                pass
            except Exception:
                result["geo_error"] = True

        if not result["enriched"]:
            result["reason"] = "not_found"
        return result

    def close(self) -> None:
        for reader in (self.asn_reader, self.country_reader, self.city_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
