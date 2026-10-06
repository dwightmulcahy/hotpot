from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ImportError:  # pragma: no cover
    geoip2 = None  # type: ignore[assignment]
    AddressNotFoundError = LookupError  # type: ignore[assignment,misc]


class GeoIPEnricher:
    """Optional local MaxMind MMDB enrichment with automatic file reloads."""

    def __init__(self, *, asn_db=None, country_db=None, city_db=None) -> None:
        self.asn_path = self._path(asn_db if asn_db is not None else os.getenv("HOTPOT_GEOIP_ASN_DB", ""))
        self.country_path = self._path(country_db if country_db is not None else os.getenv("HOTPOT_GEOIP_COUNTRY_DB", ""))
        self.city_path = self._path(city_db if city_db is not None else os.getenv("HOTPOT_GEOIP_CITY_DB", ""))
        self.errors: list[str] = []
        self.asn_reader = self.country_reader = self.city_reader = None
        self.reload_count = 0
        self.last_reload_at: str | None = None
        self._signatures: dict[str, tuple[bool, int, int]] = {}
        if geoip2 is None:
            self.errors.append("geoip2 package is unavailable")
            return
        self.asn_reader = self._open(self.asn_path, "asn")
        self.country_reader = self._open(self.country_path, "country")
        self.city_reader = self._open(self.city_path, "city")
        self._signatures = self._current_signatures()
        if self.enabled:
            self.last_reload_at = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _path(value) -> Path | None:
        raw = str(value or "").strip()
        return Path(raw) if raw else None

    @staticmethod
    def _signature(path: Path | None) -> tuple[bool, int, int]:
        if path is None:
            return (False, 0, 0)
        try:
            stat = path.stat()
            return (path.is_file(), int(stat.st_mtime_ns), int(stat.st_size))
        except OSError:
            return (False, 0, 0)

    def _current_signatures(self) -> dict[str, tuple[bool, int, int]]:
        return {
            "asn": self._signature(self.asn_path),
            "country": self._signature(self.country_path),
            "city": self._signature(self.city_path),
        }

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

    @staticmethod
    def _close_reader(reader) -> None:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

    @property
    def enabled(self) -> bool:
        return any((self.asn_reader, self.country_reader, self.city_reader))

    def reload_if_changed(self) -> bool:
        """Reload MMDB readers when geoipupdate replaces a database on disk.

        The dashboard calls this on its normal refresh interval. New readers are
        opened before old readers are closed so a bad/incomplete replacement does
        not discard a working database. Successful reloads also clear the IP lookup
        cache so subsequent dashboard data uses the new database immediately.
        """

        if geoip2 is None:
            return False
        current = self._current_signatures()
        if current == self._signatures:
            return False

        changed = False
        new_errors: list[str] = []
        specs = (
            ("asn", self.asn_path, "asn_reader"),
            ("country", self.country_path, "country_reader"),
            ("city", self.city_path, "city_reader"),
        )
        for label, path, attr in specs:
            if current[label] == self._signatures.get(label):
                continue
            old_reader = getattr(self, attr)
            if path is None:
                self._close_reader(old_reader)
                setattr(self, attr, None)
                changed = True
                continue
            if not path.is_file():
                new_errors.append(f"{label} database not found: {path}")
                continue
            try:
                new_reader = geoip2.database.Reader(str(path))  # type: ignore[union-attr]
            except Exception as exc:
                new_errors.append(f"{label} database reload failed: {type(exc).__name__}")
                continue
            setattr(self, attr, new_reader)
            self._close_reader(old_reader)
            changed = True

        # Remember the observed files even if one could not be opened; another file
        # replacement changes the signature and triggers a new attempt. A failed file
        # remains represented in status while the previously working reader stays live.
        self._signatures = current
        self.errors = new_errors
        if changed:
            self.lookup.cache_clear()
            self.reload_count += 1
            self.last_reload_at = datetime.now(timezone.utc).isoformat()
        return changed

    def status(self) -> dict[str, Any]:
        signatures = self._current_signatures()
        return {
            "enabled": self.enabled,
            "source": "MaxMind local MMDB",
            "asn_loaded": self.asn_reader is not None,
            "country_loaded": self.country_reader is not None,
            "city_loaded": self.city_reader is not None,
            "reload_count": self.reload_count,
            "last_reload_at": self.last_reload_at,
            "databases": {
                name: {"present": sig[0], "mtime_ns": sig[1], "size": sig[2]}
                for name, sig in signatures.items()
            },
            "errors": list(self.errors),
        }

    @lru_cache(maxsize=20000)
    def lookup(self, ip: str) -> dict[str, Any]:
        result = {"asn": None, "provider": None, "country_code": None, "country": None, "city": None, "continent": None, "latitude": None, "longitude": None, "accuracy_radius_km": None, "enriched": False}
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
                rec = self.asn_reader.asn(ip)
                result.update(asn=rec.autonomous_system_number, provider=rec.autonomous_system_organization, enriched=True)
            except AddressNotFoundError:
                pass
            except Exception:
                result["asn_error"] = True
        if self.city_reader is not None:
            try:
                rec = self.city_reader.city(ip)
                result.update(country_code=rec.country.iso_code, country=rec.country.name, city=rec.city.name, continent=rec.continent.name, latitude=rec.location.latitude, longitude=rec.location.longitude, accuracy_radius_km=rec.location.accuracy_radius, enriched=True)
            except AddressNotFoundError:
                pass
            except Exception:
                result["geo_error"] = True
        elif self.country_reader is not None:
            try:
                rec = self.country_reader.country(ip)
                result.update(country_code=rec.country.iso_code, country=rec.country.name, continent=rec.continent.name, enriched=True)
            except AddressNotFoundError:
                pass
            except Exception:
                result["geo_error"] = True
        if not result["enriched"]:
            result["reason"] = "not_found"
        return result

    def close(self) -> None:
        for reader in (self.asn_reader, self.country_reader, self.city_reader):
            self._close_reader(reader)
