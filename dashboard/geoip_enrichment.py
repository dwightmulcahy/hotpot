from __future__ import annotations

import ipaddress
import os
import time
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
    """Optional local MaxMind MMDB enrichment with resilient file reloads."""

    EMPTY_SIGNATURE = (False, 0, 0)

    def __init__(self, *, asn_db=None, country_db=None, city_db=None) -> None:
        self.asn_path = self._path(
            asn_db if asn_db is not None else os.getenv("HOTPOT_GEOIP_ASN_DB", "")
        )
        self.country_path = self._path(
            country_db
            if country_db is not None
            else os.getenv("HOTPOT_GEOIP_COUNTRY_DB", "")
        )
        self.city_path = self._path(
            city_db if city_db is not None else os.getenv("HOTPOT_GEOIP_CITY_DB", "")
        )
        self.errors: list[str] = []
        self.asn_reader = self.country_reader = self.city_reader = None
        self.reload_count = 0
        self.reload_failure_count = 0
        self.last_reload_at: str | None = None
        self.last_reload_error_at: str | None = None
        # _signatures represents the files actually accepted by the live readers,
        # not merely files observed on disk. A bad replacement therefore remains
        # different and is retried on the next refresh.
        self._signatures: dict[str, tuple[bool, int, int]] = {
            "asn": self.EMPTY_SIGNATURE,
            "country": self.EMPTY_SIGNATURE,
            "city": self.EMPTY_SIGNATURE,
        }
        if geoip2 is None:
            self.errors.append("geoip2 package is unavailable")
            return

        self.asn_reader = self._open(self.asn_path, "asn")
        self.country_reader = self._open(self.country_path, "country")
        self.city_reader = self._open(self.city_path, "city")
        current = self._current_signatures()
        for label, path, reader in (
            ("asn", self.asn_path, self.asn_reader),
            ("country", self.country_path, self.country_reader),
            ("city", self.city_path, self.city_reader),
        ):
            if path is None or reader is not None:
                self._signatures[label] = current[label]
        if self.enabled:
            self.last_reload_at = datetime.now(timezone.utc).isoformat()
        if self.errors:
            self.last_reload_error_at = datetime.now(timezone.utc).isoformat()

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

    @staticmethod
    def _revision_for(signatures: dict[str, tuple[bool, int, int]]) -> str:
        parts = [
            f"{name}:{1 if sig[0] else 0}:{sig[1]}:{sig[2]}"
            for name, sig in sorted(signatures.items())
        ]
        return "|".join(parts) or "geoip-unconfigured"

    def revision(self) -> str:
        """Return the revision represented by the currently loaded readers."""

        return self._revision_for(self._signatures)

    @staticmethod
    def _database_status(sig: tuple[bool, int, int]) -> dict[str, Any]:
        present, mtime_ns, size = sig
        mtime_at = None
        age_seconds = None
        if present and mtime_ns > 0:
            mtime_at = datetime.fromtimestamp(
                mtime_ns / 1_000_000_000, tz=timezone.utc
            ).isoformat()
            age_seconds = max(0, int((time.time_ns() - mtime_ns) / 1_000_000_000))
        return {
            "present": present,
            "mtime_ns": mtime_ns,
            "mtime_at": mtime_at,
            "age_seconds": age_seconds,
            "size": size,
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
            self.errors.append(
                f"{label} database failed to open: {type(exc).__name__}"
            )
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
        """Reload changed MMDB files without acknowledging failed replacements.

        Readers are opened before old readers are closed. If a replacement is
        incomplete/corrupt, the working reader and its accepted signature remain
        active. Because the bad on-disk signature is not recorded as accepted, the
        exact same file is retried on every normal dashboard refresh until it can be
        opened or is replaced again.
        """

        if geoip2 is None:
            return False
        current = self._current_signatures()
        if current == self._signatures:
            return False

        changed = False
        new_errors: list[str] = []
        accepted = dict(self._signatures)
        failure_count = 0
        specs = (
            ("asn", self.asn_path, "asn_reader"),
            ("country", self.country_path, "country_reader"),
            ("city", self.city_path, "city_reader"),
        )
        for label, path, attr in specs:
            if current[label] == accepted.get(label, self.EMPTY_SIGNATURE):
                continue
            old_reader = getattr(self, attr)
            if path is None:
                self._close_reader(old_reader)
                setattr(self, attr, None)
                accepted[label] = current[label]
                changed = True
                continue
            if not path.is_file():
                new_errors.append(f"{label} database not found: {path}")
                failure_count += 1
                continue
            try:
                new_reader = geoip2.database.Reader(str(path))  # type: ignore[union-attr]
            except Exception as exc:
                new_errors.append(
                    f"{label} database reload failed: {type(exc).__name__}"
                )
                failure_count += 1
                continue

            setattr(self, attr, new_reader)
            self._close_reader(old_reader)
            accepted[label] = current[label]
            changed = True

        self._signatures = accepted
        self.errors = new_errors
        if failure_count:
            self.reload_failure_count += failure_count
            self.last_reload_error_at = datetime.now(timezone.utc).isoformat()
        if changed:
            self.lookup.cache_clear()
            self.reload_count += 1
            self.last_reload_at = datetime.now(timezone.utc).isoformat()
        return changed

    def status(self) -> dict[str, Any]:
        observed = self._current_signatures()
        databases = {
            name: self._database_status(sig) for name, sig in observed.items()
        }
        for name, info in databases.items():
            loaded = self._signatures.get(name, self.EMPTY_SIGNATURE)
            info["loaded_signature"] = {
                "present": loaded[0],
                "mtime_ns": loaded[1],
                "size": loaded[2],
            }
            info["reload_pending"] = observed[name] != loaded
        ages = [
            int(info["age_seconds"])
            for info in databases.values()
            if info.get("age_seconds") is not None
        ]
        return {
            "enabled": self.enabled,
            "source": "MaxMind local MMDB",
            "asn_loaded": self.asn_reader is not None,
            "country_loaded": self.country_reader is not None,
            "city_loaded": self.city_reader is not None,
            "reload_count": self.reload_count,
            "reload_failure_count": self.reload_failure_count,
            "last_reload_at": self.last_reload_at,
            "last_reload_error_at": self.last_reload_error_at,
            "revision": self.revision(),
            "observed_revision": self._revision_for(observed),
            "reload_pending": observed != self._signatures,
            "oldest_database_age_seconds": max(ages) if ages else None,
            "newest_database_age_seconds": min(ages) if ages else None,
            "databases": databases,
            "errors": list(self.errors),
        }

    @lru_cache(maxsize=20000)
    def lookup(self, ip: str) -> dict[str, Any]:
        result = {
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
                rec = self.asn_reader.asn(ip)
                result.update(
                    asn=rec.autonomous_system_number,
                    provider=rec.autonomous_system_organization,
                    enriched=True,
                )
            except AddressNotFoundError:
                pass
            except Exception:
                result["asn_error"] = True
        if self.city_reader is not None:
            try:
                rec = self.city_reader.city(ip)
                result.update(
                    country_code=rec.country.iso_code,
                    country=rec.country.name,
                    city=rec.city.name,
                    continent=rec.continent.name,
                    latitude=rec.location.latitude,
                    longitude=rec.location.longitude,
                    accuracy_radius_km=rec.location.accuracy_radius,
                    enriched=True,
                )
            except AddressNotFoundError:
                pass
            except Exception:
                result["geo_error"] = True
        elif self.country_reader is not None:
            try:
                rec = self.country_reader.country(ip)
                result.update(
                    country_code=rec.country.iso_code,
                    country=rec.country.name,
                    continent=rec.continent.name,
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
            self._close_reader(reader)
