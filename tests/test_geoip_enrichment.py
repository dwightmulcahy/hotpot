from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dashboard import geoip_enrichment as geoip_module
from dashboard.geoip_enrichment import GeoIPEnricher


class FakeASNReader:
    def asn(self, ip):
        return SimpleNamespace(
            autonomous_system_number=24940,
            autonomous_system_organization="Hetzner Online GmbH",
        )

    def close(self):
        pass


class FakeCityReader:
    def city(self, ip):
        return SimpleNamespace(
            country=SimpleNamespace(iso_code="DE", name="Germany"),
            city=SimpleNamespace(name="Falkenstein"),
            continent=SimpleNamespace(name="Europe"),
            location=SimpleNamespace(
                latitude=50.4779,
                longitude=12.3713,
                accuracy_radius=50,
            ),
        )

    def close(self):
        pass


class GeoIPEnrichmentTests(unittest.TestCase):
    def test_non_global_ip_is_not_enriched(self):
        enricher = GeoIPEnricher(asn_db="", country_db="", city_db="")
        result = enricher.lookup("127.0.0.1")
        self.assertFalse(result["enriched"])
        self.assertEqual(result["reason"], "non_global_ip")

    def test_asn_and_city_results_are_combined(self):
        enricher = GeoIPEnricher(asn_db="", country_db="", city_db="")
        enricher.asn_reader = FakeASNReader()
        enricher.city_reader = FakeCityReader()
        result = enricher.lookup("8.8.8.8")
        self.assertTrue(result["enriched"])
        self.assertEqual(result["asn"], 24940)
        self.assertEqual(result["provider"], "Hetzner Online GmbH")
        self.assertEqual(result["country_code"], "DE")
        self.assertEqual(result["country"], "Germany")
        self.assertEqual(result["city"], "Falkenstein")
        self.assertEqual(result["continent"], "Europe")
        self.assertEqual(result["accuracy_radius_km"], 50)

    def test_changed_database_is_reloaded_and_lookup_cache_is_cleared(self):
        if geoip_module.geoip2 is None:
            self.skipTest("geoip2 dependency unavailable")

        enricher = GeoIPEnricher(asn_db="", country_db="", city_db="")
        first = enricher.lookup("8.8.8.8")
        self.assertFalse(first["enriched"])

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "GeoLite2-ASN.mmdb"
            db_path.write_bytes(b"replacement-mmdb")
            enricher.asn_path = db_path
            enricher._signatures = {
                "asn": (False, 0, 0),
                "country": (False, 0, 0),
                "city": (False, 0, 0),
            }

            with patch.object(
                geoip_module.geoip2.database,
                "Reader",
                return_value=FakeASNReader(),
            ):
                self.assertTrue(enricher.reload_if_changed())

        second = enricher.lookup("8.8.8.8")
        self.assertTrue(second["enriched"])
        self.assertEqual(second["asn"], 24940)
        self.assertEqual(enricher.reload_count, 1)
        self.assertIsNotNone(enricher.last_reload_at)

    def test_status_exposes_database_age_and_revision(self):
        if geoip_module.geoip2 is None:
            self.skipTest("geoip2 dependency unavailable")

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "GeoLite2-ASN.mmdb"
            db_path.write_bytes(b"fake-mmdb")
            with patch.object(
                geoip_module.geoip2.database,
                "Reader",
                return_value=FakeASNReader(),
            ):
                enricher = GeoIPEnricher(
                    asn_db=db_path,
                    country_db="",
                    city_db="",
                )
            status = enricher.status()
            self.assertTrue(status["enabled"])
            self.assertTrue(status["asn_loaded"])
            self.assertIsNotNone(status["databases"]["asn"]["mtime_at"])
            self.assertIsNotNone(status["databases"]["asn"]["age_seconds"])
            self.assertGreater(status["databases"]["asn"]["size"], 0)
            self.assertEqual(status["revision"], enricher.revision())
            self.assertIsNotNone(status["oldest_database_age_seconds"])
            enricher.close()


if __name__ == "__main__":
    unittest.main()
