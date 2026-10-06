from __future__ import annotations

import unittest
from types import SimpleNamespace

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


if __name__ == "__main__":
    unittest.main()
