from __future__ import annotations

import unittest
from pathlib import Path


class GeoIPUpdateConfigTests(unittest.TestCase):
    def test_qnap_compose_uses_official_geoipupdate_image_and_shared_directory(self):
        root = Path(__file__).resolve().parents[1]
        compose = (root / "compose.qnap.example.yml").read_text(encoding="utf-8")
        self.assertIn("ghcr.io/maxmind/geoipupdate:latest", compose)
        self.assertIn("/share/Data/config/cloudflared/geoipupdate.env", compose)
        self.assertIn("/share/Data/config/cloudflared/geoip:/usr/share/GeoIP", compose)
        self.assertIn("/share/Data/config/cloudflared/geoip:/geoip:ro", compose)

    def test_geoipupdate_example_downloads_asn_and_city_daily(self):
        root = Path(__file__).resolve().parents[1]
        env = (root / "geoipupdate.env.example").read_text(encoding="utf-8")
        self.assertIn("GEOIPUPDATE_ACCOUNT_ID=", env)
        self.assertIn("GEOIPUPDATE_LICENSE_KEY=", env)
        self.assertIn("GEOIPUPDATE_EDITION_IDS=GeoLite2-ASN GeoLite2-City", env)
        self.assertIn("GEOIPUPDATE_FREQUENCY=24", env)
        self.assertIn("GEOIPUPDATE_DB_DIR=/usr/share/GeoIP", env)


if __name__ == "__main__":
    unittest.main()
