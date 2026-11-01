import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from geowan_geoip import GeoIPResolver


class FakeReader:
    def __init__(self, record):
        self.record = record

    def get(self, ip):
        return self.record

    def close(self):
        pass


class GeoIPTests(unittest.TestCase):
    def test_dbip_lite_country_city_and_asn_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ("country.mmdb", "city.mmdb", "asn.mmdb"):
                (directory / name).write_bytes(b"fixture")
            (directory / "metadata.json").write_text(json.dumps({
                "provider": "DB-IP Lite",
                "release": "2026-11"
            }), encoding="utf-8")

            records = {
                "country.mmdb": {
                    "country": {
                        "iso_code": "US",
                        "names": {"zh-CN": "美国", "en": "United States"}
                    },
                    "continent": {
                        "code": "NA",
                        "names": {"zh-CN": "北美洲"}
                    }
                },
                "city.mmdb": {
                    "city": {"names": {"en": "Mountain View"}},
                    "subdivisions": [{"names": {"en": "California"}}]
                },
                "asn.mmdb": {
                    "autonomous_system_number": 15169,
                    "autonomous_system_organization": "Google LLC"
                }
            }

            def factory(path):
                return FakeReader(records[Path(path).name])

            resolver = GeoIPResolver(directory, reader_factory=factory)
            result = resolver.lookup("8.8.8.8")
            self.assertEqual(result["country_code"], "US")
            self.assertEqual(result["country_name"], "美国")
            self.assertEqual(result["continent_code"], "NA")
            self.assertEqual(result["city"], "Mountain View")
            self.assertEqual(result["region"], "California")
            self.assertEqual(result["asn"], 15169)
            self.assertEqual(result["asn_org"], "Google LLC")
            self.assertEqual(result["database_version"], "2026-11")
            self.assertEqual(result["lookup_status"], "ok")
            resolver.close()

    def test_non_global_ip_is_not_geolocated(self):
        resolver = GeoIPResolver(reader_factory=lambda _path: FakeReader({}))
        result = resolver.lookup("10.0.0.1")
        self.assertEqual(result["lookup_status"], "non_global")
        self.assertEqual(result["country_code"], "")
        resolver.close()

    def test_invalid_ip_is_rejected(self):
        resolver = GeoIPResolver(reader_factory=lambda _path: FakeReader({}))
        result = resolver.lookup("not-an-ip")
        self.assertEqual(result["lookup_status"], "invalid")
        resolver.close()


if __name__ == "__main__":
    unittest.main()
