import json
import sqlite3
import subprocess
import sys
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import geowan_rpc


class FakeResolver:
    available = True
    version = "2026-11"

    def lookup(self, ip):
        return {
            "ip": ip,
            "country_code": "US",
            "country_name": "美国",
            "city": "Mountain View",
            "asn": 15169,
            "asn_org": "Google LLC",
            "lookup_status": "ok"
        }

    def close(self):
        pass


def make_inventory_db(path, now):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE bans(
            ip TEXT PRIMARY KEY,family INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );
        CREATE TABLE geoip_cache(
            ip TEXT PRIMARY KEY,country_code TEXT NOT NULL DEFAULT '',
            country_name TEXT NOT NULL DEFAULT '',continent_code TEXT NOT NULL DEFAULT '',
            continent_name TEXT NOT NULL DEFAULT '',region TEXT NOT NULL DEFAULT '',
            city TEXT NOT NULL DEFAULT '',asn INTEGER,asn_org TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',database_version TEXT NOT NULL DEFAULT '',
            lookup_status TEXT NOT NULL,updated_at INTEGER NOT NULL
        );
        CREATE TABLE events(
            id TEXT PRIMARY KEY,ts INTEGER NOT NULL,family INTEGER NOT NULL,
            src TEXT NOT NULL,dst TEXT,port INTEGER,proto TEXT
        );
        CREATE INDEX idx_events_src_ts ON events(src,ts);
    """)
    conn.executemany(
        "INSERT INTO bans VALUES(?,?,?,?,?)",
        [
            ("8.8.8.8", 4, now - 300, now - 10, now + 600),
            ("1.1.1.1", 4, now - 200, now - 20, now + 900),
            ("2001:4860:4860::8888", 6, now - 100, now - 40, now + 1200)
        ]
    )
    conn.executemany(
        "INSERT INTO geoip_cache VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            ("8.8.8.8", "US", "美国", "NA", "北美洲", "California",
             "Mountain View", 15169, "Google LLC", "DB-IP Lite",
             "2026-11", "ok", now),
            ("1.1.1.1", "AU", "澳大利亚", "OC", "大洋洲", "New South Wales",
             "Sydney", 13335, "Cloudflare, Inc.", "DB-IP Lite",
             "2026-11", "ok", now),
            ("2001:4860:4860::8888", "US", "美国", "NA", "北美洲", "California",
             "Mountain View", 15169, "Google LLC", "DB-IP Lite",
             "2026-11", "ok", now)
        ]
    )
    conn.executemany(
        "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
        [
            ("evt1", now - 30, 4, "8.8.8.8", "10.0.0.61", 31080, "TCP"),
            ("evt2", now - 20, 4, "1.1.1.1", "10.0.0.61", 53, "UDP"),
            ("evt3", now - 10, 6, "2001:4860:4860::8888", "2001:db8::1", 443, "TCP")
        ]
    )
    conn.commit()
    conn.close()


class RpcLookupTests(unittest.TestCase):
    def test_invalid_ip_is_rejected_before_database_access(self):
        result = geowan_rpc.lookup({"ip": "bad address"})
        self.assertEqual(result["lookup_status"], "invalid")

    def test_cached_lookup_uses_current_database_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.sqlite3"
            conn = sqlite3.connect(path)
            conn.execute("""CREATE TABLE geoip_cache(
                ip TEXT PRIMARY KEY,country_code TEXT,country_name TEXT,
                continent_code TEXT,continent_name TEXT,region TEXT,city TEXT,
                asn INTEGER,asn_org TEXT,provider TEXT,database_version TEXT,
                lookup_status TEXT,updated_at INTEGER
            )""")
            conn.execute(
                "INSERT INTO geoip_cache VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("8.8.8.8", "US", "美国", "NA", "北美洲", "California",
                 "Mountain View", 15169, "Google LLC", "DB-IP Lite",
                 "2026-11", "ok", 1800000000)
            )
            conn.commit()
            conn.close()

            with mock.patch.object(
                geowan_rpc, "read_metadata", return_value={"release": "2026-11"}
            ):
                result = geowan_rpc.lookup(
                    {"ip": "8.8.8.8"}, db_path=path,
                    resolver_factory=lambda: self.fail("cache should be used")
                )
            self.assertEqual(result["country_code"], "US")
            self.assertEqual(result["asn"], 15169)

    def test_rpcd_plugin_list_protocol(self):
        plugin = Path(__file__).resolve().parents[1] / "rpcd" / "geowan"
        result = subprocess.run(
            [sys.executable, str(plugin), "list"],
            check=False, capture_output=True, text=True
        )
        self.assertEqual(
            result.returncode, 0,
            f"rpcd list failed: stdout={result.stdout!r}, stderr={result.stderr!r}"
        )
        methods = json.loads(result.stdout)
        self.assertEqual(set(methods), {
            "lookup", "list_bans", "get_ban", "analytics",
            "source_profile", "asn_profile", "correlations"
        })
        self.assertEqual(methods["lookup"], {"ip": ""})
        self.assertEqual(methods["get_ban"], {"ip": ""})
        self.assertEqual(methods["analytics"], {"period": "24h"})
        self.assertEqual(methods["source_profile"], {"ip": "", "period": "24h"})
        self.assertEqual(methods["asn_profile"], {"asn": 15169, "period": "24h"})
        self.assertEqual(methods["correlations"], {"period": "24h"})
        self.assertEqual(methods["list_bans"]["page_size"], 50)

    def test_dispatch_routes_new_read_only_profile_methods(self):
        with mock.patch.object(geowan_rpc, "source_profile", return_value={"source": True}) as source:
            self.assertEqual(
                geowan_rpc.dispatch("source_profile", {"ip": "8.8.8.8"}),
                {"source": True}
            )
            source.assert_called_once_with({"ip": "8.8.8.8"})

        with mock.patch.object(geowan_rpc, "asn_profile", return_value={"asn": True}) as asn:
            self.assertEqual(
                geowan_rpc.dispatch("asn_profile", {"asn": 15169}),
                {"asn": True}
            )
            asn.assert_called_once_with({"asn": 15169})

        with mock.patch.object(geowan_rpc, "correlations", return_value={"clusters": []}) as corr:
            self.assertEqual(
                geowan_rpc.dispatch("correlations", {"period": "24h"}),
                {"clusters": []}
            )
            corr.assert_called_once_with({"period": "24h"})

    def test_rpcd_plugin_call_protocol(self):
        plugin = Path(__file__).resolve().parents[1] / "rpcd" / "geowan"
        result = subprocess.run(
            [sys.executable, str(plugin), "call", "lookup"],
            input='{"ip":"10.0.0.1"}',
            check=False, capture_output=True, text=True
        )
        self.assertEqual(
            result.returncode, 0,
            f"rpcd call failed: stdout={result.stdout!r}, stderr={result.stderr!r}"
        )
        self.assertEqual(json.loads(result.stdout)["lookup_status"], "non_global")

    def test_non_global_lookup_does_not_open_mmdb_reader(self):
        with mock.patch.object(
            geowan_rpc, "GeoIPResolver",
            side_effect=AssertionError("non-global IP must not open MMDB")
        ):
            result = geowan_rpc.lookup({"ip": "10.0.0.1"})
        self.assertEqual(result["lookup_status"], "non_global")

    def test_uncached_lookup_uses_local_resolver(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = geowan_rpc.lookup(
                {"ip": "8.8.4.4"},
                db_path=Path(tmp) / "missing.sqlite3",
                resolver_factory=FakeResolver
            )
            self.assertEqual(result["country_code"], "US")
            self.assertEqual(result["city"], "Mountain View")

    def test_list_bans_paginates_active_records(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.sqlite3"
            make_inventory_db(path, now)
            with mock.patch.object(
                geowan_rpc, "read_metadata", return_value={"release": "2026-11"}
            ):
                result = geowan_rpc.list_bans(
                    {"page": 1, "page_size": 20}, db_path=path, now=now
                )
            self.assertEqual(result["total"], 3)
            self.assertEqual(len(result["items"]), 3)
            self.assertEqual(result["pages"], 1)
            self.assertEqual(result["items"][0]["ip"], "8.8.8.8")
            self.assertEqual(result["items"][0]["event_count"], 1)
            self.assertEqual(result["items"][0]["first_seen"], now - 300)
            self.assertEqual(result["items"][0]["last_event"], now - 30)

    def test_list_bans_supports_frontend_page_sizes(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.sqlite3"
            make_inventory_db(path, now)
            with mock.patch.object(
                geowan_rpc, "read_metadata", return_value={"release": "2026-11"}
            ):
                for size in (20, 50, 100):
                    result = geowan_rpc.list_bans(
                        {"page": 1, "page_size": size}, db_path=path, now=now
                    )
                    self.assertEqual(result["page_size"], size)
                    self.assertEqual(len(result["items"]), 3)

                invalid = geowan_rpc.list_bans(
                    {"page": 1, "page_size": 10}, db_path=path, now=now
                )
            self.assertEqual(invalid, {"error": "invalid_parameters"})

    def test_list_bans_filters_country_asn_port_and_proto(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.sqlite3"
            make_inventory_db(path, now)
            with mock.patch.object(
                geowan_rpc, "read_metadata", return_value={"release": "2026-11"}
            ):
                country = geowan_rpc.list_bans(
                    {"country_code": "au"}, db_path=path, now=now
                )
                asn = geowan_rpc.list_bans(
                    {"asn": 15169}, db_path=path, now=now
                )
                port = geowan_rpc.list_bans(
                    {"port": 31080, "proto": "tcp"}, db_path=path, now=now
                )
                query = geowan_rpc.list_bans(
                    {"query": "Mountain"}, db_path=path, now=now
                )
            self.assertEqual([r["ip"] for r in country["items"]], ["1.1.1.1"])
            self.assertEqual(asn["total"], 2)
            self.assertEqual([r["ip"] for r in port["items"]], ["8.8.8.8"])
            self.assertEqual(query["total"], 2)

    def test_list_bans_rejects_invalid_filters(self):
        self.assertEqual(
            geowan_rpc.list_bans({"port": 70000}),
            {"error": "invalid_parameters"}
        )
        self.assertEqual(
            geowan_rpc.list_bans({"family": 5}),
            {"error": "invalid_parameters"}
        )

    def test_analytics_returns_period_trend_and_sampled_rankings(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.sqlite3"
            make_inventory_db(path, now)
            conn = sqlite3.connect(path)
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                ("evt4", now - 40, 4, "8.8.8.8", "10.0.0.61", 31080, "TCP")
            )
            conn.commit()
            conn.close()

            with mock.patch.object(
                geowan_rpc, "read_metadata", return_value={"release": "2026-11"}
            ):
                result = geowan_rpc.analytics(
                    {"period": "24h"}, db_path=path, now=now
                )
                self.assertEqual(result["event_samples"], 4)
                self.assertEqual(result["unique_sources"], 3)
                self.assertEqual(len(result["trend"]), 24)
                self.assertEqual(sum(x["count"] for x in result["trend"]), 4)
                self.assertEqual(result["top_ports"][0]["port"], 31080)
                self.assertEqual(result["top_ports"][0]["samples"], 2)
                self.assertEqual(result["top_protocols"][0]["proto"], "TCP")
                self.assertEqual(result["top_protocols"][0]["samples"], 3)
                self.assertEqual(result["top_countries"][0]["code"], "US")
                self.assertEqual(result["top_countries"][0]["source_ips"], 2)
                self.assertEqual(result["top_countries"][0]["samples"], 3)
                self.assertEqual(result["top_asns"][0]["asn"], 15169)
                self.assertEqual(result["top_asns"][0]["source_ips"], 2)

                expected = {"1h": (12, 300), "7d": (7, 86400), "30d": (30, 86400)}
                for period, (count, bucket) in expected.items():
                    selected = geowan_rpc.analytics(
                        {"period": period}, db_path=path, now=now
                    )
                    self.assertEqual(len(selected["trend"]), count)
                    self.assertEqual(selected["bucket_seconds"], bucket)

    def test_analytics_rejects_invalid_period(self):
        self.assertEqual(
            geowan_rpc.analytics({"period": "all"}),
            {"error": "invalid_period"}
        )
        self.assertEqual(
            geowan_rpc.analytics(None),
            {"error": "invalid_period"}
        )

    def test_get_ban_returns_geoip_and_bounded_event_history(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.sqlite3"
            make_inventory_db(path, now)
            with mock.patch.object(
                geowan_rpc, "read_metadata", return_value={"release": "2026-11"}
            ):
                result = geowan_rpc.get_ban(
                    {"ip": "8.8.8.8"}, db_path=path, now=now
                )
            self.assertTrue(result["found"])
            self.assertEqual(result["item"]["country_code"], "US")
            self.assertEqual(result["item"]["remaining_seconds"], 600)
            self.assertEqual(result["item"]["event_count"], 1)
            self.assertEqual(len(result["item"]["events"]), 1)

    def test_get_ban_reports_missing_record(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "telemetry.sqlite3"
            make_inventory_db(path, now)
            with mock.patch.object(
                geowan_rpc, "read_metadata", return_value={"release": "2026-11"}
            ):
                result = geowan_rpc.get_ban(
                    {"ip": "9.9.9.9"}, db_path=path, now=now
                )
            self.assertEqual(result, {"found": False, "ip": "9.9.9.9"})


if __name__ == "__main__":
    unittest.main()
