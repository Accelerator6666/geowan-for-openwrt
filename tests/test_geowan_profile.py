import sqlite3
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import geowan_profile as profile


def make_profile_db(path, now):
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE events(
            id TEXT PRIMARY KEY,ts INTEGER NOT NULL,family INTEGER NOT NULL,
            src TEXT NOT NULL,dst TEXT,port INTEGER,proto TEXT
        );
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
        CREATE INDEX idx_events_src_ts ON events(src,ts);
        CREATE INDEX idx_geoip_asn ON geoip_cache(asn);
    """)
    conn.executemany(
        "INSERT INTO geoip_cache VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            ("8.8.8.8", "US", "美国", "NA", "北美洲", "California",
             "Mountain View", 15169, "Google LLC", "DB-IP Lite",
             "2026-11", "ok", now),
            ("8.8.4.4", "US", "美国", "NA", "北美洲", "California",
             "Mountain View", 15169, "Google LLC", "DB-IP Lite",
             "2026-11", "ok", now),
            ("9.9.9.9", "US", "美国", "NA", "北美洲", "California",
             "Los Angeles", 15169, "Google LLC", "DB-IP Lite",
             "2026-11", "ok", now),
            ("1.1.1.1", "AU", "澳大利亚", "OC", "大洋洲", "New South Wales",
             "Sydney", 13335, "Cloudflare, Inc.", "DB-IP Lite",
             "2026-11", "ok", now)
        ]
    )
    conn.executemany(
        "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
        [
            ("evt1", now - 100, 4, "8.8.8.8", "10.0.0.1", 443, "TCP"),
            ("evt2", now - 90, 4, "8.8.4.4", "10.0.0.1", 443, "TCP"),
            ("evt3", now - 80, 4, "9.9.9.9", "10.0.0.1", 443, "TCP"),
            ("evt4", now - 4000, 4, "8.8.8.8", "10.0.0.2", 22, "TCP"),
            ("evt5", now - 20, 4, "8.8.8.8", "10.0.0.1", 443, "TCP"),
            ("evt6", now - 10, 4, "1.1.1.1", "10.0.0.2", 53, "UDP")
        ]
    )
    conn.execute(
        "INSERT INTO bans VALUES(?,?,?,?,?)",
        ("8.8.8.8", 4, now - 500, now - 20, now + 600)
    )
    conn.commit()
    conn.close()


class GeoWANProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "telemetry.sqlite3"
        self.now = 1800000000
        make_profile_db(self.db, self.now)
        self.version_patch = mock.patch.object(
            profile, "read_metadata", return_value={"release": "2026-11"}
        )
        self.version_patch.start()

    def tearDown(self):
        self.version_patch.stop()
        self.tmp.cleanup()

    def test_source_profile_returns_bounded_behavior_evidence(self):
        result = profile.source_profile(
            {"ip": "8.8.8.8", "period": "24h"}, db_path=self.db, now=self.now
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["samples"], 3)
        self.assertEqual(result["unique_targets"], 2)
        self.assertEqual(result["unique_ports"], 2)
        self.assertEqual(result["geoip"]["asn"], 15169)
        self.assertTrue(result["ban"]["active"])
        self.assertEqual(result["ban"]["remaining_seconds"], 600)
        self.assertEqual(result["behavior_score"]["level"], "中等观察强度")
        self.assertLessEqual(len(result["events"]), 30)

    def test_source_profile_marks_sparse_data_as_insufficient(self):
        result = profile.source_profile(
            {"ip": "1.1.1.1", "period": "24h"}, db_path=self.db, now=self.now
        )
        self.assertEqual(result["samples"], 1)
        self.assertIsNone(result["behavior_score"]["score"])
        self.assertEqual(result["behavior_score"]["level"], "证据不足")

    def test_source_profile_rejects_invalid_and_non_global_ip(self):
        self.assertEqual(
            profile.source_profile({"ip": "bad"}, db_path=self.db),
            {"error": "invalid_ip"}
        )
        self.assertEqual(
            profile.source_profile({"ip": "10.0.0.1"}, db_path=self.db)["error"],
            "non_global_ip"
        )

    def test_source_profile_rejects_invalid_period(self):
        self.assertEqual(
            profile.source_profile(
                {"ip": "8.8.8.8", "period": "all"}, db_path=self.db
            ),
            {"error": "invalid_period"}
        )

    def test_asn_profile_aggregates_sources_and_behavior(self):
        result = profile.asn_profile(
            {"asn": 15169, "period": "24h"}, db_path=self.db, now=self.now
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["unique_sources"], 3)
        self.assertEqual(result["samples"], 5)
        self.assertEqual(result["organization"], "Google LLC")
        self.assertEqual(result["active_banned_sources"], 1)
        self.assertEqual(result["top_ports"][0]["port"], 443)
        self.assertEqual(result["correlations"][0]["source_count"], 3)

    def test_asn_profile_rejects_invalid_asn(self):
        for value in (0, -1, 4294967296, True, "15169"):
            self.assertEqual(
                profile.asn_profile({"asn": value}, db_path=self.db)["error"],
                "invalid_asn"
            )

    def test_global_correlations_require_three_distinct_sources(self):
        result = profile.correlations(
            {"period": "24h"}, db_path=self.db, now=self.now
        )
        self.assertEqual(result["minimum_sources"], 3)
        self.assertTrue(result["clusters"])
        cluster = result["clusters"][0]
        self.assertEqual(cluster["dst"], "10.0.0.1")
        self.assertEqual(cluster["port"], 443)
        self.assertEqual(cluster["source_count"], 3)
        self.assertEqual(len(cluster["sources"]), 3)

    def test_correlations_reject_invalid_period(self):
        self.assertEqual(
            profile.correlations({"period": "all"}, db_path=self.db),
            {"error": "invalid_period"}
        )


if __name__ == "__main__":
    unittest.main()
