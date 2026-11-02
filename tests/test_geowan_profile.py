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
            ("evt6", now - 10, 4, "1.1.1.1", "10.0.0.2", 53, "UDP"),
            ("evt7", now - 70, 4, "1.1.1.1", "10.0.0.1", 443, "TCP")
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
        self.assertEqual(result["samples"], 2)
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
        self.assertEqual(cluster["source_count"], 4)
        self.assertEqual(len(cluster["sources"]), 4)
        self.assertEqual(cluster["unique_countries"], 2)
        self.assertEqual(cluster["unique_asns"], 2)
        self.assertFalse(cluster["sources_truncated"])


    def test_epoch_aligned_buckets_do_not_move_with_rolling_window(self):
        conn = sqlite3.connect(self.db)
        conn.executemany(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
            [
                ("edge1", self.now - 3610, 4, "8.8.8.9", "10.0.0.9", 53, "UDP"),
                ("edge2", self.now - 3590, 4, "8.8.8.9", "10.0.0.9", 53, "UDP")
            ]
        )
        conn.commit()
        conn.close()

        first = profile.source_profile(
            {"ip": "8.8.8.9", "period": "24h"},
            db_path=self.db, now=self.now
        )
        shifted = profile.source_profile(
            {"ip": "8.8.8.9", "period": "24h"},
            db_path=self.db, now=self.now + 600
        )
        self.assertEqual(first["active_buckets"], 2)
        self.assertEqual(shifted["active_buckets"], 2)
        self.assertEqual(first["bucket_seconds"], 3600)
        self.assertEqual(shifted["bucket_alignment"], "UTC Unix epoch")

        corr_first = profile.correlations(
            {"period": "24h"}, db_path=self.db, now=self.now
        )
        corr_shifted = profile.correlations(
            {"period": "24h"}, db_path=self.db, now=self.now + 600
        )
        target = lambda result: next(
            item for item in result["clusters"]
            if item["dst"] == "10.0.0.1" and item["port"] == 443
        )
        self.assertEqual(
            target(corr_first)["time"],
            target(corr_shifted)["time"]
        )
        self.assertEqual(
            target(corr_first)["time"],
            ((self.now - 100) // 3600) * 3600
        )

    def test_global_correlation_reports_full_cross_country_asn_fixture(self):
        sources = [
            ("106.155.5.152", "JP", "日本", 2516, "KDDI CORPORATION"),
            ("109.204.179.26", "FI", "芬兰", 202246, "Valoo Oy"),
            ("116.118.156.84", "TW", "台湾", 18049, "Taiwan Infrastructure Network Technologie"),
            ("125.30.73.187", "JP", "日本", 2497, "Internet Initiative Japan Inc."),
            ("128.79.136.199", "FR", "法国", 5410, "Bouygues Telecom SA"),
            ("14.100.36.255", "SG", "新加坡", 9506, "Singapore Telecommunications Ltd"),
            ("141.157.245.32", "US", "美国", 701, "Verizon Business"),
            ("176.116.178.123", "RU", "俄罗斯", 31257, "Orion Telecom LLC"),
            ("178.193.110.45", "CH", "瑞士", 3303, "Swisscom (Schweiz) AG"),
            ("185.138.207.195", "RU", "俄罗斯", 8359, "MTS PJSC"),
            ("188.157.43.225", "HU", "匈牙利", 5483, "Magyar Telekom plc."),
            ("189.196.214.244", "MX", "墨西哥", 13999, "Mega Cable"),
            ("202.59.12.142", "PK", "巴基斯坦", 141342, "FIBERISH"),
            ("221.133.95.66", "JP", "日本", 17534, "NSK Co.,Ltd."),
            ("41.59.13.227", "TZ", "坦桑尼亚", 33765, "Tanzania Telecommunications"),
            ("46.217.102.66", "MK", "马其顿", 6821, "Makedonski Telekom"),
            ("60.54.232.34", "MY", "马来西亚", 4788, "TM Technology Services"),
            ("76.145.102.227", "US", "美国", 7922, "Comcast Cable"),
            ("78.144.94.55", "GB", "英国", 13285, "TalkTalk Communications"),
            ("84.232.140.116", "RO", "罗马尼亚", 8708, "DIGI ROMANIA"),
            ("84.77.124.233", "ES", "西班牙", 12479, "Orange Espagne"),
            ("86.87.88.124", "NL", "荷兰", 1136, "KPN B.V."),
            ("87.126.24.123", "BG", "保加利亚", 8866, "Vivacom Bulgaria"),
            ("87.252.188.58", "BG", "保加利亚", 12829, "Angel Soft"),
            ("89.134.9.11", "HU", "匈牙利", 21334, "One Hungary"),
            ("94.158.58.184", "UZ", "乌兹别克斯坦", 43060, "IPLUS LLC"),
            ("95.61.102.30", "ES", "西班牙", 12430, "Vodafone Espana")
        ]
        conn = sqlite3.connect(self.db)
        geo_rows = [
            (
                ip, code, country, "", "", "", "", asn, org,
                "DB-IP Lite", "2026-11", "ok", self.now
            )
            for ip, code, country, asn, org in sources
        ]
        event_rows = [
            (
                "corr-%02d" % index, self.now - 1800, 4, ip,
                "112.82.232.30", 40163, "UDP"
            )
            for index, (ip, code, country, asn, org) in enumerate(sources, 1)
        ]
        conn.executemany(
            "INSERT INTO geoip_cache VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            geo_rows
        )
        conn.executemany(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
            event_rows
        )
        conn.commit()
        conn.close()

        result = profile.correlations(
            {"period": "24h"}, db_path=self.db, now=self.now
        )
        cluster = next(
            item for item in result["clusters"]
            if item["dst"] == "112.82.232.30"
            and item["port"] == 40163
            and item["proto"] == "UDP"
        )
        self.assertEqual(cluster["source_count"], 27)
        self.assertEqual(cluster["unique_countries"], 20)
        self.assertEqual(cluster["unique_asns"], 27)
        self.assertEqual(cluster["sources_returned"], 27)
        self.assertFalse(cluster["sources_truncated"])
        self.assertFalse(cluster["countries_truncated"])
        self.assertFalse(cluster["asns_truncated"])
        self.assertEqual(len(cluster["sources"]), 27)
        self.assertEqual(
            sum(item["source_count"] for item in cluster["countries"]), 27
        )
        self.assertEqual(
            sum(item["source_count"] for item in cluster["asns"]), 27
        )
        japan = next(
            item for item in cluster["countries"]
            if item["country_code"] == "JP"
        )
        self.assertEqual(japan["source_count"], 3)
        self.assertEqual(
            cluster["geoip_unresolved_sources"], 0
        )


    def test_global_correlation_marks_source_list_truncation(self):
        conn = sqlite3.connect(self.db)
        conn.executemany(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
            [
                (
                    "many-%03d" % index, self.now - 120, 4,
                    "8.8.8.%d" % (index + 10),
                    "203.0.113.10", 45678, "UDP"
                )
                for index in range(101)
            ]
        )
        conn.commit()
        conn.close()

        result = profile.correlations(
            {"period": "24h"}, db_path=self.db, now=self.now
        )
        cluster = next(
            item for item in result["clusters"]
            if item["dst"] == "203.0.113.10"
            and item["port"] == 45678
        )
        self.assertEqual(cluster["source_count"], 101)
        self.assertEqual(cluster["sources_returned"], 100)
        self.assertTrue(cluster["sources_truncated"])

    def test_correlations_reject_invalid_period(self):
        self.assertEqual(
            profile.correlations({"period": "all"}, db_path=self.db),
            {"error": "invalid_period"}
        )


if __name__ == "__main__":
    unittest.main()
