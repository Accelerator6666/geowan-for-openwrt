import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import geowan_agent as g


class AgentTests(unittest.TestCase):
    def test_ipv4_nft_member_expiry_seconds(self):
        self.assertEqual(
            g.parse_member({"elem": {"val": "8.8.8.8", "expires": 120}}, 4),
            ("8.8.8.8", 120),
        )
        self.assertIsNone(g.parse_member({"elem": {"val": "8.8.8.8"}}, 6))
        self.assertIsNone(g.parse_member({"elem": {"val": "bad-data"}}, 4))

    def test_incremental_snapshot_avoids_rewriting_unchanged_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(g, "DB", Path(tmp) / "db.sqlite"):
                conn = g.db_open()
                now = 1800000000
                with mock.patch.object(g, "read_members",
                                       side_effect=[{"8.8.8.8": 7000}, {}]):
                    sizes, errors = g.snapshot_incremental(conn, now)
                self.assertEqual(sizes, {"4": 1, "6": 0})
                self.assertEqual(errors, [])
                first = conn.execute(
                    "SELECT first_seen,last_seen,expires_at FROM bans WHERE ip=?",
                    ("8.8.8.8",)
                ).fetchone()
                self.assertEqual(first, (now, now, now + 7000))

                # A normal countdown preserves the same absolute expiry.
                with mock.patch.object(g, "read_members",
                                       side_effect=[{"8.8.8.8": 6970}, {}]):
                    g.snapshot_incremental(conn, now + 30)
                second = conn.execute(
                    "SELECT first_seen,last_seen,expires_at FROM bans WHERE ip=?",
                    ("8.8.8.8",)
                ).fetchone()
                self.assertEqual(second, first)

                # A renewed seven-day TTL is a meaningful change and is persisted.
                with mock.patch.object(g, "read_members",
                                       side_effect=[{"8.8.8.8": g.MAX_TTL}, {}]):
                    g.snapshot_incremental(conn, now + 600)
                third = conn.execute(
                    "SELECT first_seen,last_seen,expires_at FROM bans WHERE ip=?",
                    ("8.8.8.8",)
                ).fetchone()
                self.assertEqual(third[0], now)
                self.assertEqual(third[1], now + 600)
                self.assertEqual(third[2], now + 600 + g.MAX_TTL)
                conn.close()

    def test_enrich_pending_persists_geoip_cache(self):
        class Resolver:
            available = True
            version = "2026-11"

            def lookup(self, ip):
                return {
                    "country_code": "US",
                    "country_name": "美国",
                    "continent_code": "NA",
                    "continent_name": "北美洲",
                    "region": "California",
                    "city": "Mountain View",
                    "asn": 15169,
                    "asn_org": "Google LLC",
                    "provider": "DB-IP Lite",
                    "database_version": self.version,
                    "lookup_status": "ok"
                }

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(g, "DB", Path(tmp) / "db.sqlite"):
                conn = g.db_open()
                now = 1800000000
                conn.execute("INSERT INTO bans VALUES(?,?,?,?,?)",
                             ("8.8.8.8", 4, now - 10, now, now + 600))
                count = g.enrich_pending(conn, Resolver(), now, limit=10)
                row = conn.execute(
                    "SELECT country_code,country_name,city,asn,asn_org,lookup_status "
                    "FROM geoip_cache WHERE ip=?",
                    ("8.8.8.8",)
                ).fetchone()
                self.assertEqual(count, 1)
                self.assertEqual(
                    row, ("US", "美国", "Mountain View", 15169, "Google LLC", "ok")
                )
                self.assertEqual(g.enrich_pending(conn, Resolver(), now, limit=10), 0)
                conn.close()

    def test_geoip_cache_cleanup_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(g, "DB", Path(tmp) / "db.sqlite"):
                conn = g.db_open()
                now = 1800000000
                conn.executemany(
                    "INSERT INTO geoip_cache(ip,lookup_status,updated_at) VALUES(?,?,?)",
                    [(f"203.0.113.{i}", "not_found", now - 100 * 86400)
                     for i in range(1, 1201)]
                )
                conn.commit()
                g.cleanup_geoip_cache(conn, now)
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM geoip_cache"
                ).fetchone()[0]
                self.assertEqual(remaining, 200)
                conn.close()

    def test_nft_json_inventory(self):
        example = {"nftables": [{"metainfo": {}}, {"set": {
            "name": "geo_black4", "elem": [
                {"elem": {"val": "8.8.8.8", "expires": 30}},
                {"elem": {"val": "1.1.1.1", "expires": 60}}
            ]
        }}]}
        with mock.patch.object(g, "cmd", return_value=json.dumps(example)):
            result = g.read_members(4)
        self.assertEqual(result, {"8.8.8.8": 30, "1.1.1.1": 60})

    def test_log_parsing_and_injection_rejection(self):
        line = (
            "Sat Oct 31 00:42:00 2026 kern.warn kernel: GEOWAN4 "
            "IN=pppoe-wan SRC=8.8.8.8 DST=10.0.0.61 "
            "PROTO=TCP SPT=40001 DPT=31080"
        )
        row = g.parse_log(line, 1793436120, "boot1")
        self.assertEqual(row[2:7], (4, "8.8.8.8", "10.0.0.61", 31080, "TCP"))
        self.assertIsNone(g.parse_log("GEOWAN4 SRC=not-an-ip", 123, "boot"))

    def test_sqlite_retention_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(g, "DB", Path(tmp) / "db.sqlite"):
                conn = g.db_open()
                now = 1800000000
                conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                             ("abc", now - 20, 4, "8.8.8.8", "10.0.0.61", 31080, "TCP"))
                conn.execute("INSERT INTO bans VALUES(?,?,?,?,?)",
                             ("8.8.8.8", 4, now - 100, now - 20, now + 500))
                conn.commit()
                with mock.patch.object(g, "read_counters", return_value={"black4": 1}):
                    data = g.build_status(conn, now, {"4": 1, "6": 0}, [])
                self.assertEqual(data["samples_24h"], 1)
                self.assertEqual(data["active_bans"], 1)
                self.assertEqual(data["top_ports"][0]["port"], 31080)
                self.assertEqual(len(data["hours"]), 24)
                conn.close()


if __name__ == "__main__":
    unittest.main()
