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


    def test_monitor_cycle_passes_boot_id_as_keyword_not_log_lines(self):
        from contextlib import ExitStack

        with tempfile.TemporaryDirectory() as tmp:
            conn = mock.Mock()
            state = {
                "sizes": {"4": 0, "6": 0},
                "errors": [],
                "last_inventory": 1,
                "last_inventory_mono": 100.0,
                "last_log_mono": 0.0,
                "last_geoip_mono": 100.0,
                "last_geoip_cleanup_mono": 100.0,
                "geoip_resolver": None,
                "guard_runtime": {"enabled": True},
            }
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(
                    g, "COLLECT_LOCK", Path(tmp) / "collect.lock"
                ))
                stack.enter_context(mock.patch.object(
                    g.time, "time", return_value=1800000000
                ))
                stack.enter_context(mock.patch.object(
                    g.time, "monotonic", return_value=100.0
                ))
                stack.enter_context(mock.patch.object(
                    g, "boot_id", return_value="boot-test"
                ))
                stack.enter_context(mock.patch.object(g, "insert_log_samples"))
                insert_guard = stack.enter_context(mock.patch.object(
                    g, "insert_guard_log_samples", return_value=2
                ))
                stack.enter_context(mock.patch.object(
                    g, "evaluate_guard_alerts", return_value={"enabled": True}
                ))
                stack.enter_context(mock.patch.object(
                    g, "build_status", return_value={}
                ))
                stack.enter_context(mock.patch.object(g, "publish_status"))

                self.assertTrue(g.monitor_cycle(state, conn))

            insert_guard.assert_called_once_with(
                conn, 1800000000, boot="boot-test"
            )
            self.assertEqual(state["guard_samples_inserted"], 2)


    def test_collect_passes_boot_id_as_keyword_not_log_lines(self):
        from contextlib import ExitStack

        conn = sqlite3.connect(":memory:")
        resolver = mock.Mock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                g.time, "time", return_value=1800000000
            ))
            stack.enter_context(mock.patch.object(g, "db_open", return_value=conn))
            stack.enter_context(mock.patch.object(
                g, "GeoIPResolver", return_value=resolver
            ))
            stack.enter_context(mock.patch.object(
                g, "snapshot", return_value=({"4": 0, "6": 0}, [])
            ))
            stack.enter_context(mock.patch.object(g, "insert_log_samples"))
            stack.enter_context(mock.patch.object(g, "enrich_pending"))
            stack.enter_context(mock.patch.object(
                g, "refresh_guard", return_value={"enabled": True}
            ))
            stack.enter_context(mock.patch.object(
                g, "refresh_enforcement",
                return_value={"enabled": False, "mode": "disabled"}
            ))
            stack.enter_context(mock.patch.object(
                g, "boot_id", return_value="boot-reconcile-test"
            ))
            insert_guard = stack.enter_context(mock.patch.object(
                g, "insert_guard_log_samples", return_value=3
            ))
            stack.enter_context(mock.patch.object(g, "enrich_guard_sources"))
            stack.enter_context(mock.patch.object(
                g, "evaluate_guard_alerts", return_value={"enabled": True}
            ))
            stack.enter_context(mock.patch.object(g, "cleanup_geoip_cache"))
            stack.enter_context(mock.patch.object(
                g, "build_status",
                return_value={"active_bans": 0, "samples_24h": 0}
            ))
            stack.enter_context(mock.patch.object(g, "publish_status"))

            g.collect()

        insert_guard.assert_called_once_with(
            conn, 1800000000, boot="boot-reconcile-test"
        )
        resolver.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
