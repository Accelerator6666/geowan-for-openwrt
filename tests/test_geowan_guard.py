import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import geowan_guard as guard


UCI = """
config redirect 'rdp'
        option name 'P330tiny'
        option src 'wan'
        option src_dport '58964'
        option dest_ip '10.0.0.193'
        option dest_port '3389'
        option proto 'tcp udp'

config redirect 'jump'
        option name 'jumpserver'
        option src 'wan'
        option src_dport '31080'
        option dest_ip '10.0.0.61'
        option dest_port '31080'
        option proto 'tcp'

config redirect 'disabled'
        option name 'disabled-nas'
        option src 'wan'
        option src_dport '5001'
        option dest_ip '10.0.0.61'
        option dest_port '5001'
        option enabled '0'
"""

NFT = """
table inet fw4 {
 chain dstnat_wan {
  meta nfproto ipv4 tcp dport 58964 counter packets 24 bytes 1232 dnat ip to 10.0.0.193:3389 comment "!fw4: P330tiny"
  meta nfproto ipv4 udp dport 58964 counter packets 2 bytes 120 dnat ip to 10.0.0.193:3389 comment "!fw4: P330tiny"
  meta nfproto ipv4 tcp dport 31080 counter packets 56 bytes 2864 dnat ip to 10.0.0.61:31080 comment "!fw4: jumpserver"
  meta nfproto ipv6 tcp dport 40443 counter packets 1 bytes 60 dnat ip6 to [2001:4860:4860::8888]:443 comment "!fw4: test-v6"
 }
}
"""


class GuardTests(unittest.TestCase):
    def test_parse_uci_redirects_filters_disabled_and_expands_protocols(self):
        rows = guard.parse_uci_redirects(UCI)
        self.assertEqual(len(rows), 3)
        rdp = [row for row in rows if row["public_port"] == 58964]
        self.assertEqual({row["proto"] for row in rdp}, {"tcp", "udp"})
        self.assertEqual(rdp[0]["family"], 4)
        self.assertEqual(rdp[0]["dest_ip"], "10.0.0.193")
        self.assertFalse(any(row["public_port"] == 5001 for row in rows))

    def test_parse_runtime_dnat_supports_ipv4_and_ipv6(self):
        rows = guard.parse_dnat_rules(NFT)
        self.assertEqual(len(rows), 4)
        v4 = next(row for row in rows if row["public_port"] == 58964 and row["proto"] == "tcp")
        self.assertEqual((v4["family"], v4["dest_ip"], v4["dest_port"]),
                         (4, "10.0.0.193", 3389))
        v6 = next(row for row in rows if row["family"] == 6)
        self.assertEqual((v6["dest_ip"], v6["dest_port"]),
                         ("2001:4860:4860::8888", 443))

    def test_inventory_joins_uci_names_and_runtime_state(self):
        rows = guard.build_inventory(UCI, NFT, now=1800000000)
        rdp = [row for row in rows if row["public_port"] == 58964]
        self.assertEqual(len(rdp), 2)
        self.assertTrue(all(row["runtime_active"] for row in rdp))
        self.assertTrue(all(row["config_match"] for row in rdp))
        self.assertTrue(all(row["category"] == "custom" for row in rdp))
        self.assertTrue(all("待确认" in row["category_label"] for row in rdp))
        self.assertFalse(any(row["public_port"] == 5001 for row in rows))

    def test_conflicting_public_mapping_is_marked_and_not_rendered(self):
        conflicting = UCI + """
config redirect 'rdp-other'
        option name 'other-rdp'
        option src 'wan'
        option src_dport '58964'
        option dest_ip '10.0.0.212'
        option dest_port '3389'
        option proto 'tcp udp'
"""
        rows = guard.build_inventory(conflicting, NFT, now=1800000000)
        rdp = [row for row in rows if row["public_port"] == 58964 and row["proto"] == "tcp"]
        self.assertEqual(len(rdp), 2)
        self.assertTrue(all(row["conflict"] for row in rdp))
        rules = guard.render_rules(rows, "pppoe-wan")
        self.assertFalse(any("58964" in rule for rule in rules))

    def test_render_rules_log_all_sources_by_family_and_original_public_port(self):
        rows = guard.build_inventory(UCI, NFT, now=1800000000)
        rules = guard.render_rules(rows, "pppoe-wan", rate=2, burst=10)
        self.assertTrue(any("meta nfproto ipv4" in rule for rule in rules))
        self.assertTrue(any("meta nfproto ipv6" in rule for rule in rules))
        self.assertFalse(any("@geo_cn4" in rule or "@geo_cn6" in rule for rule in rules))
        self.assertTrue(any("ct original proto-dst 58964" in rule for rule in rules))
        self.assertTrue(all("ct status dnat" in rule for rule in rules))
        self.assertTrue(all("log prefix" in rule and "counter" in rule for rule in rules))
        self.assertFalse(any(
            token in rule.lower().split()
            for rule in rules for token in ("accept", "drop", "reject")
        ))

    def test_invalid_wan_interface_is_rejected(self):
        with self.assertRaises(ValueError):
            guard.render_rules([], 'pppoe-wan"; drop')

    def test_missing_guard_config_defaults_to_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = guard.read_config(Path(tmp) / "missing.json")
            self.assertFalse(config["enabled"])
            self.assertEqual(config["mode"], "observe")

    def test_existing_chain_must_match_guard_ownership_signature(self):
        owned = (
            'type filter hook forward priority -2; policy accept; '
            'comment "GeoWAN Sensitive Port Guard v0.6.0";'
        )
        with mock.patch.object(guard, "run", return_value=owned):
            self.assertTrue(guard._chain_exists())
        with mock.patch.object(
            guard, "run",
            return_value=(
                'type filter hook forward priority -2; policy accept; '
                'comment "unrelated chain";'
            )
        ):
            with self.assertRaisesRegex(RuntimeError, "guard_chain_name_conflict"):
                guard._chain_exists()
        with mock.patch.object(
            guard, "run",
            return_value=(
                'type filter hook forward priority -2; policy drop; '
                'comment "GeoWAN Sensitive Port Guard v0.6.0";'
            )
        ):
            with self.assertRaisesRegex(RuntimeError, "guard_chain_name_conflict"):
                guard._chain_exists()

    def test_validate_guard_rules_uses_nft_check_only(self):
        calls = []

        def fake_runner(*args, input_text=None):
            calls.append((args, input_text))
            if args[:3] == ("uci", "-q", "export"):
                return UCI
            if args[:5] == ("nft", "-a", "list", "chain", "inet"):
                return NFT
            if args[:4] == ("ubus", "call", "network.interface.wan", "status"):
                return json.dumps({"l3_device": "pppoe-wan"})
            if args[:5] == ("nft", "list", "chain", "inet", "fw4"):
                raise subprocess.CalledProcessError(1, args)
            if args[:3] == ("nft", "-c", "-f"):
                return ""
            raise AssertionError("unexpected command: %r" % (args,))

        result = guard.validate_guard_rules(command_runner=fake_runner)
        self.assertEqual(result["wan_device"], "pppoe-wan")
        self.assertEqual(result["rule_count"], 4)
        check_call = next(call for call in calls if call[0][:3] == ("nft", "-c", "-f"))
        self.assertIn("add chain inet fw4 geo_guard_forward", check_call[1])
        self.assertIn(
            'comment "GeoWAN Sensitive Port Guard v0.6.0"', check_call[1]
        )
        self.assertIn("ct original proto-dst 58964", check_call[1])
        rule_lines = [
            line for line in check_call[1].splitlines()
            if line.startswith("add rule ")
        ]
        self.assertTrue(rule_lines)
        for line in rule_lines:
            self.assertFalse(any(
                verdict in line.split() for verdict in ("accept", "drop", "reject")
            ))

    def test_parse_guard_log_preserves_original_public_port_and_translated_target(self):
        line = (
            "Tue Nov  3 12:34:56 2026 kern.info kernel: "
            "GEOWAN_GUARD4|abcdef123456|58964| IN=pppoe-wan "
            "SRC=8.8.8.8 DST=10.0.0.193 PROTO=TCP SPT=50123 DPT=3389"
        )
        row = guard.parse_guard_log(line, now=1793709296, boot="boot1")
        self.assertIsNotNone(row)
        self.assertEqual(row["family"], 4)
        self.assertEqual(row["src"], "8.8.8.8")
        self.assertEqual(row["src_port"], 50123)
        self.assertEqual(row["public_port"], 58964)
        self.assertEqual(row["dst"], "10.0.0.193")
        self.assertEqual(row["dest_port"], 3389)
        self.assertEqual(row["service_id"], "abcdef123456")
        self.assertEqual(row["capture_method"], "kernel_log_sample")

    def test_parse_guard_log_rejects_non_global_and_family_mismatch(self):
        private = (
            "GEOWAN_GUARD4|abcdef123456|58964| SRC=10.0.0.1 "
            "DST=10.0.0.193 PROTO=TCP SPT=1 DPT=3389"
        )
        mismatch = (
            "GEOWAN_GUARD6|abcdef123456|58964| SRC=8.8.8.8 "
            "DST=10.0.0.193 PROTO=TCP SPT=1 DPT=3389"
        )
        self.assertIsNone(guard.parse_guard_log(private, now=1800000000))
        self.assertIsNone(guard.parse_guard_log(mismatch, now=1800000000))

    def test_guard_event_storage_has_a_hard_row_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "db.sqlite")
            guard.ensure_guard_schema(conn)
            lines = [
                "GEOWAN_GUARD4|abcdef123456|58964| SRC=8.8.8.8 "
                "DST=10.0.0.193 PROTO=TCP SPT=%d DPT=3389" % port
                for port in (50123, 50124, 50125)
            ]
            with mock.patch.object(guard, "GUARD_MAX_EVENTS", 2):
                guard.insert_guard_log_samples(
                    conn, now=1800000000, lines=lines, boot="boot-cap"
                )
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM guard_events").fetchone()[0], 2
            )
            conn.close()

    def test_guard_schema_is_separate_from_existing_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "db.sqlite"
            conn = sqlite3.connect(path)
            conn.execute("""
                CREATE TABLE events(
                    id TEXT PRIMARY KEY,ts INTEGER NOT NULL,family INTEGER NOT NULL,
                    src TEXT NOT NULL,dst TEXT,port INTEGER,proto TEXT
                )
            """)
            conn.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,?)",
                ("legacy", 1800000000, 4, "8.8.8.8", "10.0.0.1", 22, "TCP")
            )
            guard.ensure_guard_schema(conn)
            columns = [row[1] for row in conn.execute("PRAGMA table_info(events)")]
            self.assertEqual(columns, ["id", "ts", "family", "src", "dst", "port", "proto"])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
            self.assertIsNotNone(conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='guard_events'"
            ).fetchone())
            conn.close()

    def test_guard_log_insert_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "db.sqlite")
            guard.ensure_guard_schema(conn)
            line = (
                "GEOWAN_GUARD4|abcdef123456|58964| SRC=8.8.8.8 "
                "DST=10.0.0.193 PROTO=TCP SPT=50123 DPT=3389"
            )
            self.assertEqual(
                guard.insert_guard_log_samples(conn, now=1800000000,
                                               lines=[line], boot="boot1"), 1
            )
            self.assertEqual(
                guard.insert_guard_log_samples(conn, now=1800000000,
                                               lines=[line], boot="boot1"), 0
            )
            self.assertEqual(conn.execute(
                "SELECT public_port,dest_port FROM guard_events"
            ).fetchone(), (58964, 3389))
            conn.close()

    def test_guard_overview_returns_read_only_inventory_and_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "db.sqlite"
            config = Path(tmp) / "guard.json"
            config.write_text(json.dumps({
                "enabled": True, "mode": "observe",
                "log_rate_per_second": 2, "log_burst": 10
            }), encoding="utf-8")
            conn = sqlite3.connect(path)
            guard.ensure_guard_schema(conn)
            conn.execute("""
                CREATE TABLE geoip_cache(
                    ip TEXT PRIMARY KEY,country_code TEXT,country_name TEXT,
                    asn INTEGER,asn_org TEXT
                )
            """)
            now = 1800000000
            conn.execute("""
                INSERT INTO guard_services(
                    service_id,family,proto,public_port,dest_ip,dest_port,name,
                    category,category_label,runtime_active,conflict,config_match,
                    fingerprint,last_seen,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                "abcdef123456", 4, "tcp", 58964, "10.0.0.193", 3389,
                "P330tiny", "management", "远程桌面 / RDP",
                1, 0, 1, "fingerprint", now, now
            ))
            conn.execute(
                "INSERT INTO guard_events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("evt1", now - 30, 4, "8.8.8.8", 50123, 58964, "TCP",
                 "10.0.0.193", 3389, "abcdef123456", "kernel_log_sample")
            )
            conn.execute(
                "INSERT INTO geoip_cache VALUES(?,?,?,?,?)",
                ("8.8.8.8", "US", "美国", 15169, "Google LLC")
            )
            conn.execute(
                "INSERT INTO guard_state VALUES(?,?,?)",
                ("runtime", json.dumps({
                    "enabled": True, "mode": "observe",
                    "chain_installed": True, "wan_device": "pppoe-wan"
                }), now)
            )
            conn.commit()
            conn.close()

            data = guard.guard_overview(
                {"period": "24h"}, db_path=path, now=now, config_path=config
            )
            self.assertEqual(data["totals"]["samples"], 1)
            self.assertEqual(data["totals"]["unique_sources"], 1)
            self.assertEqual(data["inventory"][0]["public_port"], 58964)
            self.assertEqual(data["events"][0]["src"], "8.8.8.8")
            self.assertEqual(data["events"][0]["country_code"], "US")
            self.assertTrue(data["config"]["enabled"])
            self.assertEqual(data["selected_public_port"], 0)
            self.assertIn("国内和海外来源", data["disclaimer"])
            self.assertIn("不会执行", data["disclaimer"])
            filtered = guard.guard_overview(
                {"period": "24h", "public_port": 58964},
                db_path=path, now=now, config_path=config
            )
            self.assertEqual(filtered["totals"]["samples"], 1)
            self.assertEqual(filtered["selected_public_port"], 58964)

    def test_guard_overview_rejects_invalid_period(self):
        self.assertEqual(
            guard.guard_overview({"period": "all"}),
            {"error": "invalid_period"}
        )

    def test_guard_overview_rejects_invalid_public_port(self):
        self.assertEqual(
            guard.guard_overview({"period": "24h", "public_port": 70000}),
            {"error": "invalid_port"}
        )


if __name__ == "__main__":
    unittest.main()
