import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
import geowan_enforce as enforce


UCI = """
config redirect 'rdp'
        option name 'P330tiny'
        option src 'wan'
        option src_dport '58964'
        option dest_ip '10.0.0.193'
        option dest_port '3389'
        option proto 'tcp udp'

config redirect 'sslvpn'
        option name 'fgtvm-sslvpn'
        option src 'wan'
        option src_dport '20443'
        option dest_ip '10.0.0.205'
        option dest_port '10443'
        option proto 'tcp udp'

config redirect 'jump'
        option name 'jumpserver'
        option src 'wan'
        option src_dport '31080'
        option dest_ip '10.0.0.61'
        option dest_port '31080'
        option proto 'tcp'
"""

NFT = """
table inet fw4 {
 chain dstnat_wan {
  meta nfproto ipv4 tcp dport 58964 counter packets 24 bytes 1232 dnat ip to 10.0.0.193:3389 comment "!fw4: P330tiny"
  meta nfproto ipv4 udp dport 58964 counter packets 2 bytes 120 dnat ip to 10.0.0.193:3389 comment "!fw4: P330tiny"
  meta nfproto ipv4 tcp dport 20443 counter packets 2 bytes 120 dnat ip to 10.0.0.205:10443 comment "!fw4: fgtvm-sslvpn"
  meta nfproto ipv4 udp dport 20443 counter packets 2 bytes 120 dnat ip to 10.0.0.205:10443 comment "!fw4: fgtvm-sslvpn"
  meta nfproto ipv4 tcp dport 31080 counter packets 56 bytes 2864 dnat ip to 10.0.0.61:31080 comment "!fw4: jumpserver"
 }
}
"""


class EnforcementTests(unittest.TestCase):
    def test_default_policy_is_observe_only_with_seven_day_ttl(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.read_policy(Path(tmp) / "missing.json")
        self.assertTrue(policy["enabled"])
        self.assertEqual(policy["mode"], "observe")
        self.assertEqual(policy["ban_seconds"], 7 * 86400)
        self.assertIn((4, "tcp", 20443), policy["exception_set"])
        self.assertIn((6, "tcp", 58964), policy["exception_set"])

    def test_policy_protects_active_nat_and_direct_sensitive_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        protected = policy["protected"]
        exceptions = policy["exceptions"]
        self.assertIn((4, "tcp", 31080), protected)
        self.assertIn((4, "tcp", 5001), protected)
        self.assertIn((6, "tcp", 5001), protected)
        self.assertIn((4, "tcp", 22), protected)
        self.assertIn((4, "tcp", 3389), protected)
        self.assertIn((6, "tcp", 3389), protected)
        self.assertNotIn((4, "tcp", 58964), protected)
        self.assertNotIn((4, "tcp", 20443), protected)
        self.assertIn((4, "tcp", 58964), exceptions)
        self.assertIn((4, "udp", 58964), exceptions)
        self.assertIn((4, "tcp", 20443), exceptions)
        self.assertEqual(policy["active_redirect_count"], 5)


    def test_conflicting_active_redirect_tuple_is_still_protected(self):
        conflict = {
            "family": 4, "proto": "tcp", "public_port": 45678,
            "dest_ip": "10.0.0.10", "dest_port": 8080,
            "name": "ambiguous-service", "runtime_active": True,
            "conflict": True
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(enforce, "build_inventory", return_value=[conflict]):
                policy = enforce.build_policy(
                    "", "", Path(tmp) / "missing.json", now=1800000000
                )
        self.assertIn((4, "tcp", 45678), policy["protected"])
        self.assertNotIn((4, "tcp", 45678), policy["exceptions"])
        self.assertEqual(policy["conflict_count"], 1)

    def test_explicit_custom_sensitive_port_supports_non_nat_ipv6(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({
                "enabled": True,
                "mode": "observe",
                "sensitive_ports": [
                    {"port": 45555, "proto": "udp", "family": 6, "label": "custom app"}
                ],
                "exception_ports": []
            }), encoding="utf-8")
            policy = enforce.build_policy(
                "", "table inet fw4 { chain dstnat_wan {} }",
                path, now=1800000000
            )
        self.assertEqual(policy["protected"], {(6, "udp", 45555)})

    def test_enforce_rules_cover_input_forward_nat_and_non_nat(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        policy["mode"] = "enforce"
        script = enforce.render_enforcement_script(policy, "pppoe-wan")
        self.assertIn("add set inet fw4 geo_guard_ban4", script)
        self.assertIn("add set inet fw4 geo_guard_ban6", script)
        self.assertIn("flags dynamic,timeout", script)
        self.assertIn("timeout 604800s", script)
        self.assertIn("hook input priority -2", script)
        self.assertIn("hook forward priority -2", script)
        self.assertIn("ct original proto-dst 31080", script)
        self.assertIn("ct original proto-dst 5001", script)
        self.assertIn("update @geo_guard_ban4", script)
        self.assertIn("update @geo_guard_ban6", script)
        self.assertIn('counter log prefix "GEOWAN_BLOCK4|I|TCP|5001|" level warning drop', script)
        self.assertIn("ct original proto-dst != { 20443, 58964 }", script)
        self.assertNotIn("ct status dnat", script)
        self.assertNotIn("@geo_cn4", script)
        self.assertNotIn("@geo_cn6", script)
        self.assertIn("drop", script)

    def test_observe_mode_never_changes_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        script = enforce.render_enforcement_script(policy, "pppoe-wan")
        self.assertIn("hook input priority -2", script)
        self.assertIn("hook forward priority -2", script)
        self.assertIn("ct original proto-dst 31080", script)
        self.assertIn("ct original proto-dst 5001", script)
        self.assertIn('log prefix "GEOWAN_SENS4|I|TCP|5001|"', script)
        self.assertNotIn("drop", script)
        self.assertNotIn("reject", script)
        self.assertNotIn("update @geo_guard_ban", script)

    def test_exception_ports_are_not_sensitive_triggers(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        policy["mode"] = "enforce"
        script = enforce.render_enforcement_script(policy, "pppoe-wan")
        trigger_lines = [
            line for line in script.splitlines()
            if "update @geo_guard_ban" in line
        ]
        self.assertTrue(trigger_lines)
        self.assertFalse(any("proto-dst 20443" in line for line in trigger_lines))
        self.assertFalse(any("proto-dst 58964" in line for line in trigger_lines))
        self.assertTrue(any("proto-dst 31080" in line for line in trigger_lines))
        self.assertTrue(any("proto-dst 3389" in line for line in trigger_lines))

    def test_parse_block_log_and_idempotent_database_persistence(self):
        now = 1800000000
        line = (
            "Wed Nov  4 14:47:09 2026 kern.warn kernel: "
            "GEOWAN_BLOCK4|F|TCP|31080| IN=pppoe-wan OUT=br-lan "
            "SRC=180.98.41.231 DST=10.0.0.61 "
            "PROTO=TCP SPT=50123 DPT=31080"
        )
        item = enforce.parse_block_log(line, now, "boot1")
        self.assertIsNotNone(item)
        self.assertEqual(item["ip"], "180.98.41.231")
        self.assertEqual(item["family"], 4)
        self.assertEqual(item["trigger_port"], 31080)
        self.assertEqual(item["path"], "forward")
        self.assertEqual(item["expires_at"], now + 7 * 86400)

        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "db.sqlite")
            enforce.ensure_enforcement_schema(conn)
            self.assertEqual(
                enforce.insert_block_log_samples(
                    conn, now, [line], boot="boot1"
                ), 1
            )
            self.assertEqual(
                enforce.insert_block_log_samples(
                    conn, now + 5, [line], boot="boot1"
                ), 0
            )
            row = conn.execute(
                "SELECT family,trigger_port,proto,path,expires_at "
                "FROM guard_bans WHERE ip=?",
                ("180.98.41.231",)
            ).fetchone()
            self.assertEqual(
                row, (4, 31080, "TCP", "forward", now + 7 * 86400)
            )
            conn.close()

    def test_parse_nft_set_members_reads_remaining_timeout(self):
        output = json.dumps({"nftables": [{
            "set": {
                "name": "geo_guard_ban4",
                "elem": [
                    {"elem": {"val": "180.98.41.231", "expires": 3600}},
                    {"elem": {"val": "10.0.0.1", "expires": 120}}
                ]
            }
        }]})
        self.assertEqual(
            enforce.parse_nft_set_members(output, 4),
            {"180.98.41.231": 3600, "10.0.0.1": 120}
        )

    def test_restore_missing_kernel_element_from_persistent_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "db.sqlite")
            enforce.ensure_enforcement_schema(conn)
            now = 1800000000
            conn.execute(
                "INSERT INTO guard_bans(ip,family,first_seen,last_seen,expires_at) "
                "VALUES(?,?,?,?,?)",
                ("180.98.41.231", 4, now - 60, now - 60, now + 3600)
            )
            calls = []

            def fake_runner(*args, input_text=None):
                calls.append((args, input_text))
                if args[:5] == ("nft", "-j", "list", "set", "inet"):
                    return json.dumps({"nftables": [{
                        "set": {"name": "geo_guard_ban4", "elem": []}
                    }]})
                return ""

            current, restored = enforce._restore_and_reconcile_set(
                conn, 4, "geo_guard_ban4", now, fake_runner
            )
            self.assertEqual((current, restored), (0, 1))
            add_call = next(call for call in calls if call[0][:3] == ("nft", "add", "element"))
            self.assertIn("180.98.41.231 timeout 3600s", add_call[0][-1])
            conn.close()

    def test_invalid_wan_device_is_rejected(self):
        with self.assertRaises(ValueError):
            enforce.render_enforcement_script(
                {"mode": "observe", "protected": set(), "exceptions": set()},
                'pppoe-wan"; drop'
            )


if __name__ == "__main__":
    unittest.main()
