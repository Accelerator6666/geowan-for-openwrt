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

    def test_example_config_matches_default_honeypot_catalog(self):
        example = Path(__file__).resolve().parents[1] / "enforcement.example.json"
        policy = enforce.read_policy(example)
        expected = {(family, item["proto"], item["port"])
                    for family in (4, 6)
                    for item in enforce.DEFAULT_HONEYPOT_PORTS}
        self.assertEqual(policy["sensitive_set"], expected)
        self.assertEqual({x["category"] for x in enforce.DEFAULT_HONEYPOT_PORTS},
                         {"windows", "linux", "synology", "qnap", "docker", "media"})

    def test_default_policy_only_triggers_unused_honeypots(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        protected = policy["protected"]
        exceptions = policy["exceptions"]
        self.assertEqual(protected, {
            (family, entry["proto"], entry["port"])
            for family in (4, 6)
            for entry in enforce.DEFAULT_HONEYPOT_PORTS
        })
        self.assertEqual({group["category"] for group in enforce.honeypot_groups(policy)},
                         {"windows", "linux", "synology", "qnap", "docker", "media"})
        self.assertNotIn((4, "tcp", 22), protected)
        self.assertNotIn((4, "tcp", 80), protected)
        self.assertNotIn((4, "tcp", 443), protected)
        self.assertNotIn((4, "tcp", 31080), protected)
        self.assertNotIn((4, "tcp", 58964), protected)
        self.assertNotIn((4, "tcp", 20443), protected)
        self.assertIn((4, "tcp", 58964), exceptions)
        self.assertIn((4, "udp", 58964), exceptions)
        self.assertIn((4, "tcp", 20443), exceptions)
        self.assertIn((4, "tcp", 31080), exceptions)
        self.assertIn((4, "udp", 31080), exceptions)
        self.assertEqual(policy["active_redirect_count"], 5)

    def test_legacy_broad_enforcement_fields_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.json"
            path.write_text(json.dumps({
                "enabled": True, "mode": "enforce",
                "protect_all_active_redirects": True,
                "auto_detect_rdp": True,
                "sensitive_ports": [{"port": 31080, "proto": "tcp"}],
                "exception_ports": []
            }), encoding="utf-8")
            policy = enforce.build_policy(UCI, NFT, path, now=1800000000,
                                          listening=set())
        self.assertEqual(policy["protected"], {
            (family, entry["proto"], entry["port"])
            for family in (4, 6)
            for entry in enforce.DEFAULT_HONEYPOT_PORTS
        })
        self.assertIn((4, "tcp", 31080), policy["exceptions"])
        self.assertIn((4, "udp", 31080), policy["exceptions"])

    def test_router_listener_cannot_be_honeypot(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000,
                listening={(4, "tcp", 21)}
            )
        self.assertNotIn((4, "tcp", 21), policy["protected"])
        self.assertIn((4, "tcp", 21), policy["skipped_in_use"])

    def test_wan_accept_ports_are_skipped_but_disabled_rules_are_not(self):
        uci = UCI + """
config rule 'nas_allow'
        option src 'wan'
        option dest_port '5000-5001'
        option proto 'tcp'
        option family 'ipv4'
        option target 'ACCEPT'

config rule 'disabled_media'
        option src 'wan'
        option dest_port '8096'
        option proto 'tcp'
        option target 'ACCEPT'
        option enabled '0'
"""
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(uci, NFT, Path(tmp) / "missing.json",
                                          now=1800000000, listening=set())
        for port in (5000, 5001):
            self.assertNotIn((4, "tcp", port), policy["protected"])
            self.assertIn((6, "tcp", port), policy["protected"])
            self.assertIn((4, "tcp", port), policy["skipped_in_use"])
        self.assertIn((4, "tcp", 8096), policy["protected"])



    def test_wan_accept_rule_does_not_create_honeypot(self):
        uci = UCI + """
config rule 'allow_direct_rdp'
        option name 'Allow RDP'
        option src 'wan'
        option dest_port '3389'
        option proto 'tcp'
        option target 'ACCEPT'
"""
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                uci, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        self.assertNotIn((4, "tcp", 3389), policy["protected"])
        self.assertNotIn((6, "tcp", 3389), policy["protected"])
        self.assertIn((4, "tcp", 3389), policy["skipped_in_use"])
        self.assertNotIn((4, "tcp", 3389), policy["exceptions"])
        self.assertNotIn((6, "tcp", 3389), policy["exceptions"])
        # The public DNAT port targeting backend 3389 remains the RDP bypass.
        self.assertIn((4, "tcp", 58964), policy["exceptions"])
        self.assertNotIn((4, "tcp", 58964), policy["protected"])


    def test_disabled_redirect_does_not_become_honeypot(self):
        uci = UCI + """
config redirect 'legacy_fgtvm_sslvpn'
        option name 'fgtvm-sslvpn'
        option src 'wan'
        option src_dport '41443'
        option dest_ip '10.0.0.61'
        option dest_port '41443'
        option proto 'tcp udp'
        option enabled '0'

config rule 'legacy_fgtvm_sslvpn'
        option name 'fgtvm-sslvpn'
        option src 'wan'
        option src_port '41443'
        option dest 'lan'
        option dest_ip '10.0.0.61'
        option dest_port '41443'
        option target 'ACCEPT'
"""
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                uci, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        for family in (4, 6):
            for proto in ("tcp", "udp"):
                self.assertNotIn((family, proto, 41443), policy["protected"])
                self.assertNotIn((family, proto, 41443), policy["exceptions"])
        # The live 20443 DNAT is still detected as SSLVPN and remains exempt.
        self.assertIn((4, "tcp", 20443), policy["exceptions"])
        self.assertIn((4, "udp", 20443), policy["exceptions"])

    def test_active_redirect_overlapping_honeypot_is_skipped(self):
        conflict = {
            "family": 4, "proto": "tcp", "public_port": 21,
            "dest_ip": "10.0.0.10", "dest_port": 8080,
            "name": "ambiguous-service", "runtime_active": True,
            "conflict": True
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(enforce, "build_inventory", return_value=[conflict]):
                policy = enforce.build_policy(
                    "", "", Path(tmp) / "missing.json", now=1800000000
                )
        self.assertNotIn((4, "tcp", 21), policy["protected"])
        self.assertEqual(policy["skipped_in_use"], [(4, "tcp", 21)])
        self.assertEqual(policy["conflict_count"], 1)

    def test_explicit_custom_honeypot_supports_ipv6(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({
                "enabled": True,
                "mode": "observe",
                "honeypot_ports": [
                    {"port": 45555, "proto": "udp", "family": 6, "label": "custom app"}
                ],
                "exception_ports": []
            }), encoding="utf-8")
            policy = enforce.build_policy(
                "", "table inet fw4 { chain dstnat_wan {} }",
                path, now=1800000000
            )
        self.assertEqual(policy["protected"], {(6, "udp", 45555)})

    def test_enforce_rules_cover_cn_honeypots_and_spare_nat_ports(self):
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
        self.assertIn("ct original proto-dst 21", script)
        self.assertNotIn("ct original proto-dst 31080 update", script)
        self.assertIn("ct original proto-dst 5001", script)
        self.assertIn("ct original proto-dst 8080", script)
        self.assertIn("ct original proto-dst 2375", script)
        self.assertIn("ct original proto-dst 32400", script)
        self.assertIn("update @geo_guard_ban4", script)
        self.assertIn("update @geo_guard_ban6", script)
        self.assertIn('counter log prefix "GEOWAN_HONEY4|I|TCP|21|" level warn drop', script)
        self.assertIn("ct original proto-dst != { 20443, 31080, 58964 }", script)
        self.assertNotIn("ct status dnat", script)
        self.assertIn("ip saddr @geo_cn4", script)
        self.assertIn("ip6 saddr @geo_cn6", script)
        self.assertIn("drop", script)

    def test_observe_mode_never_changes_verdicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        script = enforce.render_enforcement_script(policy, "pppoe-wan")
        self.assertIn("hook input priority -2", script)
        self.assertIn("hook forward priority -2", script)
        self.assertIn("ct original proto-dst 21", script)
        self.assertNotIn("ct original proto-dst 31080", script)
        self.assertIn('log prefix "GEOWAN_SENS4|I|TCP|21|"', script)
        self.assertIn("ip saddr @geo_cn4", script)
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
        self.assertFalse(any("proto-dst 31080" in line for line in trigger_lines))
        self.assertTrue(any("proto-dst 3389" in line for line in trigger_lines))
        self.assertTrue(any("proto-dst 21" in line for line in trigger_lines))

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
        self.assertEqual(item["reason"], "sensitive_port_hit")
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

    def test_cn_honeypot_log_has_distinct_reason(self):
        now = 1800000000
        line = (
            "Wed Nov  4 14:47:09 2026 kern.warn kernel: "
            "GEOWAN_HONEY4|I|TCP|21| IN=pppoe-wan OUT= "
            "SRC=180.98.41.231 DST=10.0.0.1 "
            "PROTO=TCP SPT=50123 DPT=21"
        )
        self.assertEqual(enforce.parse_block_log(line, now, "boot1")["reason"],
                         "cn_honeypot")
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "db.sqlite")
            enforce.ensure_enforcement_schema(conn)
            self.assertEqual(enforce.insert_block_log_samples(
                conn, now, [line], boot="boot1"), 1)
            self.assertEqual(conn.execute(
                "SELECT reason FROM guard_bans WHERE ip='180.98.41.231'"
            ).fetchone()[0], "cn_honeypot")
            conn.close()

    def test_cn_status_excludes_legacy_bans(self):
        now = 1800000000
        with sqlite3.connect(":memory:") as conn:
            enforce.ensure_enforcement_schema(conn)
            for ip, reason, first in (
                ("1.1.1.1", "cn_honeypot", now - 60),
                ("2.2.2.2", "cn_honeypot", now - 90000),
                ("3.3.3.3", "sensitive_port_hit", now - 30),
            ):
                conn.execute("""
                    INSERT INTO guard_bans(ip,family,first_seen,last_seen,expires_at,reason)
                    VALUES(?,4,?,?,?,?)
                """, (ip, first, now - 10, now + 3600, reason))
            result = enforce.enforcement_cn_summary(conn, now)
            self.assertEqual(result["active_ips"], 2)
            self.assertEqual(result["new_ips_24h"], 1)
            self.assertEqual(result["legacy_active_ips"], 1)
            self.assertEqual(result["last_hit"], now - 10)

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

    def test_chain_rules_match_detects_missing_or_extra_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        name = enforce.INPUT_CHAIN
        lines = [
            "table inet fw4 {",
            " chain %s {" % name,
            '  type filter hook input priority filter - 2; policy accept;',
            '  comment "%s";' % enforce.CHAIN_COMMENTS[name],
        ]
        for family, proto, port in sorted(policy["protected"]):
            marker = "GEOWAN_SENS%d|I|%s|%d|" % (
                family, proto.upper(), port
            )
            lines.append(
                '  iifname "pppoe-wan" %s saddr @geo_cn%d '
                'counter packets 0 bytes 0 log prefix "%s" level info'
                % ("ip" if family == 4 else "ip6", family, marker)
            )
        lines.append(" }")
        lines.append("}")
        output = "\n".join(lines)
        runner = lambda *args: output
        self.assertTrue(enforce._chain_rules_match(
            name, "input", policy, runner
        ))
        missing = output.replace("GEOWAN_SENS4|I|TCP|21|", "MISSING", 1)
        self.assertFalse(enforce._chain_rules_match(
            name, "input", policy, lambda *args: missing
        ))
        extra = output + '\n  counter packets 0 bytes 0'
        self.assertFalse(enforce._chain_rules_match(
            name, "input", policy, lambda *args: extra
        ))

    def test_enforce_chain_match_requires_drop_verdicts_and_ban_sets(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        policy["mode"] = "enforce"
        lines = [
            "table inet fw4 {",
            " chain %s {" % enforce.FORWARD_CHAIN,
            "  type filter hook forward priority filter - 2; policy accept;",
            '  comment "%s";' % enforce.CHAIN_COMMENTS[enforce.FORWARD_CHAIN],
        ]
        for family, proto, port in sorted(policy["protected"]):
            marker = "GEOWAN_HONEY%d|F|%s|%d|" % (
                family, proto.upper(), port
            )
            lines.append(
                '  iifname "pppoe-wan" %s saddr @geo_cn%d '
                'counter packets 0 bytes 0 log prefix "%s" level warn drop'
                % ("ip" if family == 4 else "ip6", family, marker)
            )
        for set_name in (enforce.BAN4_SET, enforce.BAN6_SET):
            for _ in range(3):
                lines.append(
                    '  iifname "pppoe-wan" @%s counter packets 0 bytes 0 drop'
                    % set_name
                )
        output = "\n".join(lines)
        self.assertTrue(enforce._chain_rules_match(
            enforce.FORWARD_CHAIN, "forward", policy, lambda *args: output
        ))
        weakened = output.replace("level warn drop", "level warn", 1)
        self.assertFalse(enforce._chain_rules_match(
            enforce.FORWARD_CHAIN, "forward", policy, lambda *args: weakened
        ))

    def test_rules_fingerprint_changes_when_mode_or_policy_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = enforce.build_policy(
                UCI, NFT, Path(tmp) / "missing.json", now=1800000000
            )
        original = enforce._rules_fingerprint(policy, "pppoe-wan")
        changed_mode = dict(policy, mode="enforce")
        self.assertNotEqual(
            original, enforce._rules_fingerprint(changed_mode, "pppoe-wan")
        )
        changed_ports = dict(policy, protected=set(policy["protected"]))
        changed_ports["protected"].add((4, "tcp", 45555))
        self.assertNotEqual(
            original, enforce._rules_fingerprint(changed_ports, "pppoe-wan")
        )

    def test_refresh_skips_unchanged_enforcement_chain_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "missing.json"
            db_path = Path(tmp) / "db.sqlite"
            policy = enforce.build_policy(
                UCI, NFT, config, now=1800000000
            )
            fingerprint = enforce._rules_fingerprint(policy, "pppoe-wan")
            conn = sqlite3.connect(db_path)
            enforce.ensure_enforcement_schema(conn)
            conn.execute(
                "INSERT OR REPLACE INTO guard_enforcement_state(key,value) "
                "VALUES('rules_fingerprint',?)",
                (fingerprint,)
            )
            conn.commit()

            chain_outputs = {}
            for name, hook, path_code in (
                (enforce.INPUT_CHAIN, "input", "I"),
                (enforce.FORWARD_CHAIN, "forward", "F"),
            ):
                lines = [
                    "table inet fw4 {",
                    " chain %s {" % name,
                    "  type filter hook %s priority filter - 2; policy accept;" % hook,
                    '  comment "%s";' % enforce.CHAIN_COMMENTS[name],
                ]
                for family, proto, port in sorted(policy["protected"]):
                    marker = "GEOWAN_SENS%d|%s|%s|%d|" % (
                        family, path_code, proto.upper(), port
                    )
                    lines.append(
                        '  iifname "pppoe-wan" %s saddr @geo_cn%d '
                        'counter packets 0 bytes 0 log prefix "%s" level info'
                        % ("ip" if family == 4 else "ip6", family, marker)
                    )
                lines.extend([" }", "}"])
                chain_outputs[name] = "\n".join(lines)

            calls = []
            def runner(*args, input_text=None):
                calls.append((args, input_text))
                if args == ("uci", "-q", "export", "firewall"):
                    return UCI
                if args == ("nft", "-a", "list", "chain", "inet", "fw4", "dstnat_wan"):
                    return NFT
                if args == ("ubus", "call", "network.interface.wan", "status"):
                    return json.dumps({"l3_device": "pppoe-wan"})
                if args[:5] == ("nft", "list", "chain", "inet", "fw4"):
                    return chain_outputs[args[5]]
                raise AssertionError("unexpected command: %r" % (args,))

            result = enforce.refresh_enforcement(
                conn, now=1800000000, config_path=config, command_runner=runner
            )
            self.assertEqual(result["mode"], "observe")
            self.assertFalse(result["rules_refreshed"])
            self.assertEqual(result["rules_fingerprint"], fingerprint)
            self.assertFalse(any(args[:3] == ("nft", "-f", "-") for args, _ in calls))
            conn.close()

    def test_invalid_wan_device_is_rejected(self):
        with self.assertRaises(ValueError):
            enforce.render_enforcement_script(
                {"mode": "observe", "protected": set(), "exceptions": set()},
                'pppoe-wan"; drop'
            )


if __name__ == "__main__":
    unittest.main()
