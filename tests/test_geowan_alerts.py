import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from geowan_alerts import evaluate_guard_alerts, read_policy
from geowan_guard import ensure_guard_schema, guard_overview


def make_database(path, now, ports, country_code="CN", runtime_mode="observe"):
    conn = sqlite3.connect(path)
    ensure_guard_schema(conn)
    conn.execute("""
        CREATE TABLE geoip_cache(
            ip TEXT PRIMARY KEY,country_code TEXT,country_name TEXT,
            region TEXT,city TEXT,asn INTEGER,asn_org TEXT
        )
    """)
    conn.execute(
        "INSERT INTO geoip_cache VALUES(?,?,?,?,?,?,?)",
        ("8.8.8.8", country_code, "测试国家", "测试地区",
         "测试城市", 64500, "Example Network")
    )
    conn.execute("""
        CREATE TABLE bans(
            ip TEXT PRIMARY KEY,family INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)
    runtime = {
        "enabled": runtime_mode == "observe",
        "mode": runtime_mode,
        "chain_installed": runtime_mode == "observe",
        "wan_device": "pppoe-wan"
    }
    conn.execute(
        "INSERT INTO guard_state VALUES(?,?,?)",
        ("runtime", json.dumps(runtime), now)
    )
    for index, port in enumerate(ports):
        service_id = "service-%d" % index
        conn.execute("""
            INSERT INTO guard_services(
                service_id,family,proto,public_port,dest_ip,dest_port,name,
                category,category_label,runtime_active,conflict,config_match,
                fingerprint,last_seen,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            service_id, 4, "tcp", port, "10.0.0.61", 443,
            "service-%d" % port, "application", "公网应用",
            1, 0, 1, "fingerprint-%d" % index, now, now
        ))
        conn.execute(
            "INSERT INTO guard_events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                "event-%d" % index, now - 60 + index * 10, 4, "8.8.8.8",
                40000 + index, port, "TCP", "10.0.0.61", 443,
                service_id, "kernel_log_sample"
            )
        )
    conn.commit()
    return conn


def add_event(conn, event_id, ts, src, public_port, service_id,
              src_port=45000):
    conn.execute(
        "INSERT INTO guard_events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            event_id, ts, 4, src, src_port, public_port, "TCP",
            "10.0.0.61", 443, service_id, "kernel_log_sample"
        )
    )


class GuardAlertTests(unittest.TestCase):
    def write_policy(self, path, **values):
        policy = {
            "enabled": True,
            "window_seconds": 600,
            "min_distinct_public_ports": 3,
            "min_samples": 3,
            "cooldown_seconds": 900,
            "retention_days": 30,
            "max_alerts": 50000
        }
        policy.update(values)
        path.write_text(json.dumps(policy), encoding="utf-8")

    def test_three_public_ports_create_advisory_alert_even_for_cn_source(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = make_database(root / "db.sqlite", now, [20443, 31080, 58964])
            policy = root / "policy.json"
            self.write_policy(policy)

            result = evaluate_guard_alerts(conn, now=now, policy_path=policy)
            row = conn.execute("""
                SELECT rule_id,severity,src,unique_public_ports,public_ports,
                       occurrence_count,last_alert_at,risk_score
                FROM guard_alerts
            """).fetchone()

            self.assertEqual(result["created"], 1)
            self.assertEqual(row[0], "multi_port_access")
            self.assertEqual(row[1], "low")
            self.assertEqual(row[2], "8.8.8.8")
            self.assertEqual(row[3], 3)
            self.assertEqual(json.loads(row[4]), [20443, 31080, 58964])
            self.assertEqual(row[5], 1)
            self.assertEqual(row[6], now)
            self.assertEqual(row[7], 35)
            conn.close()

    def test_two_public_ports_do_not_create_alert(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            conn = make_database(Path(tmp) / "db.sqlite", now, [20443, 31080])
            result = evaluate_guard_alerts(conn, now=now)
            self.assertEqual(result["created"], 0)
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM guard_alerts"
            ).fetchone()[0], 0)
            conn.close()

    def test_cooldown_deduplicates_and_realerts_after_15_minutes(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = make_database(root / "db.sqlite", now, [20443, 31080, 58964])
            policy = root / "policy.json"
            self.write_policy(policy)

            first = evaluate_guard_alerts(conn, now=now, policy_path=policy)
            second = evaluate_guard_alerts(
                conn, now=now + 30, policy_path=policy
            )
            row = conn.execute(
                "SELECT occurrence_count,last_alert_at FROM guard_alerts"
            ).fetchone()
            self.assertEqual(first["created"], 1)
            self.assertEqual(second["created"], 0)
            self.assertEqual(row, (1, now))

            later = now + 901
            for index, port in enumerate([20443, 31080, 58964]):
                conn.execute(
                    "INSERT INTO guard_events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "later-%d" % index, later - 30 + index * 10, 4,
                        "8.8.8.8", 41000 + index, port, "TCP",
                        "10.0.0.61", 443, "service-%d" % index,
                        "kernel_log_sample"
                    )
                )
            third = evaluate_guard_alerts(
                conn, now=later, policy_path=policy
            )
            row = conn.execute(
                "SELECT occurrence_count,last_alert_at FROM guard_alerts"
            ).fetchone()
            self.assertEqual(third["re_alerted"], 1)
            self.assertEqual(row, (2, later))
            conn.close()

    def test_degraded_guard_does_not_generate_alerts(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            conn = make_database(
                Path(tmp) / "db.sqlite", now,
                [20443, 31080, 58964], runtime_mode="degraded"
            )
            result = evaluate_guard_alerts(conn, now=now)
            self.assertFalse(result["enabled"])
            self.assertEqual(result["reason"], "guard_not_observing")
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM guard_alerts"
            ).fetchone()[0], 0)
            conn.close()

    def test_invalid_policy_disables_alert_evaluation(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = make_database(root / "db.sqlite", now, [20443, 31080, 58964])
            policy = root / "policy.json"
            policy.write_text("{invalid", encoding="utf-8")
            self.assertFalse(read_policy(policy)["enabled"])
            result = evaluate_guard_alerts(conn, now=now, policy_path=policy)
            self.assertFalse(result["enabled"])
            self.assertEqual(result["created"], 0)
            conn.close()

    def test_installer_copies_alert_module_and_preserves_local_policy(self):
        root = Path(__file__).resolve().parents[1]
        install = (root / "install.sh").read_text(encoding="utf-8")
        uninstall = (root / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn('cp "$BASE/agent/geowan_alerts.py" /usr/libexec/geowan-console/geowan_alerts.py', install)
        self.assertIn('cp "$BASE/guard-alert-policy.example.json" /etc/geowan-console/guard-alert-policy.json', install)
        self.assertIn('if [ ! -f /etc/geowan-console/guard-alert-policy.json ]; then', install)
        self.assertIn('rm -rf /usr/libexec/geowan-console', uninstall)
        self.assertNotIn('rm -f /etc/geowan-console/guard-alert-policy.json', uninstall)

    def test_high_frequency_same_source_same_service_creates_medium_alert(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            conn = make_database(Path(tmp) / "db.sqlite", now, [20443])
            for index in range(19):
                add_event(
                    conn, "freq-%d" % index, now - 110 + index * 5,
                    "8.8.8.8", 20443, "service-0", 46000 + index
                )
            result = evaluate_guard_alerts(conn, now=now)
            row = conn.execute("""
                SELECT rule_id,severity,risk_score,target_port,sample_count
                FROM guard_alerts WHERE rule_id='high_frequency_access'
            """).fetchone()
            self.assertEqual(result["created"], 1)
            self.assertEqual(
                row, ("high_frequency_access", "medium", 60, 20443, 20)
            )
            conn.close()

    def test_many_sources_targeting_one_public_port_creates_low_alert(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            conn = make_database(Path(tmp) / "db.sqlite", now, [20443])
            for index in range(1, 8):
                ip = "203.0.113.%d" % index
                conn.execute(
                    "INSERT INTO geoip_cache VALUES(?,?,?,?,?,?,?)",
                    (ip, "CN", "测试国家", "", "", None, "")
                )
                for sample in range(2):
                    add_event(
                        conn, "target-%d-%d" % (index, sample),
                        now - 100 + sample * 10, ip, 20443, "service-0",
                        47000 + index * 10 + sample
                    )
            result = evaluate_guard_alerts(conn, now=now)
            row = conn.execute("""
                SELECT rule_id,severity,risk_score,target_port,sample_count,
                       details_json
                FROM guard_alerts WHERE rule_id='multi_source_target'
            """).fetchone()
            self.assertEqual(result["created"], 1)
            self.assertEqual(
                row[:5], ("multi_source_target", "low", 40, 20443, 15)
            )
            self.assertEqual(json.loads(row[5])["source_count"], 8)
            conn.close()

    def test_active_blacklist_source_access_creates_high_alert(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            conn = make_database(Path(tmp) / "db.sqlite", now, [20443])
            conn.execute(
                "INSERT INTO bans VALUES(?,?,?,?,?)",
                ("8.8.8.8", 4, now - 500, now - 20, now + 3600)
            )
            add_event(conn, "ban-hit-2", now - 10, "8.8.8.8",
                      20443, "service-0", 48001)
            result = evaluate_guard_alerts(conn, now=now)
            row = conn.execute("""
                SELECT rule_id,severity,risk_score,details_json
                FROM guard_alerts WHERE rule_id='active_blacklist_access'
            """).fetchone()
            self.assertEqual(result["created"], 1)
            self.assertEqual(
                row[:3], ("active_blacklist_access", "high", 75)
            )
            self.assertEqual(
                json.loads(row[3])["active_ban_expires_at"], now + 3600
            )
            conn.close()

    def test_same_asn_multiple_sources_creates_low_context_alert(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            conn = make_database(Path(tmp) / "db.sqlite", now, [20443])
            for index in range(1, 4):
                ip = "198.51.100.%d" % index
                conn.execute(
                    "INSERT INTO geoip_cache VALUES(?,?,?,?,?,?,?)",
                    (ip, "US", "测试国家", "", "", 64500, "Example Network")
                )
                for sample in range(3):
                    add_event(
                        conn, "asn-%d-%d" % (index, sample),
                        now - 100 + sample * 10, ip, 20443, "service-0",
                        49000 + index * 10 + sample
                    )
            result = evaluate_guard_alerts(conn, now=now)
            row = conn.execute("""
                SELECT rule_id,severity,risk_score,details_json
                FROM guard_alerts WHERE rule_id='asn_multi_source'
            """).fetchone()
            self.assertEqual(result["created"], 1)
            self.assertEqual(row[:3], ("asn_multi_source", "low", 30))
            details = json.loads(row[3])
            self.assertEqual(details["asn"], 64500)
            self.assertEqual(details["source_count"], 4)
            conn.close()

    def test_v061_alert_schema_is_migrated_additively(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "legacy.sqlite")
            conn.execute("""
                CREATE TABLE guard_alerts(
                    alert_id TEXT PRIMARY KEY,rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'notice',src TEXT NOT NULL,
                    created_at INTEGER NOT NULL,first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,last_alert_at INTEGER NOT NULL,
                    window_start INTEGER NOT NULL,window_seconds INTEGER NOT NULL,
                    sample_count INTEGER NOT NULL,unique_public_ports INTEGER NOT NULL,
                    public_ports TEXT NOT NULL DEFAULT '[]',
                    occurrence_count INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.execute(
                "INSERT INTO guard_alerts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("legacy", "multi_port_access", "notice", "8.8.8.8",
                 1, 1, 1, 1, 0, 600, 3, 3, "[1,2,3]", 1)
            )
            ensure_guard_schema(conn)
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(guard_alerts)")
            }
            self.assertTrue({
                "target_port", "details_json", "risk_score", "risk_factors"
            } <= columns)
            self.assertEqual(
                conn.execute("SELECT alert_id FROM guard_alerts").fetchone()[0],
                "legacy"
            )
            conn.close()

    def test_guard_overview_filters_alert_rule_and_severity(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = make_database(root / "db.sqlite", now,
                                 [20443, 31080, 58964])
            conn.execute(
                "INSERT INTO bans VALUES(?,?,?,?,?)",
                ("8.8.8.8", 4, now - 500, now - 20, now + 3600)
            )
            add_event(conn, "filter-ban-hit", now - 10, "8.8.8.8",
                      20443, "service-0", 50001)
            evaluate_guard_alerts(conn, now=now)
            conn.commit()
            conn.close()
            config = root / "guard.json"
            config.write_text(json.dumps({
                "enabled": True, "mode": "observe",
                "log_rate_per_second": 2, "log_burst": 10
            }), encoding="utf-8")
            high = guard_overview(
                {"period": "24h", "alert_severity": "high"},
                db_path=root / "db.sqlite", now=now, config_path=config
            )
            rule = guard_overview(
                {"period": "24h", "alert_rule": "active_blacklist_access"},
                db_path=root / "db.sqlite", now=now, config_path=config
            )
            low = guard_overview(
                {"period": "24h", "alert_severity": "low"},
                db_path=root / "db.sqlite", now=now, config_path=config
            )
            self.assertEqual(
                [x["rule_id"] for x in high["alerts"]],
                ["active_blacklist_access"]
            )
            self.assertEqual(
                [x["rule_id"] for x in rule["alerts"]],
                ["active_blacklist_access"]
            )
            self.assertEqual(
                [x["rule_id"] for x in low["alerts"]],
                ["multi_port_access"]
            )
            self.assertEqual(high["selected_alert_severity"], "high")

    def test_guard_overview_returns_geoip_enriched_alerts(self):
        now = 1800000000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = make_database(root / "db.sqlite", now, [20443, 31080, 58964])
            policy = root / "policy.json"
            self.write_policy(policy)
            evaluate_guard_alerts(conn, now=now, policy_path=policy)
            conn.commit()
            conn.close()

            guard_config = root / "guard.json"
            guard_config.write_text(json.dumps({
                "enabled": True, "mode": "observe",
                "log_rate_per_second": 2, "log_burst": 10
            }), encoding="utf-8")
            data = guard_overview(
                {"period": "24h"}, db_path=root / "db.sqlite",
                now=now, config_path=guard_config
            )
            self.assertEqual(len(data["alerts"]), 1)
            self.assertEqual(data["alerts"][0]["src"], "8.8.8.8")
            self.assertEqual(data["alerts"][0]["country_code"], "CN")
            self.assertEqual(data["alerts"][0]["asn"], 64500)
            self.assertEqual(data["alerts"][0]["risk_score"], 35)
            self.assertEqual(data["alerts"][0]["severity"], "low")
            self.assertEqual(json.loads(data["alerts"][0]["public_ports"]),
                             [20443, 31080, 58964])


if __name__ == "__main__":
    unittest.main()
