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
                       occurrence_count,last_alert_at
                FROM guard_alerts
            """).fetchone()

            self.assertEqual(result["created"], 1)
            self.assertEqual(row[0], "multi_port_access")
            self.assertEqual(row[1], "notice")
            self.assertEqual(row[2], "8.8.8.8")
            self.assertEqual(row[3], 3)
            self.assertEqual(json.loads(row[4]), [20443, 31080, 58964])
            self.assertEqual(row[5], 1)
            self.assertEqual(row[6], now)
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
            self.assertEqual(json.loads(data["alerts"][0]["public_ports"]),
                             [20443, 31080, 58964])


if __name__ == "__main__":
    unittest.main()
