#!/usr/bin/env python3
"""Alert-only heuristics for GeoWAN Guard.

This module reads sampled Guard events and writes advisory records to SQLite.
It never invokes nftables, changes firewall rules, or blocks traffic.
"""
import hashlib
import json
import os
from pathlib import Path

POLICY_PATH = Path(os.environ.get(
    "GEOWAN_ALERT_POLICY", "/etc/geowan-console/guard-alert-policy.json"
))
RULE_ID = "multi_port_access"
DEFAULT_POLICY = {
    "enabled": True,
    "window_seconds": 600,
    "min_distinct_public_ports": 3,
    "min_samples": 3,
    "cooldown_seconds": 900,
    "retention_days": 30,
    "max_alerts": 50000,
}


def _bounded_int(raw, key, default, minimum, maximum):
    value = raw.get(key, default)
    if isinstance(value, bool):
        return default
    try:
        value = int(value)
    except (TypeError, ValueError):
        return default
    return min(maximum, max(minimum, value))


def read_policy(path=None):
    """Read local alert thresholds; malformed files fail closed for alerting."""
    path = Path(path or POLICY_PATH)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("policy must be an object")
    except FileNotFoundError:
        raw = {}
    except (OSError, ValueError, json.JSONDecodeError):
        policy = dict(DEFAULT_POLICY)
        policy["enabled"] = False
        policy["policy_error"] = "invalid_policy"
        return policy

    policy = dict(DEFAULT_POLICY)
    policy["enabled"] = raw.get("enabled", True) is True
    policy["window_seconds"] = _bounded_int(
        raw, "window_seconds", 600, 60, 3600
    )
    policy["min_distinct_public_ports"] = _bounded_int(
        raw, "min_distinct_public_ports", 3, 2, 32
    )
    policy["min_samples"] = _bounded_int(raw, "min_samples", 3, 2, 10000)
    policy["cooldown_seconds"] = _bounded_int(
        raw, "cooldown_seconds", 900, 60, 86400
    )
    policy["retention_days"] = _bounded_int(
        raw, "retention_days", 30, 1, 90
    )
    policy["max_alerts"] = _bounded_int(
        raw, "max_alerts", 50000, 1000, 200000
    )
    return policy


def evaluate_guard_alerts(conn, now=None, policy_path=None, candidate_limit=200):
    """Create/update advisory alerts from sampled events for active services."""
    import time

    now = int(time.time()) if now is None else int(now)
    policy = read_policy(policy_path)
    result = {
        "enabled": bool(policy["enabled"]),
        "rule_id": RULE_ID,
        "candidates": 0,
        "created": 0,
        "updated": 0,
        "re_alerted": 0,
        "policy_error": policy.get("policy_error", ""),
    }
    if not policy["enabled"]:
        return result

    runtime_row = conn.execute(
        "SELECT value FROM guard_state WHERE key='runtime'"
    ).fetchone()
    if not runtime_row:
        result["enabled"] = False
        result["reason"] = "guard_not_initialized"
        return result
    try:
        runtime = json.loads(runtime_row[0])
    except (TypeError, ValueError):
        runtime = {}
    if not (
        runtime.get("enabled") is True
        and runtime.get("mode") == "observe"
        and runtime.get("chain_installed") is True
    ):
        result["enabled"] = False
        result["reason"] = "guard_not_observing"
        return result

    window = policy["window_seconds"]
    window_start = now - window
    try:
        rows = conn.execute("""
            SELECT e.src,
                   COUNT(*) AS sample_count,
                   COUNT(DISTINCT e.public_port) AS unique_public_ports,
                   MIN(e.ts) AS first_seen,
                   MAX(e.ts) AS last_seen,
                   GROUP_CONCAT(DISTINCT e.public_port) AS public_ports
            FROM guard_events e
            JOIN guard_services s ON s.service_id=e.service_id
            WHERE e.ts>=? AND e.ts<=?
              AND s.runtime_active=1 AND s.conflict=0
            GROUP BY e.src
            HAVING COUNT(DISTINCT e.public_port)>=? AND COUNT(*)>=?
            ORDER BY unique_public_ports DESC,sample_count DESC,e.src
            LIMIT ?
        """, (
            window_start, now,
            policy["min_distinct_public_ports"], policy["min_samples"],
            max(1, min(1000, int(candidate_limit)))
        )).fetchall()

        result["candidates"] = len(rows)
        for row in rows:
            src, samples, unique_ports, first_seen, last_seen, raw_ports = row
            ports = sorted({
                int(value) for value in str(raw_ports or "").split(",")
                if value.isdigit() and 1 <= int(value) <= 65535
            })
            if len(ports) < policy["min_distinct_public_ports"]:
                continue

            alert_id = hashlib.sha256(
                (RULE_ID + "\0" + str(src)).encode("utf-8")
            ).hexdigest()[:32]
            ports_json = json.dumps(ports, separators=(",", ":"))
            existing = conn.execute("""
                SELECT created_at,last_alert_at,first_seen,occurrence_count
                FROM guard_alerts WHERE alert_id=?
            """, (alert_id,)).fetchone()

            if existing is None:
                conn.execute("""
                    INSERT INTO guard_alerts(
                        alert_id,rule_id,severity,src,created_at,first_seen,
                        last_seen,last_alert_at,window_start,window_seconds,
                        sample_count,unique_public_ports,public_ports,
                        occurrence_count
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    alert_id, RULE_ID, "notice", str(src), now,
                    int(first_seen), int(last_seen), now, window_start, window,
                    int(samples), len(ports), ports_json, 1
                ))
                result["created"] += 1
                continue

            created_at, last_alert_at, original_first_seen, occurrences = existing
            re_alert = now - int(last_alert_at) >= policy["cooldown_seconds"]
            next_occurrences = int(occurrences or 1) + (1 if re_alert else 0)
            next_alert_at = now if re_alert else int(last_alert_at)
            conn.execute("""
                UPDATE guard_alerts SET
                    last_seen=?,last_alert_at=?,window_start=?,window_seconds=?,
                    sample_count=?,unique_public_ports=?,public_ports=?,
                    occurrence_count=?
                WHERE alert_id=?
            """, (
                int(last_seen), next_alert_at, window_start, window,
                int(samples), len(ports), ports_json, next_occurrences, alert_id
            ))
            result["updated"] += 1
            if re_alert:
                result["re_alerted"] += 1

        retention = policy["retention_days"] * 86400
        conn.execute(
            "DELETE FROM guard_alerts WHERE last_seen < ?",
            (now - retention,)
        )
        conn.execute("""
            DELETE FROM guard_alerts
            WHERE alert_id IN (
                SELECT alert_id FROM guard_alerts
                ORDER BY last_seen DESC,alert_id
                LIMIT -1 OFFSET ?
            )
        """, (policy["max_alerts"],))
    except Exception as exc:
        result["error"] = str(exc)[:160]
    return result
