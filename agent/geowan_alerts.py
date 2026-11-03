#!/usr/bin/env python3
"""Alert-only behavioral analytics for GeoWAN Sensitive Port Guard.

All detections use rate-limited kernel-log samples. This module writes only
advisory SQLite records; it never invokes nftables or changes firewall policy.
"""
import hashlib
import json
import os
from pathlib import Path

POLICY_PATH = Path(os.environ.get(
    "GEOWAN_ALERT_POLICY", "/etc/geowan-console/guard-alert-policy.json"
))
RULE_ID = "multi_port_access"
RULES = (
    "multi_port_access",
    "high_frequency_access",
    "multi_source_target",
    "active_blacklist_access",
    "asn_multi_source",
)
DEFAULT_POLICY = {
    "enabled": True,
    "window_seconds": 600,
    "min_distinct_public_ports": 3,
    "min_samples": 3,
    "cooldown_seconds": 900,
    "retention_days": 30,
    "max_alerts": 50000,
    "high_frequency_window_seconds": 120,
    "high_frequency_min_samples": 20,
    "target_concentration_window_seconds": 300,
    "target_concentration_min_sources": 8,
    "target_concentration_min_samples": 12,
    "blacklist_correlation_enabled": True,
    "blacklist_window_seconds": 600,
    "blacklist_min_samples": 2,
    "asn_correlation_window_seconds": 600,
    "asn_correlation_min_sources": 4,
    "asn_correlation_min_samples": 8,
    "max_source_details": 20,
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
    """Read local thresholds; malformed policy disables alert evaluation."""
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
    for key, bounds in {
        "window_seconds": (60, 3600),
        "min_distinct_public_ports": (2, 32),
        "min_samples": (2, 10000),
        "cooldown_seconds": (60, 86400),
        "retention_days": (1, 90),
        "max_alerts": (1000, 200000),
        "high_frequency_window_seconds": (30, 1800),
        "high_frequency_min_samples": (5, 10000),
        "target_concentration_window_seconds": (60, 3600),
        "target_concentration_min_sources": (2, 10000),
        "target_concentration_min_samples": (2, 10000),
        "blacklist_window_seconds": (60, 3600),
        "blacklist_min_samples": (1, 10000),
        "asn_correlation_window_seconds": (60, 3600),
        "asn_correlation_min_sources": (2, 10000),
        "asn_correlation_min_samples": (2, 10000),
        "max_source_details": (1, 100),
    }.items():
        policy[key] = _bounded_int(
            raw, key, DEFAULT_POLICY[key], bounds[0], bounds[1]
        )
    policy["blacklist_correlation_enabled"] = (
        raw.get("blacklist_correlation_enabled", True) is True
    )
    return policy


def _csv_values(raw):
    return [value.strip() for value in str(raw or "").split(",") if value.strip()]


def _csv_ports(raw):
    values = set()
    for value in _csv_values(raw):
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            values.add(port)
    return sorted(values)


def _source_details(raw, limit):
    values = sorted(set(_csv_values(raw)))
    return values[:limit], len(values) > limit


def _upsert_alert(
    conn, result, *, rule_id, subject_key, src, target_port,
    first_seen, last_seen, sample_count, ports, window_seconds, now,
    details, severity, risk_score, risk_factors, cooldown_seconds
):
    """Persist one stable alert identity and enforce its per-identity cooldown."""
    alert_id = hashlib.sha256(
        (rule_id + "\0" + str(subject_key)).encode("utf-8")
    ).hexdigest()[:32]
    ports = sorted(set(int(port) for port in ports if 1 <= int(port) <= 65535))
    ports_json = json.dumps(ports, separators=(",", ":"))
    details_json = json.dumps(
        details, ensure_ascii=False, separators=(",", ":")
    )
    factors_json = json.dumps(
        risk_factors, ensure_ascii=False, separators=(",", ":")
    )
    window_start = int(now) - int(window_seconds)
    existing = conn.execute("""
        SELECT first_seen,last_seen,last_alert_at,occurrence_count
        FROM guard_alerts WHERE alert_id=?
    """, (alert_id,)).fetchone()

    by_rule = result.setdefault("by_rule", {})
    counts = by_rule.setdefault(
        rule_id, {"candidates": 0, "created": 0, "updated": 0, "re_alerted": 0}
    )
    counts["candidates"] += 1
    result["candidates"] += 1

    if existing is None:
        conn.execute("""
            INSERT INTO guard_alerts(
                alert_id,rule_id,severity,src,created_at,first_seen,last_seen,
                last_alert_at,window_start,window_seconds,sample_count,
                unique_public_ports,public_ports,occurrence_count,target_port,
                details_json,risk_score,risk_factors
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            alert_id, rule_id, severity, str(src or ""), int(now),
            int(first_seen), int(last_seen), int(now), window_start,
            int(window_seconds), int(sample_count), len(ports), ports_json, 1,
            target_port, details_json, int(risk_score), factors_json
        ))
        result["created"] += 1
        counts["created"] += 1
        return

    old_first, old_last, old_alert_at, old_occurrences = existing
    re_alert = int(now) - int(old_alert_at) >= int(cooldown_seconds)
    next_alert_at = int(now) if re_alert else int(old_alert_at)
    next_occurrences = int(old_occurrences or 1) + (1 if re_alert else 0)
    conn.execute("""
        UPDATE guard_alerts SET
            severity=?,first_seen=?,last_seen=?,last_alert_at=?,
            window_start=?,window_seconds=?,sample_count=?,
            unique_public_ports=?,public_ports=?,occurrence_count=?,
            target_port=?,details_json=?,risk_score=?,risk_factors=?
        WHERE alert_id=?
    """, (
        severity, min(int(old_first), int(first_seen)),
        max(int(old_last), int(last_seen)), next_alert_at, window_start,
        int(window_seconds), int(sample_count), len(ports), ports_json,
        next_occurrences, target_port, details_json, int(risk_score),
        factors_json, alert_id
    ))
    result["updated"] += 1
    counts["updated"] += 1
    if re_alert:
        result["re_alerted"] += 1
        counts["re_alerted"] += 1


def evaluate_guard_alerts(conn, now=None, policy_path=None, candidate_limit=200):
    """Evaluate five advisory rules using only active service mappings and samples."""
    import time

    now = int(time.time()) if now is None else int(now)
    policy = read_policy(policy_path)
    result = {
        "enabled": bool(policy["enabled"]),
        "rule_id": RULE_ID,
        "rules": list(RULES),
        "candidates": 0,
        "created": 0,
        "updated": 0,
        "re_alerted": 0,
        "by_rule": {},
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

    limit = max(1, min(1000, int(candidate_limit)))
    cooldown = policy["cooldown_seconds"]
    active_from = """
        FROM guard_events e
        JOIN guard_services s ON s.service_id=e.service_id
    """
    active_where = """
        WHERE s.runtime_active=1 AND s.conflict=0
          AND e.ts>=? AND e.ts<=?
    """
    try:
        conn.execute("SAVEPOINT geowan_alert_evaluation")

        # Rule 1: one source observed on multiple published WAN ports.
        window = policy["window_seconds"]
        start = now - window
        rows = conn.execute("""
            SELECT e.src,COUNT(*) AS samples,
                   COUNT(DISTINCT e.public_port) AS port_count,
                   MIN(e.ts),MAX(e.ts),GROUP_CONCAT(DISTINCT e.public_port)
        """ + active_from + active_where + """
            GROUP BY e.src
            HAVING COUNT(DISTINCT e.public_port)>=? AND COUNT(*)>=?
            ORDER BY port_count DESC,samples DESC,e.src LIMIT ?
        """, (
            start, now, policy["min_distinct_public_ports"],
            policy["min_samples"], limit
        )).fetchall()
        for src, samples, port_count, first_seen, last_seen, raw_ports in rows:
            ports = _csv_ports(raw_ports)
            if len(ports) < policy["min_distinct_public_ports"]:
                continue
            _upsert_alert(
                conn, result, rule_id="multi_port_access",
                subject_key=src, src=src, target_port=None,
                first_seen=first_seen, last_seen=last_seen,
                sample_count=samples, ports=ports, window_seconds=window,
                now=now, details={"source_ip": src, "source_count": 1},
                severity="low", risk_score=35,
                risk_factors=["one_source_multiple_public_ports"],
                cooldown_seconds=cooldown
            )

        # Rule 2: repeated sampled attempts by one source against one service.
        window = policy["high_frequency_window_seconds"]
        start = now - window
        rows = conn.execute("""
            SELECT e.src,e.public_port,COUNT(*) AS samples,
                   COUNT(DISTINCT e.src_port) AS source_ports,
                   MIN(e.ts),MAX(e.ts),GROUP_CONCAT(DISTINCT e.src_port)
        """ + active_from + active_where + """
            GROUP BY e.src,e.public_port
            HAVING COUNT(*)>=?
            ORDER BY samples DESC,e.src,e.public_port LIMIT ?
        """, (start, now, policy["high_frequency_min_samples"], limit)).fetchall()
        for src, port, samples, source_ports, first_seen, last_seen, raw_source_ports in rows:
            _upsert_alert(
                conn, result, rule_id="high_frequency_access",
                subject_key=str(src) + "|" + str(port), src=src,
                target_port=int(port), first_seen=first_seen,
                last_seen=last_seen, sample_count=samples, ports=[port],
                window_seconds=window, now=now,
                details={
                    "source_ip": src, "public_port": int(port),
                    "distinct_source_ports": int(source_ports or 0),
                    "source_ports": _csv_values(raw_source_ports)[:10]
                },
                severity="medium", risk_score=60,
                risk_factors=["repeated_samples_same_source_same_service"],
                cooldown_seconds=cooldown
            )

        # Rule 3: many distinct sources converging on one published service.
        window = policy["target_concentration_window_seconds"]
        start = now - window
        rows = conn.execute("""
            SELECT e.public_port,COUNT(*) AS samples,
                   COUNT(DISTINCT e.src) AS source_count,
                   MIN(e.ts),MAX(e.ts),GROUP_CONCAT(DISTINCT e.src),
                   COUNT(DISTINCT g.country_code),COUNT(DISTINCT g.asn)
        """ + active_from + """
            LEFT JOIN geoip_cache g ON g.ip=e.src
        """ + active_where + """
            GROUP BY e.public_port
            HAVING COUNT(DISTINCT e.src)>=? AND COUNT(*)>=?
            ORDER BY source_count DESC,samples DESC,e.public_port LIMIT ?
        """, (
            start, now, policy["target_concentration_min_sources"],
            policy["target_concentration_min_samples"], limit
        )).fetchall()
        for port, samples, source_count, first_seen, last_seen, raw_sources, country_count, asn_count in rows:
            sources, truncated = _source_details(
                raw_sources, policy["max_source_details"]
            )
            _upsert_alert(
                conn, result, rule_id="multi_source_target",
                subject_key=str(port), src="", target_port=int(port),
                first_seen=first_seen, last_seen=last_seen,
                sample_count=samples, ports=[port], window_seconds=window,
                now=now,
                details={
                    "public_port": int(port), "source_count": int(source_count),
                    "source_ips": sources, "source_ips_truncated": truncated,
                    "country_count": int(country_count or 0),
                    "asn_count": int(asn_count or 0)
                },
                severity="low", risk_score=40,
                risk_factors=["many_distinct_sources_same_public_service"],
                cooldown_seconds=cooldown
            )

        # Rule 4: a source still present in the active GeoWAN ban inventory
        # is also observed attempting to reach a currently published service.
        if policy["blacklist_correlation_enabled"]:
            window = policy["blacklist_window_seconds"]
            start = now - window
            tables = {
                row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if "bans" in tables:
                rows = conn.execute("""
                    SELECT e.src,COUNT(*) AS samples,
                           COUNT(DISTINCT e.public_port) AS port_count,
                           MIN(e.ts),MAX(e.ts),
                           GROUP_CONCAT(DISTINCT e.public_port),
                           MAX(b.expires_at),MAX(b.family)
                    FROM guard_events e
                    JOIN guard_services s ON s.service_id=e.service_id
                    JOIN bans b ON b.ip=e.src AND b.expires_at>?
                    WHERE e.ts>=? AND e.ts<=?
                      AND s.runtime_active=1 AND s.conflict=0
                    GROUP BY e.src
                    HAVING COUNT(*)>=?
                    ORDER BY samples DESC,e.src LIMIT ?
                """, (
                    now, start, now, policy["blacklist_min_samples"], limit
                )).fetchall()
                for src, samples, port_count, first_seen, last_seen, raw_ports, ban_expiry, family in rows:
                    ports = _csv_ports(raw_ports)
                    _upsert_alert(
                        conn, result, rule_id="active_blacklist_access",
                        subject_key=src, src=src, target_port=None,
                        first_seen=first_seen, last_seen=last_seen,
                        sample_count=samples, ports=ports,
                        window_seconds=window, now=now,
                        details={
                            "source_ip": src, "active_ban_expires_at": int(ban_expiry),
                            "address_family": int(family or 0)
                        },
                        severity="high", risk_score=75,
                        risk_factors=["source_is_currently_in_active_geowan_blacklist"],
                        cooldown_seconds=cooldown
                    )

        # Rule 5: several distinct sources in one ASN show activity in the
        # same window. ASN is a grouping dimension only, never a reputation score.
        window = policy["asn_correlation_window_seconds"]
        start = now - window
        rows = conn.execute("""
            SELECT g.asn,MAX(g.asn_org),COUNT(*) AS samples,
                   COUNT(DISTINCT e.src) AS source_count,
                   COUNT(DISTINCT e.public_port) AS port_count,
                   MIN(e.ts),MAX(e.ts),
                   GROUP_CONCAT(DISTINCT e.src),
                   GROUP_CONCAT(DISTINCT e.public_port),
                   GROUP_CONCAT(DISTINCT g.country_code)
        """ + active_from + """
            JOIN geoip_cache g ON g.ip=e.src
        """ + active_where + """
            AND g.asn IS NOT NULL AND g.asn>0
            GROUP BY g.asn
            HAVING COUNT(DISTINCT e.src)>=? AND COUNT(*)>=?
            ORDER BY source_count DESC,samples DESC,g.asn LIMIT ?
        """, (
            start, now, policy["asn_correlation_min_sources"],
            policy["asn_correlation_min_samples"], limit
        )).fetchall()
        for asn, asn_org, samples, source_count, port_count, first_seen, last_seen, raw_sources, raw_ports, raw_countries in rows:
            try:
                asn = int(asn)
            except (TypeError, ValueError):
                continue
            sources, truncated = _source_details(
                raw_sources, policy["max_source_details"]
            )
            ports = _csv_ports(raw_ports)
            countries = sorted(set(_csv_values(raw_countries)))
            _upsert_alert(
                conn, result, rule_id="asn_multi_source",
                subject_key=str(asn), src="", target_port=None,
                first_seen=first_seen, last_seen=last_seen,
                sample_count=samples, ports=ports, window_seconds=window,
                now=now,
                details={
                    "asn": asn, "asn_org": str(asn_org or ""),
                    "source_count": int(source_count), "source_ips": sources,
                    "source_ips_truncated": truncated,
                    "country_codes": countries
                },
                severity="low", risk_score=30,
                risk_factors=["multiple_sources_same_asn_observed"],
                cooldown_seconds=cooldown
            )

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
        conn.execute("RELEASE SAVEPOINT geowan_alert_evaluation")
    except Exception as exc:
        try:
            conn.execute("ROLLBACK TO SAVEPOINT geowan_alert_evaluation")
            conn.execute("RELEASE SAVEPOINT geowan_alert_evaluation")
        except Exception:
            pass
        result["error"] = str(exc)[:160]
        result["created"] = 0
        result["updated"] = 0
        result["re_alerted"] = 0
        result["by_rule"] = {}
    return result
