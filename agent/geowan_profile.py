"""Read-only GeoWAN source and ASN behavioral profiles.

All observations are derived from the locally sampled GEOWAN kernel events.
This module never changes firewall state or performs network lookups.
"""
import ipaddress
import sqlite3
import time
from pathlib import Path

from geowan_geoip import read_metadata

DB = Path("/etc/geowan-console/telemetry.sqlite3")
PERIODS = {
    "1h": {"seconds": 3600, "bucket": 300, "label": "最近 1 小时"},
    "24h": {"seconds": 86400, "bucket": 3600, "label": "最近 24 小时"},
    "7d": {"seconds": 7 * 86400, "bucket": 86400, "label": "最近 7 天"},
    "30d": {"seconds": 30 * 86400, "bucket": 86400, "label": "最近 30 天"},
}
DISCLAIMER = (
    "画像、评分和关联线索仅基于本机已采集的 GEOWAN 内核日志样本；"
    "内核日志限速可能丢弃部分记录，不代表完整连接或攻击总量。"
    "GeoIP 城市信息是网络归属估算，不代表人员真实所在地。"
    "时间桶按 Unix epoch 固定边界对齐，统计窗口首尾可能只覆盖部分时间桶。"
)
SOURCE_LIMIT = 100
DISTRIBUTION_LIMIT = 20


def _open_readonly(db_path):
    conn = sqlite3.connect(
        "file:" + str(db_path) + "?mode=ro", uri=True, timeout=2
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=2000")
    return conn


def _period(request):
    if not isinstance(request, dict):
        raise ValueError("request")
    value = request.get("period", "24h")
    if not isinstance(value, str) or value not in PERIODS:
        raise ValueError("period")
    return value, PERIODS[value]


def _version():
    try:
        return str(read_metadata().get("release") or "unknown")
    except Exception:
        return "unknown"


def _score(samples, ports, targets, buckets, last_event, now):
    """Transparent local-behavior score; never a threat-intelligence verdict."""
    if samples < 3:
        return {
            "score": None,
            "level": "证据不足",
            "evidence": "当前时间范围内少于 3 条日志样本，不生成评分",
            "components": []
        }

    age = max(0, now - int(last_event or 0))
    recency = 20 if age <= 300 else 15 if age <= 3600 else (
        10 if age <= 86400 else 5 if age <= 7 * 86400 else 0
    )
    components = [
        {"key": "repeat_samples", "label": "重复样本", "points": min(25, max(0, samples - 1) * 2), "max": 25},
        {"key": "port_diversity", "label": "目标端口多样性", "points": min(20, max(0, ports - 1) * 4), "max": 20},
        {"key": "target_diversity", "label": "目标地址多样性", "points": min(15, max(0, targets - 1) * 3), "max": 15},
        {"key": "temporal_recurrence", "label": "跨时间桶重复出现", "points": min(20, max(0, buckets - 1) * 4), "max": 20},
        {"key": "recency", "label": "最近活动时间", "points": recency, "max": 20},
    ]
    score = sum(item["points"] for item in components)
    level = (
        "低观察强度" if score < 25 else
        "中等观察强度" if score < 50 else
        "较高观察强度" if score < 75 else
        "高观察强度"
    )
    return {
        "score": score,
        "level": level,
        "evidence": "仅表示本机采样行为强度，不代表恶意判定",
        "components": components
    }


def _correlation_clusters(conn, since, now, bucket, version, asn=None,
                          min_sources=3, limit=10):
    """Return bounded, epoch-aligned correlation clusters and GeoIP breakdowns."""
    clauses = ["e.ts>=?", "e.ts<=?", "e.dst IS NOT NULL"]
    join = (
        " LEFT JOIN geoip_cache g ON g.ip=e.src "
        "AND g.database_version=? AND g.lookup_status='ok' "
    )
    params = [version, since, now]
    if asn is not None:
        clauses.append("g.asn=?")
        params.append(asn)
    where = " AND ".join(clauses)

    sql = (
        "SELECT e.dst,e.port,e.proto,"
        "CAST(e.ts / ? AS INTEGER) AS bucket_index,"
        "COUNT(*) AS samples,COUNT(DISTINCT e.src) AS source_count "
        "FROM events e" + join +
        " WHERE " + where +
        " GROUP BY e.dst,e.port,e.proto,bucket_index "
        "HAVING COUNT(DISTINCT e.src)>=? "
        "ORDER BY source_count DESC,samples DESC,e.dst ASC,"
        "e.port ASC,e.proto ASC,bucket_index DESC LIMIT ?"
    )
    rows = conn.execute(
        sql, [bucket] + params + [min_sources, limit]
    ).fetchall()

    clusters = []
    for row in rows:
        bucket_index = int(row["bucket_index"])
        start = bucket_index * bucket
        cluster_where = (
            where +
            " AND e.dst=? AND e.port IS ? AND e.proto IS ? "
            "AND CAST(e.ts / ? AS INTEGER)=?"
        )
        cluster_params = params + [
            row["dst"], row["port"], row["proto"], bucket, bucket_index
        ]

        rollup = (
            "WITH source_rollup AS ("
            " SELECT e.src AS ip,COUNT(*) AS samples,"
            " MAX(NULLIF(g.country_code,'')) AS country_code,"
            " MAX(NULLIF(g.country_name,'')) AS country_name,"
            " MAX(g.asn) AS asn,"
            " MAX(NULLIF(g.asn_org,'')) AS asn_org "
            " FROM events e" + join +
            " WHERE " + cluster_where +
            " GROUP BY e.src"
            ") "
        )

        summary = conn.execute(
            rollup +
            "SELECT COUNT(*) AS total_sources,"
            "COUNT(DISTINCT country_code) AS unique_countries,"
            "COUNT(DISTINCT asn) AS unique_asns,"
            "SUM(CASE WHEN country_code IS NOT NULL THEN 1 ELSE 0 END) "
            "AS country_known_sources,"
            "SUM(CASE WHEN asn IS NOT NULL THEN 1 ELSE 0 END) "
            "AS asn_known_sources,"
            "SUM(CASE WHEN country_code IS NULL AND asn IS NULL "
            "THEN 1 ELSE 0 END) AS geoip_unresolved_sources "
            "FROM source_rollup",
            cluster_params
        ).fetchone()

        sources = conn.execute(
            rollup +
            "SELECT ip,samples,country_code,country_name,asn,asn_org "
            "FROM source_rollup "
            "ORDER BY samples DESC,ip ASC LIMIT ?",
            cluster_params + [SOURCE_LIMIT]
        ).fetchall()

        countries = conn.execute(
            rollup +
            "SELECT country_code,country_name,COUNT(*) AS source_count,"
            "SUM(samples) AS samples FROM source_rollup "
            "WHERE country_code IS NOT NULL "
            "GROUP BY country_code "
            "ORDER BY source_count DESC,country_code ASC LIMIT ?",
            cluster_params + [DISTRIBUTION_LIMIT]
        ).fetchall()

        asns = conn.execute(
            rollup +
            "SELECT asn,asn_org,COUNT(*) AS source_count,"
            "SUM(samples) AS samples FROM source_rollup "
            "WHERE asn IS NOT NULL "
            "GROUP BY asn "
            "ORDER BY source_count DESC,asn ASC LIMIT ?",
            cluster_params + [DISTRIBUTION_LIMIT]
        ).fetchall()

        source_items = [
            {
                "ip": item["ip"],
                "samples": item["samples"],
                "country_code": item["country_code"] or "",
                "country_name": item["country_name"] or "",
                "asn": item["asn"],
                "asn_org": item["asn_org"] or ""
            }
            for item in sources
        ]
        clusters.append({
            "time": start,
            "bucket_start": start,
            "bucket_end": start + bucket,
            "dst": row["dst"],
            "port": row["port"],
            "proto": row["proto"] or "UNKNOWN",
            "samples": int(row["samples"]),
            "source_count": int(row["source_count"]),
            "unique_countries": int(summary["unique_countries"] or 0),
            "unique_asns": int(summary["unique_asns"] or 0),
            "country_known_sources": int(summary["country_known_sources"] or 0),
            "asn_known_sources": int(summary["asn_known_sources"] or 0),
            "geoip_unresolved_sources": int(
                summary["geoip_unresolved_sources"] or 0
            ),
            "sources_returned": len(source_items),
            "source_limit": SOURCE_LIMIT,
            "sources_truncated": int(row["source_count"]) > len(source_items),
            "countries": [
                {
                    "country_code": item["country_code"],
                    "country_name": item["country_name"] or "",
                    "source_count": int(item["source_count"]),
                    "samples": int(item["samples"])
                }
                for item in countries
            ],
            "asns": [
                {
                    "asn": int(item["asn"]),
                    "organization": item["asn_org"] or "",
                    "source_count": int(item["source_count"]),
                    "samples": int(item["samples"])
                }
                for item in asns
            ],
            "sources": source_items
        })
    return clusters


def source_profile(request, db_path=DB, now=None):
    if not isinstance(request, dict):
        return {"error": "invalid_ip"}
    value = request.get("ip")
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        return {"error": "invalid_ip"}
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return {"error": "invalid_ip"}
    if not address.is_global:
        return {"error": "non_global_ip", "ip": str(address)}
    try:
        period, config = _period(request)
    except ValueError:
        return {"error": "invalid_period"}

    now = int(time.time()) if now is None else int(now)
    since = now - config["seconds"]
    bucket = config["bucket"]
    version = _version()
    conn = None
    try:
        conn = _open_readonly(db_path)
        row = conn.execute(
            "SELECT COUNT(*) AS samples,MIN(ts) AS first_event,"
            "MAX(ts) AS last_event,COUNT(DISTINCT dst) AS targets,"
            "COUNT(DISTINCT port) AS ports,COUNT(DISTINCT proto) AS protocols,"
            "COUNT(DISTINCT CAST(ts / ? AS INTEGER)) AS active_buckets "
            "FROM events WHERE src=? AND ts>=? AND ts<=?",
            (bucket, str(address), since, now)
        ).fetchone()
        samples = int(row["samples"] or 0)
        geo = conn.execute(
            "SELECT country_code,country_name,continent_name,region,city,"
            "asn,asn_org,provider,database_version,lookup_status "
            "FROM geoip_cache WHERE ip=? AND database_version=?",
            (str(address), version)
        ).fetchone()
        ban = conn.execute(
            "SELECT family,first_seen,last_seen,expires_at "
            "FROM bans WHERE ip=?",
            (str(address),)
        ).fetchone()

        top_ports = [
            dict(item) for item in conn.execute(
                "SELECT port,COUNT(*) AS samples FROM events "
                "WHERE src=? AND ts>=? AND ts<=? AND port IS NOT NULL "
                "GROUP BY port ORDER BY samples DESC,port ASC LIMIT 10",
                (str(address), since, now)
            ).fetchall()
        ]
        top_targets = [
            dict(item) for item in conn.execute(
                "SELECT dst,COUNT(*) AS samples FROM events "
                "WHERE src=? AND ts>=? AND ts<=? AND dst IS NOT NULL "
                "GROUP BY dst ORDER BY samples DESC,dst ASC LIMIT 10",
                (str(address), since, now)
            ).fetchall()
        ]
        top_protocols = [
            dict(item) for item in conn.execute(
                "SELECT COALESCE(NULLIF(proto,''),'UNKNOWN') AS proto,"
                "COUNT(*) AS samples FROM events "
                "WHERE src=? AND ts>=? AND ts<=? "
                "GROUP BY COALESCE(NULLIF(proto,''),'UNKNOWN') "
                "ORDER BY samples DESC,proto ASC LIMIT 8",
                (str(address), since, now)
            ).fetchall()
        ]
        events = [
            dict(item) for item in conn.execute(
                "SELECT ts,dst,port,proto FROM events "
                "WHERE src=? AND ts>=? AND ts<=? "
                "ORDER BY ts DESC LIMIT 30",
                (str(address), since, now)
            ).fetchall()
        ]

        last_event = row["last_event"]
        scoring = _score(
            samples, int(row["ports"] or 0), int(row["targets"] or 0),
            int(row["active_buckets"] or 0), last_event, now
        )
        ban_data = None
        if ban is not None:
            remaining = max(0, int(ban["expires_at"]) - now)
            ban_data = {
                "family": ban["family"],
                "first_seen": ban["first_seen"],
                "last_seen": ban["last_seen"],
                "expires_at": ban["expires_at"],
                "active": remaining > 0,
                "remaining_seconds": remaining
            }

        geo_data = dict(geo) if geo is not None else {}
        return {
            "found": bool(samples or geo or ban),
            "ip": str(address),
            "period": period,
            "period_label": config["label"],
            "from_ts": since,
            "to_ts": now,
            "bucket_seconds": bucket,
            "bucket_alignment": "UTC Unix epoch",
            "samples": samples,
            "first_event": row["first_event"],
            "last_event": last_event,
            "unique_targets": int(row["targets"] or 0),
            "unique_ports": int(row["ports"] or 0),
            "unique_protocols": int(row["protocols"] or 0),
            "active_buckets": int(row["active_buckets"] or 0),
            "geoip": geo_data,
            "ban": ban_data,
            "behavior_score": scoring,
            "top_ports": top_ports,
            "top_targets": top_targets,
            "top_protocols": top_protocols,
            "events": events,
            "disclaimer": DISCLAIMER
        }
    except (OSError, sqlite3.Error):
        return {"error": "database_unavailable"}
    finally:
        if conn is not None:
            conn.close()


def asn_profile(request, db_path=DB, now=None):
    if not isinstance(request, dict):
        return {"error": "invalid_asn"}
    value = request.get("asn")
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4294967295:
        return {"error": "invalid_asn"}
    try:
        period, config = _period(request)
    except ValueError:
        return {"error": "invalid_period"}

    now = int(time.time()) if now is None else int(now)
    since = now - config["seconds"]
    bucket = config["bucket"]
    version = _version()
    conn = None
    try:
        conn = _open_readonly(db_path)
        base = (
            " FROM events e JOIN geoip_cache g ON g.ip=e.src "
            "AND g.database_version=? AND g.asn=? AND g.lookup_status='ok' "
            "WHERE e.ts>=? AND e.ts<=? "
        )
        params = [version, value, since, now]
        summary = conn.execute(
            "SELECT MAX(g.asn_org) AS organization,COUNT(*) AS samples,"
            "COUNT(DISTINCT e.src) AS sources,COUNT(DISTINCT e.dst) AS targets,"
            "COUNT(DISTINCT e.port) AS ports,COUNT(DISTINCT e.proto) AS protocols" + base,
            params
        ).fetchone()
        active_bans = conn.execute(
            "SELECT COUNT(DISTINCT b.ip) FROM bans b JOIN geoip_cache g "
            "ON g.ip=b.ip AND g.database_version=? AND g.asn=? "
            "WHERE b.expires_at>?",
            (version, value, now)
        ).fetchone()[0]
        sources = [
            dict(item) for item in conn.execute(
                "SELECT e.src AS ip,COUNT(*) AS samples,MIN(e.ts) AS first_event,"
                "MAX(e.ts) AS last_event,g.country_name,g.country_code,g.city "
                + base +
                "GROUP BY e.src,g.country_name,g.country_code,g.city "
                "ORDER BY samples DESC,e.src ASC LIMIT 20",
                params
            ).fetchall()
        ]
        ports = [
            dict(item) for item in conn.execute(
                "SELECT e.port,COUNT(*) AS samples" + base +
                "AND e.port IS NOT NULL GROUP BY e.port "
                "ORDER BY samples DESC,e.port ASC LIMIT 10",
                params
            ).fetchall()
        ]
        targets = [
            dict(item) for item in conn.execute(
                "SELECT e.dst,COUNT(*) AS samples" + base +
                "AND e.dst IS NOT NULL GROUP BY e.dst "
                "ORDER BY samples DESC,e.dst ASC LIMIT 10",
                params
            ).fetchall()
        ]
        protocols = [
            dict(item) for item in conn.execute(
                "SELECT COALESCE(NULLIF(e.proto,''),'UNKNOWN') AS proto,"
                "COUNT(*) AS samples" + base +
                "GROUP BY COALESCE(NULLIF(e.proto,''),'UNKNOWN') "
                "ORDER BY samples DESC,proto ASC LIMIT 8",
                params
            ).fetchall()
        ]
        clusters = _correlation_clusters(
            conn, since, now, bucket, version, asn=value,
            min_sources=2, limit=10
        )
        return {
            "found": bool(summary["samples"]),
            "asn": value,
            "organization": summary["organization"] or "",
            "period": period,
            "period_label": config["label"],
            "from_ts": since,
            "to_ts": now,
            "bucket_seconds": bucket,
            "bucket_alignment": "UTC Unix epoch",
            "samples": int(summary["samples"] or 0),
            "unique_sources": int(summary["sources"] or 0),
            "unique_targets": int(summary["targets"] or 0),
            "unique_ports": int(summary["ports"] or 0),
            "unique_protocols": int(summary["protocols"] or 0),
            "active_banned_sources": int(active_bans or 0),
            "top_sources": sources,
            "top_ports": ports,
            "top_targets": targets,
            "top_protocols": protocols,
            "correlations": clusters,
            "disclaimer": DISCLAIMER
        }
    except (OSError, sqlite3.Error):
        return {"error": "database_unavailable"}
    finally:
        if conn is not None:
            conn.close()


def correlations(request, db_path=DB, now=None):
    try:
        period, config = _period(request)
    except ValueError:
        return {"error": "invalid_period"}
    now = int(time.time()) if now is None else int(now)
    since = now - config["seconds"]
    conn = None
    try:
        conn = _open_readonly(db_path)
        clusters = _correlation_clusters(
            conn, since, now, config["bucket"], _version(),
            asn=None, min_sources=3, limit=20
        )
        return {
            "period": period,
            "period_label": config["label"],
            "from_ts": since,
            "to_ts": now,
            "minimum_sources": 3,
            "bucket_seconds": config["bucket"],
            "bucket_alignment": "UTC Unix epoch",
            "clusters": clusters,
            "disclaimer": DISCLAIMER
        }
    except (OSError, sqlite3.Error):
        return {"error": "database_unavailable"}
    finally:
        if conn is not None:
            conn.close()
