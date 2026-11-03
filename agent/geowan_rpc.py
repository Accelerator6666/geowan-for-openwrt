"""Read-only rpcd APIs for GeoWAN IP lookup and blacklist inventory."""
import ipaddress
import re
import sqlite3
import time
from pathlib import Path

from geowan_geoip import GeoIPResolver, read_metadata
from geowan_profile import source_profile, asn_profile, correlations
from geowan_guard import guard_overview

DB = Path("/etc/geowan-console/telemetry.sqlite3")
SORTS = {
    "last_seen": "b.last_seen DESC, b.ip ASC",
    "first_seen": "b.first_seen DESC, b.ip ASC",
    "expires_at": "b.expires_at ASC, b.ip ASC",
    "ip": "b.ip ASC",
}
PROTOS = {"TCP", "UDP", "ICMP", "ICMPV6", "GRE", "ESP"}

ANALYTICS_PERIODS = {
    "1h": {"seconds": 3600, "bucket": 300, "count": 12, "label": "最近 1 小时"},
    "24h": {"seconds": 86400, "bucket": 3600, "count": 24, "label": "最近 24 小时"},
    "7d": {"seconds": 7 * 86400, "bucket": 86400, "count": 7, "label": "最近 7 天"},
    "30d": {"seconds": 30 * 86400, "bucket": 86400, "count": 30, "label": "最近 30 天"},
}


def _open_readonly(db_path):
    conn = sqlite3.connect(
        "file:" + str(db_path) + "?mode=ro", uri=True, timeout=2
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=2000")
    return conn


def _optional_int(request, key, minimum, maximum):
    value = request.get(key)
    if isinstance(value, bool):
        raise ValueError(key)
    if value is None or value == "" or value == 0 or value == "0":
        return None
    if not isinstance(value, int):
        raise ValueError(key)
    if value < minimum or value > maximum:
        raise ValueError(key)
    return value


def _page_int(request, key, default, minimum, maximum):
    value = request.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(key)
    if value < minimum or value > maximum:
        raise ValueError(key)
    return value


def _filters(request):
    if not isinstance(request, dict):
        raise ValueError("request")

    page = _page_int(request, "page", 1, 1, 100000)
    page_size = _page_int(request, "page_size", 50, 20, 100)
    if page_size not in (20, 50, 100):
        raise ValueError("page_size")

    family = _optional_int(request, "family", 4, 6)
    if family not in (None, 4, 6):
        raise ValueError("family")
    query = request.get("query", "")
    if not isinstance(query, str) or len(query) > 96 or "\x00" in query:
        raise ValueError("query")
    query = query.strip()

    country = request.get("country_code", "")
    if not isinstance(country, str) or len(country) > 3:
        raise ValueError("country_code")
    country = country.strip().upper()
    if country and not re.fullmatch(r"[A-Z]{2,3}", country):
        raise ValueError("country_code")

    asn = _optional_int(request, "asn", 1, 4294967295)
    port = _optional_int(request, "port", 1, 65535)

    proto = request.get("proto", "")
    if not isinstance(proto, str) or len(proto) > 12:
        raise ValueError("proto")
    proto = proto.strip().upper()
    if proto and proto not in PROTOS:
        raise ValueError("proto")

    sort = request.get("sort", "last_seen")
    if not isinstance(sort, str) or sort not in SORTS:
        raise ValueError("sort")

    return {
        "page": page, "page_size": page_size, "query": query,
        "family": family, "country_code": country, "asn": asn,
        "port": port, "proto": proto, "sort": sort
    }


def _where(filters, now):
    clauses = ["b.expires_at > ?"]
    params = [int(now)]

    if filters["family"] is not None:
        clauses.append("b.family = ?")
        params.append(filters["family"])

    if filters["country_code"]:
        clauses.append("g.country_code = ?")
        params.append(filters["country_code"])

    if filters["asn"] is not None:
        clauses.append("g.asn = ?")
        params.append(filters["asn"])

    if filters["query"]:
        value = filters["query"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = "%" + value + "%"
        clauses.append(
            "(b.ip LIKE ? ESCAPE '\\' OR g.country_name LIKE ? ESCAPE '\\' "
            "OR g.country_code LIKE ? ESCAPE '\\' OR g.region LIKE ? ESCAPE '\\' "
            "OR g.city LIKE ? ESCAPE '\\' OR g.asn_org LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern] * 6)

    if filters["port"] is not None or filters["proto"]:
        exists = ["e.src = b.ip"]
        if filters["port"] is not None:
            exists.append("e.port = ?")
            params.append(filters["port"])
        if filters["proto"]:
            exists.append("e.proto = ?")
            params.append(filters["proto"])
        clauses.append("EXISTS (SELECT 1 FROM events e WHERE " + " AND ".join(exists) + ")")

    return " AND ".join(clauses), params


def lookup(request, db_path=DB, resolver_factory=GeoIPResolver):
    value = request.get("ip") if isinstance(request, dict) else None
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        return {"ip": str(value or ""), "lookup_status": "invalid"}

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return {"ip": value.strip(), "lookup_status": "invalid"}

    metadata = read_metadata()
    version = str(metadata.get("release") or "unknown")
    if not address.is_global:
        return {
            "ip": str(address),
            "country_code": "",
            "country_name": "",
            "continent_code": "",
            "continent_name": "",
            "region": "",
            "city": "",
            "asn": None,
            "asn_org": "",
            "provider": str(metadata.get("provider") or "DB-IP Lite"),
            "database_version": version,
            "lookup_status": "non_global"
        }

    conn = None
    try:
        conn = _open_readonly(db_path)
        row = conn.execute(
            "SELECT country_code,country_name,continent_code,continent_name,"
            "region,city,asn,asn_org,provider,database_version,lookup_status "
            "FROM geoip_cache WHERE ip=?",
            (str(address),)
        ).fetchone()
        if row and row["database_version"] == version:
            result = dict(row)
            return {"ip": str(address), **result}
    except (OSError, sqlite3.Error):
        pass
    finally:
        if conn is not None:
            conn.close()

    resolver = resolver_factory()
    try:
        return resolver.lookup(str(address))
    finally:
        resolver.close()


def list_bans(request, db_path=DB, now=None):
    """Return a bounded, read-only page of currently active blacklist entries."""
    try:
        filters = _filters(request)
    except ValueError:
        return {"error": "invalid_parameters"}

    now = int(time.time()) if now is None else int(now)
    metadata = read_metadata()
    version = str(metadata.get("release") or "unknown")
    from_sql = (
        " FROM bans b LEFT JOIN geoip_cache g "
        "ON g.ip=b.ip AND g.database_version=?"
    )
    where_sql, where_params = _where(filters, now)
    params = [version] + where_params

    conn = None
    try:
        conn = _open_readonly(db_path)
        total = conn.execute(
            "SELECT COUNT(*)" + from_sql + " WHERE " + where_sql,
            params
        ).fetchone()[0]

        offset = (filters["page"] - 1) * filters["page_size"]
        rows = conn.execute(
            "SELECT b.ip,b.family,b.first_seen,b.last_seen,b.expires_at,"
            "g.country_code,g.country_name,g.continent_code,g.continent_name,"
            "g.region,g.city,g.asn,g.asn_org,g.provider,g.database_version,"
            "COALESCE(g.lookup_status,'pending') AS lookup_status,"
            "(SELECT COUNT(*) FROM events e WHERE e.src=b.ip) AS event_count,"
            "(SELECT MAX(e.ts) FROM events e WHERE e.src=b.ip) AS last_event"
            + from_sql + " WHERE " + where_sql
            + " ORDER BY " + SORTS[filters["sort"]] + " LIMIT ? OFFSET ?",
            params + [filters["page_size"], offset]
        ).fetchall()

        return {
            "items": [dict(row) for row in rows],
            "page": filters["page"],
            "page_size": filters["page_size"],
            "total": total,
            "pages": (total + filters["page_size"] - 1) // filters["page_size"],
            "filters": filters,
            "database_version": version
        }
    except (OSError, sqlite3.Error):
        return {"error": "database_unavailable"}
    finally:
        if conn is not None:
            conn.close()


def get_ban(request, db_path=DB, now=None):
    """Return one active blacklist record and its bounded sampled event history."""
    value = request.get("ip") if isinstance(request, dict) else None
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        return {"error": "invalid_ip"}

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return {"error": "invalid_ip"}

    now = int(time.time()) if now is None else int(now)
    metadata = read_metadata()
    version = str(metadata.get("release") or "unknown")
    conn = None
    try:
        conn = _open_readonly(db_path)
        row = conn.execute(
            "SELECT b.ip,b.family,b.first_seen,b.last_seen,b.expires_at,"
            "g.country_code,g.country_name,g.continent_code,g.continent_name,"
            "g.region,g.city,g.asn,g.asn_org,g.provider,g.database_version,"
            "COALESCE(g.lookup_status,'pending') AS lookup_status "
            "FROM bans b LEFT JOIN geoip_cache g "
            "ON g.ip=b.ip AND g.database_version=? WHERE b.ip=?",
            (version, str(address))
        ).fetchone()

        if row is None:
            return {"found": False, "ip": str(address)}

        item = dict(row)
        item["active"] = item["expires_at"] > now
        item["remaining_seconds"] = max(0, item["expires_at"] - now)
        item["event_count"] = conn.execute(
            "SELECT COUNT(*) FROM events WHERE src=?", (str(address),)
        ).fetchone()[0]
        item["events"] = [
            dict(event) for event in conn.execute(
                "SELECT ts,dst,port,proto FROM events WHERE src=? "
                "ORDER BY ts DESC LIMIT 30",
                (str(address),)
            ).fetchall()
        ]
        return {"found": True, "item": item}
    except (OSError, sqlite3.Error):
        return {"error": "database_unavailable"}
    finally:
        if conn is not None:
            conn.close()



def analytics(request, db_path=DB, now=None):
    """Return bounded, read-only sampled-event analytics for a fixed time range."""
    if not isinstance(request, dict):
        return {"error": "invalid_period"}
    period = request.get("period", "24h")
    if not isinstance(period, str) or period not in ANALYTICS_PERIODS:
        return {"error": "invalid_period"}

    config = ANALYTICS_PERIODS[period]
    now = int(time.time()) if now is None else int(now)
    since = now - config["seconds"]
    bucket = config["bucket"]
    bucket_count = config["count"]
    metadata = read_metadata()
    version = str(metadata.get("release") or "unknown")
    conn = None

    try:
        conn = _open_readonly(db_path)
        event_samples = conn.execute(
            "SELECT COUNT(*) FROM events WHERE ts>=? AND ts<=?",
            (since, now)
        ).fetchone()[0]
        unique_sources = conn.execute(
            "SELECT COUNT(DISTINCT src) FROM events WHERE ts>=? AND ts<=?",
            (since, now)
        ).fetchone()[0]
        active_bans = conn.execute(
            "SELECT COUNT(*) FROM bans WHERE expires_at>?", (now,)
        ).fetchone()[0]

        bucket_counts = dict(conn.execute(
            "SELECT CAST((ts-?)/? AS INTEGER),COUNT(*) FROM events "
            "WHERE ts>=? AND ts<=? GROUP BY CAST((ts-?)/? AS INTEGER)",
            (since, bucket, since, now, since, bucket)
        ).fetchall())
        trend = [
            {"time": since + index * bucket, "count": bucket_counts.get(index, 0)}
            for index in range(bucket_count)
        ]

        top_sources = [
            {
                "ip": row["src"], "samples": row["samples"],
                "country_code": row["country_code"] or "",
                "country": row["country_name"] or "",
                "city": row["city"] or "",
                "asn": row["asn"], "asn_org": row["asn_org"] or ""
            }
            for row in conn.execute(
                "SELECT e.src,COUNT(*) AS samples,g.country_code,g.country_name,"
                "g.city,g.asn,g.asn_org FROM events e "
                "LEFT JOIN geoip_cache g ON g.ip=e.src AND g.database_version=? "
                "WHERE e.ts>=? AND e.ts<=? "
                "GROUP BY e.src,g.country_code,g.country_name,g.city,g.asn,g.asn_org "
                "ORDER BY samples DESC,e.src ASC LIMIT 10",
                (version, since, now)
            )
        ]
        top_ports = [
            {"port": row["port"], "service": {
                31080: "JumpServer 反代", 20443: "SSL VPN",
                3389: "RDP 后端", 58964: "RDP 公网"
            }.get(row["port"], "其他端口"), "samples": row["samples"]}
            for row in conn.execute(
                "SELECT port,COUNT(*) AS samples FROM events "
                "WHERE ts>=? AND ts<=? AND port IS NOT NULL "
                "GROUP BY port ORDER BY samples DESC,port ASC LIMIT 10",
                (since, now)
            )
        ]
        top_protocols = [
            {"proto": row["proto"], "samples": row["samples"]}
            for row in conn.execute(
                "SELECT COALESCE(NULLIF(proto,''),'UNKNOWN') AS proto,"
                "COUNT(*) AS samples FROM events WHERE ts>=? AND ts<=? "
                "GROUP BY COALESCE(NULLIF(proto,''),'UNKNOWN') "
                "ORDER BY samples DESC,proto ASC LIMIT 8",
                (since, now)
            )
        ]
        top_countries = [
            {
                "code": row["country_code"], "country": row["country_name"],
                "source_ips": row["source_ips"], "samples": row["samples"]
            }
            for row in conn.execute(
                "SELECT g.country_code,g.country_name,COUNT(DISTINCT e.src) AS source_ips,"
                "COUNT(*) AS samples FROM events e "
                "JOIN geoip_cache g ON g.ip=e.src AND g.database_version=? "
                "WHERE e.ts>=? AND e.ts<=? AND g.lookup_status='ok' "
                "AND g.country_code<>'' "
                "GROUP BY g.country_code,g.country_name "
                "ORDER BY source_ips DESC,samples DESC LIMIT 10",
                (version, since, now)
            )
        ]
        top_asns = [
            {
                "asn": row["asn"], "organization": row["asn_org"],
                "source_ips": row["source_ips"], "samples": row["samples"]
            }
            for row in conn.execute(
                "SELECT g.asn,g.asn_org,COUNT(DISTINCT e.src) AS source_ips,"
                "COUNT(*) AS samples FROM events e "
                "JOIN geoip_cache g ON g.ip=e.src AND g.database_version=? "
                "WHERE e.ts>=? AND e.ts<=? AND g.lookup_status='ok' "
                "AND g.asn IS NOT NULL "
                "GROUP BY g.asn,g.asn_org "
                "ORDER BY source_ips DESC,samples DESC LIMIT 10",
                (version, since, now)
            )
        ]

        return {
            "period": period,
            "period_label": config["label"],
            "from_ts": since,
            "to_ts": now,
            "bucket_seconds": bucket,
            "event_samples": event_samples,
            "unique_sources": unique_sources,
            "active_bans": active_bans,
            "trend": trend,
            "top_sources": top_sources,
            "top_ports": top_ports,
            "top_protocols": top_protocols,
            "top_countries": top_countries,
            "top_asns": top_asns,
            "database_version": version,
            "disclaimer": "趋势、来源、端口、国家和 ASN 均基于 GEOWAN 内核日志样本；内核日志限速可能丢弃部分记录，不代表完整连接或攻击总量。"
        }
    except (OSError, sqlite3.Error):
        return {"error": "database_unavailable"}
    finally:
        if conn is not None:
            conn.close()


def dispatch(method, request):
    if method == "lookup":
        return lookup(request)
    if method == "list_bans":
        return list_bans(request)
    if method == "get_ban":
        return get_ban(request)
    if method == "analytics":
        return analytics(request)
    if method == "source_profile":
        return source_profile(request)
    if method == "asn_profile":
        return asn_profile(request)
    if method == "correlations":
        return correlations(request)
    if method == "guard_overview":
        return guard_overview(request)
    return {"error": "unknown_method"}
