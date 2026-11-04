#!/usr/bin/env python3
"""GeoWAN read-only telemetry, sampled event audit and expiring-set recovery.

Does not edit existing firewall rules, DNAT, GeoIP databases or router services.
Python 3 standard library + sqlite3 only.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import tempfile
import time

from geowan_geoip import GEOIP_DIR, GeoIPResolver, read_metadata
from geowan_guard import (
    ensure_guard_schema, refresh_guard, insert_guard_log_samples,
    enrich_guard_sources
)
from geowan_alerts import evaluate_guard_alerts

DB = Path(os.environ.get("GEOWAN_DB", "/etc/geowan-console/telemetry.sqlite3"))
STATUS = Path(os.environ.get("GEOWAN_STATUS", "/tmp/geowan-console/status.json"))
MAX_TTL = 7 * 86400
COLLECT_LOCK = Path("/tmp/geowan-console.collect.lock")
MONITOR_INTERVAL = 5
INVENTORY_INTERVAL = 15
LOG_SCAN_INTERVAL = 15
LOG_MARKER = re.compile(r"\bGEOWAN([46])\b")
FIELD = re.compile(r"\b(SRC|DST|DPT|PROTO|SPT)=([^\s]+)")
SYSLOG_TIME = re.compile(r"^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)")
SERVICE_PORTS = {31080: "JumpServer 反代", 20443: "SSL VPN", 3389: "RDP 后端", 58964: "RDP 公网"}


def cmd(*args, input_text=None):
    return subprocess.run(
        list(args), input=input_text, text=True, capture_output=True,
        timeout=40, check=True
    ).stdout


def db_open():
    DB.parent.mkdir(parents=True, exist_ok=True)
    DB.parent.chmod(0o700)
    conn = sqlite3.connect(str(DB), timeout=20)
    # The database contains source IPs and firewall event metadata.
    os.chmod(DB, 0o600)
    conn.execute("PRAGMA busy_timeout=20000")
    conn.execute("""CREATE TABLE IF NOT EXISTS events(
        id TEXT PRIMARY KEY, ts INTEGER NOT NULL, family INTEGER NOT NULL,
        src TEXT NOT NULL, dst TEXT, port INTEGER, proto TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS bans(
        ip TEXT PRIMARY KEY, family INTEGER NOT NULL,
        first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS geoip_cache(
        ip TEXT PRIMARY KEY, country_code TEXT NOT NULL DEFAULT '',
        country_name TEXT NOT NULL DEFAULT '', continent_code TEXT NOT NULL DEFAULT '',
        continent_name TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '',
        city TEXT NOT NULL DEFAULT '', asn INTEGER, asn_org TEXT NOT NULL DEFAULT '',
        provider TEXT NOT NULL DEFAULT '', database_version TEXT NOT NULL DEFAULT '',
        lookup_status TEXT NOT NULL, updated_at INTEGER NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_bans_last_seen ON bans(last_seen DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ts ON events(src,ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_port_ts ON events(port,ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_geoip_country ON geoip_cache(country_code)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_geoip_asn ON geoip_cache(asn)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_geoip_updated ON geoip_cache(updated_at)")
    conn.commit()
    ensure_guard_schema(conn)
    return conn


def parse_member(entry, family):
    """nft JSON versions encode elements as strings or {'elem': {'val':...}}."""
    obj = entry.get("elem", entry) if isinstance(entry, dict) else entry
    if isinstance(obj, dict):
        raw = obj.get("val", obj.get("addr"))
        expires = obj.get("expires")
    else:
        raw, expires = obj, None
    if isinstance(raw, dict):
        raw = raw.get("prefix", raw.get("val"))
    try:
        ip = ipaddress.ip_address(raw)
        if ip.version != family or ip.is_multicast or ip.is_unspecified:
            return None
    except (ValueError, TypeError):
        return None
    seconds = MAX_TTL
    if isinstance(expires, (int, float)):
        # libnftables JSON reports timeout/expires in seconds.
        seconds = min(MAX_TTL, max(1, int(expires)))
    return str(ip), seconds


def read_members(family):
    name = f"geo_black{family}"
    data = json.loads(cmd("nft", "-j", "list", "set", "inet", "fw4", name))
    for row in data.get("nftables", []):
        item = row.get("set", {})
        if item.get("name") == name:
            result = {}
            for entry in item.get("elem", []):
                parsed = parse_member(entry, family)
                if parsed:
                    result[parsed[0]] = parsed[1]
            return result
    raise RuntimeError(f"{name} missing in nft output")


def log_ts(line, now):
    found = SYSLOG_TIME.match(line)
    if not found:
        return now
    try:
        t = dt.datetime.strptime(f"{dt.datetime.fromtimestamp(now).year} {found.group(1)}",
                                 "%Y %b %d %H:%M:%S")
        stamp = int(t.timestamp())
        if stamp > now + 86400:
            stamp = int(t.replace(year=t.year - 1).timestamp())
        return stamp
    except ValueError:
        return now


def parse_log(line, now, boot):
    match = LOG_MARKER.search(line)
    if not match:
        return None
    family = int(match.group(1))
    fields = dict(FIELD.findall(line))
    try:
        ip = ipaddress.ip_address(fields.get("SRC", ""))
        if ip.version != family:
            return None
    except ValueError:
        return None
    dst = fields.get("DST", "")
    try:
        dst = str(ipaddress.ip_address(dst)) if dst else ""
    except ValueError:
        dst = ""
    try:
        port = int(fields["DPT"])
        if not (1 <= port <= 65535):
            port = None
    except (KeyError, ValueError):
        port = None
    proto = fields.get("PROTO", "")[:12].upper()
    if not re.fullmatch(r"[A-Z0-9]{1,12}", proto):
        proto = ""
    digest = hashlib.sha256((boot + "\0" + line).encode()).hexdigest()
    return digest, log_ts(line, now), family, str(ip), dst, port, proto


def read_log():
    try:
        return cmd("logread").splitlines()
    except (OSError, subprocess.CalledProcessError):
        return []


def read_counters():
    result = {"black4": 0, "black6": 0, "geo4": 0, "geo6": 0}
    try:
        output = cmd("nft", "list", "chain", "inet", "fw4", "geo_filter")
    except (OSError, subprocess.CalledProcessError):
        return result
    for family in (4, 6):
        src = "ip saddr" if family == 4 else "ip6 saddr"
        expressions = [
            (f"{src} @geo_black{family}", f"black{family}"),
            (f"{src} != @geo_cn{family}", f"geo{family}"),
        ]
        for expression, key in expressions:
            for line in output.splitlines():
                if expression in line and "counter packets" in line and "drop" in line:
                    found = re.search(r"counter packets (\d+)", line)
                    if found:
                        result[key] = int(found.group(1))
    return result


def boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "unknown-boot"


def snapshot(conn, now):
    sizes = {}
    errors = []
    for family in (4, 6):
        try:
            members = read_members(family)
            sizes[str(family)] = len(members)
            for ip, ttl in members.items():
                conn.execute("""INSERT INTO bans(ip,family,first_seen,last_seen,expires_at)
                    VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                    last_seen=excluded.last_seen,expires_at=excluded.expires_at""",
                    (ip, family, now, now, now + ttl))
        except (OSError, subprocess.CalledProcessError, ValueError, RuntimeError) as exc:
            errors.append(f"IPv{family}: {exc}")
            sizes[str(family)] = None
    conn.execute("DELETE FROM bans WHERE expires_at <= ?", (now,))
    return sizes, errors



def snapshot_incremental(conn, now):
    """Inventory live nft sets but only write new or meaningfully refreshed rows.

    nft JSON expiry values count down. Comparing now+TTL avoids rewriting every
    row merely because the same TTL lost a few seconds between polls.
    """
    sizes = {}
    errors = []
    for family in (4, 6):
        try:
            members = read_members(family)
            sizes[str(family)] = len(members)
            previous = dict(conn.execute(
                "SELECT ip,expires_at FROM bans WHERE family=?", (family,)
            ))
            for ip, ttl in members.items():
                expiry = now + min(MAX_TTL, max(1, int(ttl)))
                old_expiry = previous.get(ip)
                if old_expiry is None:
                    conn.execute(
                        "INSERT INTO bans(ip,family,first_seen,last_seen,expires_at) "
                        "VALUES(?,?,?,?,?)",
                        (ip, family, now, now, expiry)
                    )
                elif abs(expiry - old_expiry) >= 60:
                    conn.execute(
                        "UPDATE bans SET last_seen=?,expires_at=? WHERE ip=?",
                        (now, expiry, ip)
                    )
        except (OSError, subprocess.CalledProcessError, ValueError, RuntimeError) as exc:
            errors.append(f"IPv{family}: {exc}")
            sizes[str(family)] = None
    conn.execute("DELETE FROM bans WHERE expires_at <= ?", (now,))
    return sizes, errors


def insert_log_samples(conn, now):
    boot = boot_id()
    inserted = 0
    for line in read_log():
        row = parse_log(line, now, boot)
        if row:
            cur = conn.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?)", row)
            inserted += max(0, cur.rowcount)
    conn.execute("DELETE FROM events WHERE ts < ?", (now - 30 * 86400,))
    return inserted


def publish_status(status):
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".status-", dir=str(STATUS.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(status, f, ensure_ascii=False, separators=(",", ":"))
        os.chmod(name, 0o600)
        os.replace(name, STATUS)
    finally:
        if os.path.exists(name):
            os.unlink(name)





def cleanup_geoip_cache(conn, now):
    """Retain inactive GeoIP cache rows for 90 days."""
    conn.execute(
        "DELETE FROM geoip_cache WHERE ip IN ("
        "SELECT ip FROM geoip_cache WHERE updated_at < ? LIMIT 1000)",
        (int(now) - 90 * 86400,)
    )

def enrich_pending(conn, resolver, now=None, limit=250):
    """Resolve a bounded batch of active bans; no network API calls are made."""
    if resolver is None or not resolver.available:
        return 0
    now = int(time.time()) if now is None else int(now)
    version = resolver.version
    rows = conn.execute(
        "SELECT b.ip FROM bans b LEFT JOIN geoip_cache g ON g.ip=b.ip "
        "WHERE b.expires_at>? AND (g.ip IS NULL OR g.database_version<>?) "
        "ORDER BY b.first_seen,b.ip LIMIT ?",
        (now, version, max(1, int(limit)))
    ).fetchall()
    saved = 0
    for (ip,) in rows:
        item = resolver.lookup(ip)
        conn.execute(
            """INSERT INTO geoip_cache(
                ip,country_code,country_name,continent_code,continent_name,
                region,city,asn,asn_org,provider,database_version,
                lookup_status,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                country_code=excluded.country_code,
                country_name=excluded.country_name,
                continent_code=excluded.continent_code,
                continent_name=excluded.continent_name,
                region=excluded.region,city=excluded.city,asn=excluded.asn,
                asn_org=excluded.asn_org,provider=excluded.provider,
                database_version=excluded.database_version,
                lookup_status=excluded.lookup_status,updated_at=excluded.updated_at""",
            (
                ip, item.get("country_code", ""), item.get("country_name", ""),
                item.get("continent_code", ""), item.get("continent_name", ""),
                item.get("region", ""), item.get("city", ""), item.get("asn"),
                item.get("asn_org", ""), item.get("provider", ""),
                item.get("database_version", version),
                item.get("lookup_status", "not_found"), now
            )
        )
        saved += 1
    return saved


def geoip_summary(conn, now):
    metadata = read_metadata()
    version = str(metadata.get("release") or "unknown")
    provider = str(metadata.get("provider") or "DB-IP Lite")
    files_present = all(
        (GEOIP_DIR / filename).is_file()
        for filename in ("country.mmdb", "city.mmdb", "asn.mmdb")
    )
    try:
        import maxminddb  # noqa: F401
        reader_available = True
    except ImportError:
        reader_available = False
    active = conn.execute(
        "SELECT COUNT(*) FROM bans WHERE expires_at>?", (now,)
    ).fetchone()[0]
    resolved = conn.execute(
        "SELECT COUNT(*) FROM bans b JOIN geoip_cache g ON g.ip=b.ip "
        "WHERE b.expires_at>? AND g.database_version=? "
        "AND g.lookup_status='ok'", (now, version)
    ).fetchone()[0]
    pending = conn.execute(
        "SELECT COUNT(*) FROM bans b LEFT JOIN geoip_cache g ON g.ip=b.ip "
        "WHERE b.expires_at>? AND (g.ip IS NULL OR g.database_version<>?)",
        (now, version)
    ).fetchone()[0]
    countries = [{"code": code, "country": name, "ips": count} for code, name, count
                 in conn.execute(
        "SELECT g.country_code,g.country_name,COUNT(*) FROM bans b "
        "JOIN geoip_cache g ON g.ip=b.ip WHERE b.expires_at>? "
        "AND g.database_version=? AND g.lookup_status='ok' "
        "AND g.country_code<>'' GROUP BY g.country_code,g.country_name "
        "ORDER BY COUNT(*) DESC LIMIT 20", (now, version))]
    asns = [{"asn": asn, "organization": org, "ips": count} for asn, org, count
            in conn.execute(
        "SELECT g.asn,g.asn_org,COUNT(*) FROM bans b JOIN geoip_cache g ON g.ip=b.ip "
        "WHERE b.expires_at>? AND g.database_version=? AND g.lookup_status='ok' "
        "AND g.asn IS NOT NULL GROUP BY g.asn,g.asn_org "
        "ORDER BY COUNT(*) DESC LIMIT 20", (now, version))]
    return {
        "enabled": bool(files_present and reader_available),
        "files_present": bool(files_present),
        "reader_available": reader_available,
        "provider": provider,
        "database_version": version,
        "attribution_url": "https://db-ip.com",
        "active_bans": active,
        "resolved_active_bans": resolved,
        "pending_active_bans": pending,
        "top_countries": countries,
        "top_asns": asns
    }


def lookup_ip(value):
    resolver = GeoIPResolver()
    try:
        print(json.dumps(resolver.lookup(value), ensure_ascii=False, indent=2))
        if not resolver.available:
            raise SystemExit(2)
    finally:
        resolver.close()


def monitor_cycle(state, conn):
    """Collect telemetry and refresh only the isolated log/counter Guard chain.

    Existing GeoWAN verdict rules, blacklist sets and DNAT mappings are untouched.
    """
    try:
        COLLECT_LOCK.mkdir(mode=0o700)
    except FileExistsError:
        return False

    try:
        now = int(time.time())
        mono = time.monotonic()
        if state["last_inventory"] == 0 or mono - state["last_inventory_mono"] >= INVENTORY_INTERVAL:
            sizes, errors = snapshot_incremental(conn, now)
            state["sizes"] = sizes
            state["errors"] = errors
            state["guard_runtime"] = refresh_guard(conn, now)
            state["last_inventory"] = now
            state["last_inventory_mono"] = mono
        if state["last_log_mono"] == 0 or mono - state["last_log_mono"] >= LOG_SCAN_INTERVAL:
            insert_log_samples(conn, now)
            state["guard_samples_inserted"] = insert_guard_log_samples(conn, now, boot=boot_id())
            resolver = state.get("geoip_resolver")
            if resolver and resolver.available:
                state["guard_geoip_enriched"] = enrich_guard_sources(
                    conn, resolver, now, limit=100
                )
            state["last_log_mono"] = mono
            state["guard_alert_summary"] = evaluate_guard_alerts(conn, now)
        resolver = state.get("geoip_resolver")
        if resolver and resolver.available and mono - state["last_geoip_mono"] >= 15:
            state["geoip_enriched"] = enrich_pending(conn, resolver, now, limit=250)
            state["last_geoip_mono"] = mono
        if mono - state["last_geoip_cleanup_mono"] >= 3600:
            cleanup_geoip_cache(conn, now)
            state["last_geoip_cleanup_mono"] = mono
        conn.commit()
        status = build_status(conn, now, state["sizes"], state["errors"])
        status["collector"] = {
            "mode": "fast",
            "counter_interval_seconds": MONITOR_INTERVAL,
            "inventory_interval_seconds": INVENTORY_INTERVAL,
            "log_scan_interval_seconds": LOG_SCAN_INTERVAL,
            "last_inventory": state["last_inventory"]
        }
        status["guard"] = state.get("guard_runtime", {})
        status["guard_samples_inserted_last_cycle"] = state.get("guard_samples_inserted", 0)
        status["guard_alerts"] = state.get("guard_alert_summary", {})
        publish_status(status)
        return True
    finally:
        try:
            COLLECT_LOCK.rmdir()
        except OSError:
            pass


def monitor():
    """Supervised fast monitor loop; procd restarts it if it exits."""
    state = {
        "sizes": {"4": None, "6": None},
        "errors": [],
        "last_inventory": 0,
        "last_inventory_mono": 0.0,
        "last_log_mono": 0.0,
        "last_geoip_mono": 0.0,
        "last_geoip_cleanup_mono": 0.0,
        "geoip_enriched": 0,
        "guard_runtime": {},
        "guard_samples_inserted": 0,
        "guard_geoip_enriched": 0,
        "guard_alert_summary": {},
        "geoip_resolver": GeoIPResolver()
    }
    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    conn = db_open()
    print("GeoWAN fast monitor started: counters=5s, inventory=15s, logs=15s", flush=True)
    try:
        while not stopping:
            started = time.monotonic()
            try:
                monitor_cycle(state, conn)
            except Exception as exc:
                print(f"GeoWAN monitor cycle failed: {exc}", flush=True)
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
            delay = max(0.0, MONITOR_INTERVAL - (time.monotonic() - started))
            if not stopping:
                time.sleep(delay)
    finally:
        conn.close()
        state["geoip_resolver"].close()
    print("GeoWAN fast monitor stopped", flush=True)


def collect():
    now = int(time.time())
    conn = db_open()
    resolver = GeoIPResolver()
    with conn:
        sizes, errors = snapshot(conn, now)
        insert_log_samples(conn, now)
        enrich_pending(conn, resolver, now, limit=250)
        guard_runtime = refresh_guard(conn, now)
        guard_samples = insert_guard_log_samples(conn, now, boot_id())
        enrich_guard_sources(conn, resolver, now, limit=100)
        guard_alert_summary = evaluate_guard_alerts(conn, now)
        cleanup_geoip_cache(conn, now)
    status = build_status(conn, now, sizes, errors)
    status["guard"] = guard_runtime
    status["guard_samples_inserted_last_cycle"] = guard_samples
    status["guard_alerts"] = guard_alert_summary
    resolver.close()
    status["collector"] = {
        "mode": "reconcile",
        "counter_interval_seconds": None,
        "inventory_interval_seconds": 300,
        "log_scan_interval_seconds": 300,
        "last_inventory": now
    }
    conn.close()
    publish_status(status)
    print(f"GeoWAN collect: {status['active_bans']} active records, "
          f"{status['samples_24h']} sampled events, errors={len(errors)}")


def build_status(conn, now, sizes, errors):
    since = now - 86400
    geo = geoip_summary(conn, now)
    geo_version = geo["database_version"]
    total = conn.execute("SELECT COUNT(*) FROM events WHERE ts>=?", (since,)).fetchone()[0]
    active = conn.execute("SELECT COUNT(*) FROM bans WHERE expires_at>?", (now,)).fetchone()[0]
    top_ip = [{"ip": ip, "count": cnt, "country_code": cc,
                "country": country, "city": city, "asn": asn,
                "asn_org": org} for ip, cnt, cc, country, city, asn, org in conn.execute(
        "SELECT e.src,COUNT(*) n,g.country_code,g.country_name,g.city,g.asn,g.asn_org "
        "FROM events e LEFT JOIN geoip_cache g ON g.ip=e.src AND g.database_version=? WHERE e.ts>=? "
        "GROUP BY e.src,g.country_code,g.country_name,g.city,g.asn,g.asn_org "
        "ORDER BY n DESC LIMIT 12", (geo_version, since))]
    top_port = [{"port": port, "service": SERVICE_PORTS.get(port, "其他端口"),
                 "count": cnt} for port, cnt in conn.execute(
        "SELECT port,COUNT(*) n FROM events WHERE ts>=? AND port IS NOT NULL "
        "GROUP BY port ORDER BY n DESC LIMIT 12", (since,))]
    events = [{"time": ts, "src": src, "dst": dst, "port": port, "proto": proto,
               "country_code": cc, "country": country, "city": city,
               "asn": asn, "asn_org": org}
              for ts, src, dst, port, proto, cc, country, city, asn, org in conn.execute(
        "SELECT e.ts,e.src,e.dst,e.port,e.proto,g.country_code,g.country_name,"
        "g.city,g.asn,g.asn_org FROM events e LEFT JOIN geoip_cache g "
        "ON g.ip=e.src AND g.database_version=? ORDER BY e.ts DESC LIMIT 80",
        (geo_version,))]
    banned = [{"ip": ip, "family": fam, "expires": expiry,
               "country_code": cc, "country": country, "region": region,
               "city": city, "asn": asn, "asn_org": org}
              for ip, fam, expiry, cc, country, region, city, asn, org in
              conn.execute(
        "SELECT b.ip,b.family,b.expires_at,g.country_code,g.country_name,"
        "g.region,g.city,g.asn,g.asn_org FROM bans b "
        "LEFT JOIN geoip_cache g ON g.ip=b.ip AND g.database_version=? "
        "WHERE b.expires_at>? ORDER BY b.last_seen DESC LIMIT 120",
        (geo_version, now))]
    bucket_start = now - now % 3600 - 23 * 3600
    buckets = dict(conn.execute(
        "SELECT (ts/3600)*3600, COUNT(*) FROM events WHERE ts >= ? GROUP BY (ts/3600)",
        (bucket_start,)))
    return {
        "version": "0.6.0", "updated": now, "status": "degraded" if errors else "ok",
        "errors": errors, "set_sizes": sizes, "counters": read_counters(),
        "active_bans": active, "samples_24h": total, "top_sources": top_ip,
        "top_ports": top_port, "events": events, "blacklist": banned,
        "top_countries": geo["top_countries"], "top_asns": geo["top_asns"],
        "geoip": geo,
        "hours": [{"time": ts, "count": buckets.get(ts, 0)}
                  for ts in range(bucket_start, bucket_start + 24 * 3600, 3600)],
        "disclaimer": "事件和来源排行来自内核限速日志样本；国家/ASN 排行按活跃封禁 IP 去重；GeoIP 归属仅代表网络注册信息，不代表人员真实位置。"
    }


def restore():
    now = int(time.time())
    conn = db_open()
    restored = 0
    for family in (4, 6):
        try:
            current = read_members(family)
        except (OSError, subprocess.CalledProcessError, ValueError, RuntimeError) as exc:
            print(f"Skip IPv{family}: {exc}")
            continue
        rows = conn.execute(
            "SELECT ip,expires_at FROM bans WHERE family=? AND expires_at>?",
            (family, now)).fetchall()
        pending = []
        for ip, expiry in rows:
            if ip not in current:
                ttl = min(MAX_TTL, max(1, expiry - now))
                pending.append(f"{ip} timeout {ttl}s")
        for start in range(0, len(pending), 64):
            members = ", ".join(pending[start:start + 64])
            try:
                cmd("nft", "add", "element", "inet", "fw4", f"geo_black{family}",
                    "{ " + members + " }")
                restored += len(pending[start:start + 64])
            except (OSError, subprocess.CalledProcessError) as exc:
                print(f"Restore IPv{family} batch failed: {exc}")
    conn.close()
    print(f"GeoWAN restored {restored} expiring IP entries")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("collect", "restore", "monitor", "lookup"))
    parser.add_argument("ip", nargs="?")
    args = parser.parse_args()
    if args.action == "lookup":
        if not args.ip:
            parser.error("lookup requires an IP address")
        lookup_ip(args.ip)
        return
    if args.action == "collect":
        collect()
    elif args.action == "restore":
        restore()
    else:
        monitor()


if __name__ == "__main__":
    main()
