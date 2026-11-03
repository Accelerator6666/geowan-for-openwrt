#!/usr/bin/env python3
"""GeoWAN Sensitive Port Guard: local DNAT inventory and observation-only telemetry.

The Guard owns one additional base chain in inet fw4. Its rules only count and
rate-limited-log new DNAT flows from the existing GeoWAN CN prefix sets. They
never accept, drop, reject, mark, or alter an existing firewall decision.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import time

DB = Path(os.environ.get("GEOWAN_DB", "/etc/geowan-console/telemetry.sqlite3"))
GUARD_CONFIG = Path(os.environ.get(
    "GEOWAN_GUARD_CONFIG", "/etc/geowan-console/guard.json"
))
GUARD_CHAIN = "geo_guard_forward"
GUARD_RETENTION = 30 * 86400
GUARD_MAX_EVENTS = 200000
GUARD_LOG_MARKER = re.compile(
    r"\bGEOWAN_GUARD([46])\|([a-f0-9]{12})\|([0-9]{1,5})\|"
)
GUARD_FIELDS = re.compile(r"\b(SRC|DST|SPT|DPT|PROTO)=([^\s]+)")
DNAT_RULE = re.compile(
    r"\bmeta nfproto\s+(ipv4|ipv6)\s+(tcp|udp)\s+dport\s+([0-9]+)\b"
    r".*?\bdnat\s+(?:ip|ip6)\s+to\s+(\[[^\]]+\](?::[0-9]+)?|[^\s]+)"
)
UCI_CONFIG = re.compile(r"^config\s+(\S+)(?:\s+(.+))?$")
IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
DEFAULT_CONFIG = {
    "enabled": False,
    "mode": "observe",
    "log_rate_per_second": 2,
    "log_burst": 10
}
PERIODS = {
    "1h": {"seconds": 3600, "bucket": 300, "count": 12, "label": "最近 1 小时"},
    "24h": {"seconds": 86400, "bucket": 3600, "count": 24, "label": "最近 24 小时"},
    "7d": {"seconds": 7 * 86400, "bucket": 86400, "count": 7, "label": "最近 7 天"},
    "30d": {"seconds": 30 * 86400, "bucket": 86400, "count": 30, "label": "最近 30 天"}
}


def run(*args, input_text=None):
    return subprocess.run(
        list(args), input=input_text, text=True, capture_output=True,
        timeout=15, check=True
    ).stdout


def read_config(path=None):
    path = Path(path or GUARD_CONFIG)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("configuration must be an object")
    except FileNotFoundError:
        raw = {}
    except (OSError, ValueError, json.JSONDecodeError):
        raw = {}
    config = dict(DEFAULT_CONFIG)
    config.update(raw)
    config["enabled"] = config.get("enabled") is True
    config["mode"] = "observe" if config.get("mode") == "observe" else "disabled"
    try:
        config["log_rate_per_second"] = min(
            20, max(1, int(config.get("log_rate_per_second", 2)))
        )
        config["log_burst"] = min(100, max(1, int(config.get("log_burst", 10))))
    except (TypeError, ValueError):
        config["log_rate_per_second"] = DEFAULT_CONFIG["log_rate_per_second"]
        config["log_burst"] = DEFAULT_CONFIG["log_burst"]
    return config


def ensure_guard_schema(conn):
    """Create Guard-only tables without changing any v0.5.x table."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS guard_services(
            service_id TEXT PRIMARY KEY,
            family INTEGER NOT NULL,
            proto TEXT NOT NULL,
            public_port INTEGER NOT NULL,
            dest_ip TEXT NOT NULL DEFAULT '',
            dest_port INTEGER NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'custom',
            category_label TEXT NOT NULL DEFAULT '自定义 / 未分类',
            runtime_active INTEGER NOT NULL DEFAULT 0,
            conflict INTEGER NOT NULL DEFAULT 0,
            config_match INTEGER NOT NULL DEFAULT 0,
            fingerprint TEXT NOT NULL DEFAULT '',
            last_seen INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_guard_services_active
            ON guard_services(runtime_active, public_port);
        CREATE TABLE IF NOT EXISTS guard_events(
            id TEXT PRIMARY KEY,
            ts INTEGER NOT NULL,
            family INTEGER NOT NULL,
            src TEXT NOT NULL,
            src_port INTEGER,
            public_port INTEGER NOT NULL,
            proto TEXT NOT NULL,
            dst TEXT NOT NULL DEFAULT '',
            dest_port INTEGER,
            service_id TEXT NOT NULL,
            capture_method TEXT NOT NULL DEFAULT 'kernel_log_sample'
        );
        CREATE INDEX IF NOT EXISTS idx_guard_events_ts
            ON guard_events(ts);
        CREATE INDEX IF NOT EXISTS idx_guard_events_src_ts
            ON guard_events(src, ts);
        CREATE INDEX IF NOT EXISTS idx_guard_events_port_ts
            ON guard_events(public_port, ts);
        CREATE INDEX IF NOT EXISTS idx_guard_events_service_ts
            ON guard_events(service_id, ts);
        CREATE TABLE IF NOT EXISTS guard_state(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
    """)
    conn.commit()


def _valid_port(value, default=None):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def _family(value, dest_ip=""):
    text = str(value or "").strip().lower()
    if text in ("4", "ipv4"):
        return 4
    if text in ("6", "ipv6"):
        return 6
    if dest_ip:
        try:
            return ipaddress.ip_address(dest_ip).version
        except ValueError:
            return 0
    return 0


def parse_uci_redirects(text):
    """Parse enabled WAN redirect sections from uci export firewall output."""
    sections = []
    current = None

    def finish():
        if current is not None and current.get("_type") == "redirect":
            sections.append(dict(current))

    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = UCI_CONFIG.match(line)
        if match:
            finish()
            try:
                tokens = shlex.split(match.group(2) or "")
            except ValueError:
                tokens = []
            current = {"_type": match.group(1), "_section": tokens[0] if tokens else ""}
            continue
        if current is None:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if len(tokens) < 3 or tokens[0] not in ("option", "list"):
            continue
        key, value = tokens[1], " ".join(tokens[2:])
        if tokens[0] == "list":
            current.setdefault("_list_" + key, []).append(value)
        else:
            current[key] = value
    finish()

    result = []
    for section in sections:
        if section.get("src", "wan") != "wan" or section.get("enabled", "1") == "0":
            continue
        public_port = _valid_port(section.get("src_dport"))
        if public_port is None:
            continue
        dest_ip = str(section.get("dest_ip", "")).strip()
        try:
            if dest_ip:
                dest_ip = str(ipaddress.ip_address(dest_ip))
        except ValueError:
            dest_ip = ""
        family = _family(section.get("family"), dest_ip)
        dest_port = _valid_port(section.get("dest_port"), public_port)
        if family not in (4, 6) or not dest_ip or dest_port is None:
            continue
        protos = section.get("_list_proto") or str(section.get("proto", "")).split()
        if not protos:
            protos = ["tcp", "udp"]
        name = str(section.get("name") or section.get("_section") or "未命名转发")
        for proto in sorted(set(str(p).lower() for p in protos)):
            if proto not in ("tcp", "udp"):
                continue
            result.append({
                "family": family, "proto": proto, "public_port": public_port,
                "dest_ip": dest_ip, "dest_port": dest_port, "name": name,
                "config_match": True, "runtime_active": False
            })
    return result


def _split_dnat_target(target, public_port):
    token = str(target or "").strip()
    if token.startswith("["):
        end = token.find("]")
        if end < 0:
            return None, None
        address = token[1:end]
        suffix = token[end + 1:]
        port = _valid_port(suffix[1:], public_port) if suffix.startswith(":") else public_port
    elif ":" in token:
        address, _, port_text = token.rpartition(":")
        port = _valid_port(port_text, public_port)
    else:
        address, port = token, public_port
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        return None, None
    return address, port


def parse_dnat_rules(text):
    """Read active runtime DNAT rules, which are authoritative for live exposure."""
    result = []
    for line in str(text or "").splitlines():
        match = DNAT_RULE.search(line)
        if not match:
            continue
        family_text, proto, port_text, target = match.groups()
        public_port = _valid_port(port_text)
        if public_port is None:
            continue
        family = 4 if family_text == "ipv4" else 6
        dest_ip, dest_port = _split_dnat_target(target, public_port)
        if not dest_ip or dest_port is None:
            continue
        try:
            if ipaddress.ip_address(dest_ip).version != family:
                continue
        except ValueError:
            continue
        comment = re.search(r'\bcomment\s+"!fw4:\s*([^"]+)"', line)
        name = comment.group(1).strip() if comment else ""
        result.append({
            "family": family, "proto": proto.lower(), "public_port": public_port,
            "dest_ip": dest_ip, "dest_port": dest_port, "name": name,
            "config_match": False, "runtime_active": True
        })
    return result


def _service_id(item):
    raw = "%s|%s|%s|%s|%s" % (
        item["family"], item["proto"], item["public_port"],
        item["dest_ip"], item["dest_port"]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _classify(name, dest_port):
    """Classify from explicit redirect/service naming; ports alone are not proof."""
    label = (name or "").lower()
    if any(word in label for word in ("rdp", "remote-desktop", "remote desktop")):
        return "management", "远程桌面 / RDP"
    if "vnc" in label:
        return "management", "远程控制 / VNC"
    if "pve" in label or "proxmox" in label:
        return "management", "虚拟化管理"
    if "pbs" in label or "proxmox-backup" in label:
        return "management", "备份管理"
    if any(word in label for word in ("dsm", "synology", "nas-admin")):
        return "management", "NAS 管理"
    if "syn" in label and dest_port in (5000, 5001, 5006):
        return "management", "NAS 管理（名称/端口候选）"
    if any(word in label for word in ("vpn", "ssl", "forti")):
        return "remote_access", "VPN / 远程接入"
    if "jump" in label:
        return "remote_access", "堡垒机 / 运维入口"
    if any(word in label for word in (
        "emby", "jellyfin", "media", "home assistant", "webdav",
        "stirling", "mumble", "usstock", "qb"
    )):
        return "application", "公网应用"
    return "custom", "自定义 / 待确认"


def build_inventory(uci_text, nft_text, now=None):
    """Merge configured redirects with live DNAT; preserve inactive config rows."""
    now = int(time.time()) if now is None else int(now)
    configured = parse_uci_redirects(uci_text)
    runtime = parse_dnat_rules(nft_text)
    config_by_key = {}
    for item in configured:
        key = (item["family"], item["proto"], item["public_port"],
               item["dest_ip"], item["dest_port"])
        config_by_key.setdefault(key, []).append(item)

    merged = {}
    for item in runtime:
        key = (item["family"], item["proto"], item["public_port"],
               item["dest_ip"], item["dest_port"])
        matches = config_by_key.get(key, [])
        names = [x["name"] for x in matches if x.get("name")]
        if item.get("name"):
            names.append(item["name"])
        row = dict(item)
        row["name"] = " / ".join(sorted(set(names))) if names else "运行时 DNAT"
        row["config_match"] = bool(matches)
        row["runtime_active"] = True
        merged[_service_id(row)] = row

    runtime_keys = {
        (x["family"], x["proto"], x["public_port"], x["dest_ip"], x["dest_port"])
        for x in runtime
    }
    for item in configured:
        key = (item["family"], item["proto"], item["public_port"],
               item["dest_ip"], item["dest_port"])
        if key in runtime_keys:
            continue
        row = dict(item)
        row["name"] = item["name"] + "（配置未生效）"
        row["runtime_active"] = False
        merged[_service_id(row)] = row

    conflicts = {}
    for item in merged.values():
        key = (item["family"], item["proto"], item["public_port"])
        conflicts.setdefault(key, set()).add((item["dest_ip"], item["dest_port"]))
    for item in merged.values():
        key = (item["family"], item["proto"], item["public_port"])
        item["conflict"] = len(conflicts.get(key, ())) > 1
        category, category_label = _classify(item["name"], item["dest_port"])
        item["category"] = category
        item["category_label"] = category_label
        item["service_id"] = _service_id(item)
        fingerprint = "%s|%s|%s|%s|%s|%s" % (
            item["family"], item["proto"], item["public_port"],
            item["dest_ip"], item["dest_port"], item["name"]
        )
        item["fingerprint"] = hashlib.sha256(fingerprint.encode()).hexdigest()
        item["updated_at"] = now
    return sorted(
        merged.values(),
        key=lambda x: (x["family"], x["public_port"], x["proto"], x["dest_ip"])
    )


def _wan_device():
    try:
        data = json.loads(run("ubus", "call", "network.interface.wan", "status"))
        value = data.get("l3_device") or data.get("device") or data.get("ifname")
        if value and IFNAME.fullmatch(str(value)):
            return str(value)
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError):
        pass
    for key in ("network.wan.device", "network.wan.ifname"):
        try:
            value = run("uci", "-q", "get", key).strip()
            if value and IFNAME.fullmatch(value):
                return value
        except (OSError, subprocess.CalledProcessError):
            pass
    return ""


def render_rules(services, wan_device, rate=2, burst=10):
    """Return log-only rules; no verdict-changing expression is generated."""
    if not IFNAME.fullmatch(str(wan_device or "")):
        raise ValueError("invalid_wan_device")
    rules = []
    for item in services:
        if not item.get("runtime_active") or item.get("conflict"):
            continue
        family = int(item["family"])
        if family not in (4, 6):
            continue
        proto = str(item["proto"]).lower()
        if proto not in ("tcp", "udp"):
            continue
        port = _valid_port(item.get("public_port"))
        if port is None:
            continue
        family_match = "meta nfproto ipv4" if family == 4 else "meta nfproto ipv6"
        marker = "GEOWAN_GUARD%d|%s|%d|" % (
            family, item["service_id"], port
        )
        marker = marker.replace('"', "")
        rules.append(
            'add rule inet fw4 %s iifname "%s" ct state new ct status dnat '
            '%s meta l4proto %s ct original proto-dst %d counter '
            'limit rate %d/second burst %d packets '
            'log prefix "%s" level info' % (
                GUARD_CHAIN, wan_device, family_match, proto, port,
                rate, burst, marker
            )
        )
    return rules


def _chain_exists(command_runner=None):
    runner = command_runner or run
    try:
        output = runner("nft", "list", "chain", "inet", "fw4", GUARD_CHAIN)
        if ("type filter" not in output or "hook forward" not in output or
                "priority -2" not in output or "policy accept" not in output):
            raise RuntimeError("guard_chain_name_conflict")
        return True
    except subprocess.CalledProcessError:
        return False


def _chain_rule_count(command_runner=None):
    runner = command_runner or run
    output = runner("nft", "list", "chain", "inet", "fw4", GUARD_CHAIN)
    return output.count("GEOWAN_GUARD")


def apply_rules(services, wan_device, config, chain_exists=None,
                command_runner=None):
    runner = command_runner or run
    exists = _chain_exists(runner) if chain_exists is None else bool(chain_exists)
    lines = []
    if exists:
        lines.append("flush chain inet fw4 %s" % GUARD_CHAIN)
    else:
        lines.append(
            "add chain inet fw4 %s { type filter hook forward priority -2; "
            "policy accept; }" % GUARD_CHAIN
        )
    lines.extend(render_rules(
        services, wan_device,
        config["log_rate_per_second"], config["log_burst"]
    ))
    script = "\n".join(lines) + "\n"
    runner("nft", "-f", "-", input_text=script)
    return len(lines) - 1


def validate_guard_rules(command_runner=None):
    """Syntax-check the proposed Guard chain without applying any nftables change."""
    runner = command_runner or run
    uci_text = runner("uci", "-q", "export", "firewall")
    nft_text = runner("nft", "-a", "list", "chain", "inet", "fw4", "dstnat_wan")
    services = build_inventory(uci_text, nft_text)
    wan = ""
    try:
        data = json.loads(runner("ubus", "call", "network.interface.wan", "status"))
        candidate = data.get("l3_device") or data.get("device") or data.get("ifname")
        if candidate and IFNAME.fullmatch(str(candidate)):
            wan = str(candidate)
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError):
        pass
    if not wan:
        for key in ("network.wan.device", "network.wan.ifname"):
            try:
                candidate = runner("uci", "-q", "get", key).strip()
                if candidate and IFNAME.fullmatch(candidate):
                    wan = candidate
                    break
            except (OSError, subprocess.CalledProcessError):
                pass
    if not wan:
        raise RuntimeError("wan_device_unavailable")

    config = read_config()
    exists = _chain_exists(runner)
    lines = []
    if exists:
        lines.append("flush chain inet fw4 %s" % GUARD_CHAIN)
    else:
        lines.append(
            "add chain inet fw4 %s { type filter hook forward priority -2; "
            "policy accept; }" % GUARD_CHAIN
        )
    rules = render_rules(
        services, wan, config["log_rate_per_second"], config["log_burst"]
    )
    lines.extend(rules)
    script = "\n".join(lines) + "\n"
    runner("nft", "-c", "-f", "-", input_text=script)
    return {
        "wan_device": wan,
        "service_count": len(services),
        "active_service_count": sum(1 for item in services if item["runtime_active"]),
        "conflict_count": sum(1 for item in services if item["conflict"]),
        "rule_count": len(rules),
        "chain_exists": exists
    }


def _save_state(conn, state, now):
    conn.execute(
        "INSERT INTO guard_state(key,value,updated_at) VALUES('runtime',?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
        (json.dumps(state, ensure_ascii=False, separators=(",", ":")), int(now))
    )


def refresh_guard(conn, now=None, config_path=None, command_runner=None):
    """Refresh local service inventory and the Guard-owned observation chain."""
    now = int(time.time()) if now is None else int(now)
    config = read_config(config_path)
    runner = command_runner or run
    try:
        uci_text = runner("uci", "-q", "export", "firewall")
        nft_text = runner("nft", "-a", "list", "chain", "inet", "fw4", "dstnat_wan")
        services = build_inventory(uci_text, nft_text, now)
        wan = ""
        try:
            data = json.loads(runner("ubus", "call", "network.interface.wan", "status"))
            candidate = data.get("l3_device") or data.get("device") or data.get("ifname")
            if candidate and IFNAME.fullmatch(str(candidate)):
                wan = str(candidate)
        except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError):
            pass
        if not wan:
            for key in ("network.wan.device", "network.wan.ifname"):
                try:
                    candidate = runner("uci", "-q", "get", key).strip()
                    if candidate and IFNAME.fullmatch(candidate):
                        wan = candidate
                        break
                except (OSError, subprocess.CalledProcessError):
                    pass
        previous_row = conn.execute(
            "SELECT value FROM guard_state WHERE key='runtime'"
        ).fetchone()
        try:
            previous_state = json.loads(previous_row[0]) if previous_row else {}
        except (TypeError, ValueError):
            previous_state = {}

        if config["enabled"] and config["mode"] == "observe":
            if not wan:
                raise RuntimeError("wan_device_unavailable")
            desired_rules = render_rules(
                services, wan, config["log_rate_per_second"], config["log_burst"]
            )
            rules_fingerprint = hashlib.sha256(
                "\n".join(desired_rules).encode("utf-8")
            ).hexdigest()
            exists = _chain_exists(runner)
            actual_rule_count = _chain_rule_count(runner) if exists else 0
            if (not exists or
                    previous_state.get("rules_fingerprint") != rules_fingerprint or
                    actual_rule_count != len(desired_rules)):
                apply_rules(
                    services, wan, config, chain_exists=exists,
                    command_runner=runner
                )
            chain_installed = True
            installed_rules = len(desired_rules)
            mode = "observe"
        else:
            exists = _chain_exists(runner)
            if exists:
                runner("nft", "delete", "chain", "inet", "fw4", GUARD_CHAIN)
            chain_installed = False
            installed_rules = 0
            rules_fingerprint = ""
            mode = "disabled"

        conn.execute("UPDATE guard_services SET runtime_active=0,conflict=0")
        for item in services:
            conn.execute("""
                INSERT INTO guard_services(
                    service_id,family,proto,public_port,dest_ip,dest_port,name,
                    category,category_label,runtime_active,conflict,config_match,
                    fingerprint,last_seen,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(service_id) DO UPDATE SET
                    family=excluded.family,proto=excluded.proto,
                    public_port=excluded.public_port,dest_ip=excluded.dest_ip,
                    dest_port=excluded.dest_port,name=excluded.name,
                    category=excluded.category,category_label=excluded.category_label,
                    runtime_active=excluded.runtime_active,conflict=excluded.conflict,
                    config_match=excluded.config_match,fingerprint=excluded.fingerprint,
                    last_seen=CASE WHEN excluded.runtime_active=1
                        THEN excluded.updated_at ELSE guard_services.last_seen END,
                    updated_at=excluded.updated_at
            """, (
                item["service_id"], item["family"], item["proto"],
                item["public_port"], item["dest_ip"], item["dest_port"],
                item["name"], item["category"], item["category_label"],
                int(item["runtime_active"]), int(item["conflict"]),
                int(item["config_match"]), item["fingerprint"],
                now if item["runtime_active"] else 0, now
            ))
        conn.execute(
            "DELETE FROM guard_services WHERE runtime_active=0 AND updated_at<?",
            (now - 90 * 86400,)
        )
        state = {
            "enabled": bool(config["enabled"] and mode == "observe"),
            "mode": mode,
            "chain_installed": chain_installed,
            "wan_device": wan,
            "service_count": len(services),
            "active_service_count": sum(1 for x in services if x["runtime_active"]),
            "conflict_count": sum(1 for x in services if x["conflict"]),
            "installed_rule_count": installed_rules,
            "rules_fingerprint": rules_fingerprint if mode == "observe" else "",
            "last_inventory": now,
            "last_error": ""
        }
        _save_state(conn, state, now)
        conn.commit()
        return state
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as exc:
        state = {
            "enabled": False,
            "mode": "degraded",
            "chain_installed": False,
            "wan_device": "",
            "service_count": 0,
            "active_service_count": 0,
            "conflict_count": 0,
            "installed_rule_count": 0,
            "rules_fingerprint": "",
            "last_inventory": now,
            "last_error": str(exc)[:240]
        }
        _save_state(conn, state, now)
        conn.commit()
        return state


def parse_guard_log(line, now=None, boot="unknown-boot"):
    match = GUARD_LOG_MARKER.search(str(line or ""))
    if not match:
        return None
    family = 4 if match.group(1) == "4" else 6
    service_id = match.group(2)
    public_port = _valid_port(match.group(3))
    fields = dict(GUARD_FIELDS.findall(str(line)))
    try:
        source = ipaddress.ip_address(fields.get("SRC", ""))
        if source.version != family or not source.is_global:
            return None
        dest = ipaddress.ip_address(fields.get("DST", ""))
    except ValueError:
        return None
    proto = str(fields.get("PROTO", "")).upper()
    if proto not in ("TCP", "UDP"):
        return None
    src_port = _valid_port(fields.get("SPT"))
    dest_port = _valid_port(fields.get("DPT"))
    if public_port is None:
        return None
    now = int(time.time()) if now is None else int(now)
    stamp = now
    time_match = re.search(
        r"^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)",
        str(line)
    )
    if time_match:
        try:
            import datetime as dt
            parsed = dt.datetime.strptime(
                "%d %s" % (dt.datetime.fromtimestamp(now).year, time_match.group(1)),
                "%Y %b %d %H:%M:%S"
            )
            stamp = int(parsed.timestamp())
            if stamp > now + 86400:
                stamp = int(parsed.replace(year=parsed.year - 1).timestamp())
        except ValueError:
            stamp = now
    event_id = hashlib.sha256(
        (str(boot) + "\0" + str(line)).encode("utf-8")
    ).hexdigest()
    return {
        "id": event_id, "ts": stamp, "family": family, "src": str(source),
        "src_port": src_port, "public_port": public_port, "proto": proto,
        "dst": str(dest), "dest_port": dest_port, "service_id": service_id,
        "capture_method": "kernel_log_sample"
    }


def insert_guard_log_samples(conn, now=None, lines=None, boot="unknown-boot",
                             command_runner=None):
    now = int(time.time()) if now is None else int(now)
    if lines is None:
        runner = command_runner or run
        try:
            lines = runner("logread").splitlines()
        except (OSError, subprocess.CalledProcessError):
            lines = []
    inserted = 0
    for line in lines:
        item = parse_guard_log(line, now, boot)
        if not item:
            continue
        cursor = conn.execute("""
            INSERT OR IGNORE INTO guard_events(
                id,ts,family,src,src_port,public_port,proto,dst,dest_port,
                service_id,capture_method
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (
            item["id"], item["ts"], item["family"], item["src"],
            item["src_port"], item["public_port"], item["proto"],
            item["dst"], item["dest_port"], item["service_id"],
            item["capture_method"]
        ))
        inserted += max(0, cursor.rowcount)
    conn.execute("DELETE FROM guard_events WHERE ts < ?", (now - GUARD_RETENTION,))
    conn.execute("""
        DELETE FROM guard_events
        WHERE id IN (
            SELECT id FROM guard_events
            ORDER BY ts DESC,id DESC LIMIT -1 OFFSET ?
        )
    """, (GUARD_MAX_EVENTS,))
    return inserted


def enrich_guard_sources(conn, resolver, now=None, limit=100):
    """Enrich a bounded set of Guard source IPs using the local MMDB only."""
    if resolver is None or not getattr(resolver, "available", False):
        return 0
    from geowan_geoip import read_metadata
    now = int(time.time()) if now is None else int(now)
    version = str((read_metadata() or {}).get("release") or resolver.version or "unknown")
    rows = conn.execute("""
        SELECT e.src,MIN(e.ts) AS first_seen
        FROM guard_events e
        LEFT JOIN geoip_cache g ON g.ip=e.src AND g.database_version=?
        WHERE e.ts>=? AND g.ip IS NULL
        GROUP BY e.src ORDER BY first_seen,e.src LIMIT ?
    """, (version, now - GUARD_RETENTION, max(1, int(limit)))).fetchall()
    saved = 0
    for row in rows:
        item = resolver.lookup(row[0])
        conn.execute("""
            INSERT INTO geoip_cache(
                ip,country_code,country_name,continent_code,continent_name,
                region,city,asn,asn_org,provider,database_version,
                lookup_status,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
                country_code=excluded.country_code,country_name=excluded.country_name,
                continent_code=excluded.continent_code,continent_name=excluded.continent_name,
                region=excluded.region,city=excluded.city,asn=excluded.asn,
                asn_org=excluded.asn_org,provider=excluded.provider,
                database_version=excluded.database_version,
                lookup_status=excluded.lookup_status,updated_at=excluded.updated_at
        """, (
            row[0], item.get("country_code", ""), item.get("country_name", ""),
            item.get("continent_code", ""), item.get("continent_name", ""),
            item.get("region", ""), item.get("city", ""), item.get("asn"),
            item.get("asn_org", ""), item.get("provider", "DB-IP Lite"),
            item.get("database_version", version),
            item.get("lookup_status", "not_found"), now
        ))
        saved += 1
    return saved


def guard_overview(request, db_path=DB, now=None, config_path=None):
    """Read-only Guard overview, optionally scoped to one original WAN port."""
    if not isinstance(request, dict):
        return {"error": "invalid_period"}
    period = request.get("period", "24h")
    if not isinstance(period, str) or period not in PERIODS:
        return {"error": "invalid_period"}
    raw_port = request.get("public_port", 0)
    if isinstance(raw_port, bool):
        return {"error": "invalid_port"}
    try:
        public_port = int(raw_port)
    except (TypeError, ValueError):
        return {"error": "invalid_port"}
    if public_port < 0 or public_port > 65535:
        return {"error": "invalid_port"}

    config = read_config(config_path)
    now = int(time.time()) if now is None else int(now)
    since = now - PERIODS[period]["seconds"]
    bucket = PERIODS[period]["bucket"]
    filter_sql = " AND e.public_port=?" if public_port else ""
    filter_params = [public_port] if public_port else []
    conn = None
    try:
        conn = sqlite3.connect(
            "file:" + str(db_path) + "?mode=ro", uri=True, timeout=2
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA busy_timeout=2000")
        state_row = conn.execute(
            "SELECT value FROM guard_state WHERE key='runtime'"
        ).fetchone()
        state = json.loads(state_row["value"]) if state_row else {
            "enabled": False, "mode": "not_initialized",
            "chain_installed": False, "last_error": "尚未运行 Guard 采集器"
        }
        inventory = [
            dict(row) for row in conn.execute("""
                SELECT service_id,family,proto,public_port,dest_ip,dest_port,
                       name,category,category_label,runtime_active,conflict,
                       config_match,last_seen,updated_at
                FROM guard_services
                ORDER BY runtime_active DESC,public_port,family,proto,dest_ip
                LIMIT 100
            """).fetchall()
        ]
        totals = conn.execute("""
            SELECT COUNT(*) AS samples,
                   COUNT(DISTINCT e.src) AS unique_sources,
                   COUNT(DISTINCT e.service_id) AS unique_services,
                   COUNT(DISTINCT e.public_port) AS unique_public_ports,
                   SUM(CASE WHEN g.country_code='CN' THEN 1 ELSE 0 END) AS domestic_samples,
                   SUM(CASE WHEN g.country_code IS NOT NULL AND g.country_code<>'' AND g.country_code<>'CN'
                            THEN 1 ELSE 0 END) AS foreign_samples,
                   COUNT(DISTINCT CASE WHEN g.country_code='CN' THEN e.src END) AS domestic_sources,
                   COUNT(DISTINCT CASE WHEN g.country_code IS NOT NULL AND g.country_code<>'' AND g.country_code<>'CN'
                                       THEN e.src END) AS foreign_sources,
                   COUNT(DISTINCT CASE WHEN g.country_code IS NULL OR g.country_code=''
                                       THEN e.src END) AS unknown_geo_sources
            FROM guard_events e
            LEFT JOIN geoip_cache g ON g.ip=e.src
            WHERE e.ts>=? AND e.ts<=?
        """ + filter_sql, [since, now] + filter_params).fetchone()
        top_ports = [
            dict(row) for row in conn.execute("""
                SELECT e.public_port,e.proto,COUNT(*) AS samples,
                       COUNT(DISTINCT e.src) AS unique_sources,
                       COUNT(DISTINCT e.service_id) AS services,
                       COUNT(DISTINCT CASE WHEN g.country_code='CN' THEN e.src END) AS domestic_sources,
                       COUNT(DISTINCT CASE WHEN g.country_code IS NOT NULL AND g.country_code<>'' AND g.country_code<>'CN'
                                           THEN e.src END) AS foreign_sources
                FROM guard_events e
                LEFT JOIN geoip_cache g ON g.ip=e.src
                WHERE e.ts>=? AND e.ts<=?
            """ + filter_sql + """
                GROUP BY e.public_port,e.proto
                ORDER BY samples DESC,e.public_port,e.proto LIMIT 12
            """, [since, now] + filter_params).fetchall()
        ]
        top_sources = [
            dict(row) for row in conn.execute("""
                SELECT e.src,COUNT(*) AS samples,
                       g.country_code,g.country_name,g.asn,g.asn_org
                FROM guard_events e
                LEFT JOIN geoip_cache g ON g.ip=e.src
                WHERE e.ts>=? AND e.ts<=?
            """ + filter_sql + """
                GROUP BY e.src,g.country_code,g.country_name,g.asn,g.asn_org
                ORDER BY samples DESC,e.src LIMIT 12
            """, [since, now] + filter_params).fetchall()
        ]
        events = [
            dict(row) for row in conn.execute("""
                SELECT e.ts,e.family,e.src,e.src_port,e.public_port,e.proto,
                       e.dst,e.dest_port,e.service_id,e.capture_method,
                       COALESCE(s.name,'已移除或未知服务') AS service_name,
                       COALESCE(s.category_label,'未知') AS category_label,
                       g.country_code,g.country_name,g.asn,g.asn_org
                FROM guard_events e
                LEFT JOIN guard_services s ON s.service_id=e.service_id
                LEFT JOIN geoip_cache g ON g.ip=e.src
                WHERE e.ts>=? AND e.ts<=?
            """ + filter_sql + """
                ORDER BY e.ts DESC LIMIT 60
            """, [since, now] + filter_params).fetchall()
        ]
        bucket_counts = dict(conn.execute("""
            SELECT CAST(e.ts / ? AS INTEGER) AS bucket_index,COUNT(*)
            FROM guard_events e
            WHERE e.ts>=? AND e.ts<=?
        """ + filter_sql + """
            GROUP BY CAST(e.ts / ? AS INTEGER)
        """, [bucket, since, now] + filter_params + [bucket]).fetchall())
        first_bucket = since // bucket
        trend = [
            {"time": index * bucket, "samples": bucket_counts.get(index, 0)}
            for index in range(first_bucket, now // bucket + 1)
        ][-PERIODS[period]["count"]:]
        return {
            "period": period,
            "period_label": PERIODS[period]["label"],
            "selected_public_port": public_port,
            "from_ts": since,
            "to_ts": now,
            "bucket_seconds": bucket,
            "config": {
                "enabled": bool(config["enabled"] and config["mode"] == "observe"),
                "mode": config["mode"],
                "log_rate_per_second": config["log_rate_per_second"],
                "log_burst": config["log_burst"]
            },
            "runtime": state,
            "totals": dict(totals),
            "inventory": inventory,
            "top_ports": top_ports,
            "top_sources": top_sources,
            "events": events,
            "trend": trend,
            "disclaimer": (
                "采集 WAN DNAT 新建流量，包含国内和海外来源；国家/地区仅作归属背景，不代表可信或恶意判定。"
                "采集点位于现有 GeoWAN 国家过滤之前，样本可能随后被 GeoWAN 或 fw4 规则丢弃，不代表服务连接成功。"
                "事件来自限速内核日志样本，不代表完整连接数；nft counter 与日志样本是不同口径。"
                "当前为观察模式，不会执行 ACCEPT、DROP、REJECT 或自动封禁。"
            )
        }
    except (OSError, sqlite3.Error, ValueError, json.JSONDecodeError):
        return {"error": "database_unavailable"}
    finally:
        if conn is not None:
            conn.close()
