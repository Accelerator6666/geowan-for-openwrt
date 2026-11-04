#!/usr/bin/env python3
"""GeoWAN v0.7 global sensitive-port enforcement.

The nftables data path performs the decision. Python only inventories policy,
persists the kernel-created source bans, restores them after fw4 reload/reboot,
and exposes health counters. Country/GeoIP is deliberately not consulted.
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

from geowan_guard import build_inventory

CONFIG_PATH = Path(os.environ.get(
    "GEOWAN_ENFORCEMENT_CONFIG",
    "/etc/geowan-console/enforcement.json"
))
INPUT_CHAIN = "geo_guard_enforce_input"
FORWARD_CHAIN = "geo_guard_enforce_forward"
BAN4_SET = "geo_guard_ban4"
BAN6_SET = "geo_guard_ban6"
BAN_SECONDS_DEFAULT = 7 * 86400
MAX_BAN_SECONDS = 30 * 86400
CHAIN_COMMENTS = {
    INPUT_CHAIN: "GeoWAN v0.7.0 Global Source Enforcement INPUT",
    FORWARD_CHAIN: "GeoWAN v0.7.0 Global Source Enforcement FORWARD",
}
SET_COMMENTS = {
    BAN4_SET: "GeoWAN v0.7.0 Global Source Ban IPv4",
    BAN6_SET: "GeoWAN v0.7.0 Global Source Ban IPv6",
}
IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
BLOCK_MARKER = re.compile(
    r"\bGEOWAN_BLOCK([46])\|([IF])\|(TCP|UDP)\|([0-9]{1,5})\|"
)
FIELDS = re.compile(r"\b(SRC|DST|SPT|DPT|PROTO)=([^\s]+)")
SYSLOG_TIME = re.compile(
    r"^(?:[A-Za-z]{3}\s+)?([A-Za-z]{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)"
)

DEFAULT_SENSITIVE_PORTS = [
    {"port": 20, "proto": "tcp", "family": "any", "label": "FTP data"},
    {"port": 21, "proto": "tcp", "family": "any", "label": "FTP"},
    {"port": 22, "proto": "tcp", "family": "any", "label": "SSH"},
    {"port": 23, "proto": "tcp", "family": "any", "label": "Telnet"},
    {"port": 111, "proto": "tcp", "family": "any", "label": "RPCbind"},
    {"port": 111, "proto": "udp", "family": "any", "label": "RPCbind"},
    {"port": 139, "proto": "tcp", "family": "any", "label": "NetBIOS"},
    {"port": 445, "proto": "tcp", "family": "any", "label": "SMB"},
    {"port": 548, "proto": "tcp", "family": "any", "label": "AFP"},
    {"port": 873, "proto": "tcp", "family": "any", "label": "rsync"},
    {"port": 2049, "proto": "tcp", "family": "any", "label": "NFS"},
    {"port": 2049, "proto": "udp", "family": "any", "label": "NFS"},
    {"port": 2375, "proto": "tcp", "family": "any", "label": "Docker API"},
    {"port": 2376, "proto": "tcp", "family": "any", "label": "Docker TLS API"},
    {"port": 3306, "proto": "tcp", "family": "any", "label": "MySQL"},
    {"port": 3389, "proto": "tcp", "family": "any", "label": "RDP direct"},
    {"port": 3389, "proto": "udp", "family": "any", "label": "RDP direct"},
    {"port": 389, "proto": "tcp", "family": "any", "label": "LDAP"},
    {"port": 636, "proto": "tcp", "family": "any", "label": "LDAPS"},
    {"port": 1433, "proto": "tcp", "family": "any", "label": "MSSQL"},
    {"port": 5432, "proto": "tcp", "family": "any", "label": "PostgreSQL"},
    {"port": 5900, "proto": "tcp", "family": "any", "label": "VNC"},
    {"port": 5901, "proto": "tcp", "family": "any", "label": "VNC"},
    {"port": 5000, "proto": "tcp", "family": "any", "label": "Synology DSM"},
    {"port": 5001, "proto": "tcp", "family": "any", "label": "Synology DSM HTTPS"},
    {"port": 5005, "proto": "tcp", "family": "any", "label": "Synology WebDAV"},
    {"port": 5006, "proto": "tcp", "family": "any", "label": "Synology WebDAV HTTPS"},
    {"port": 5432, "proto": "tcp", "family": "any", "label": "PostgreSQL"},
    {"port": 6379, "proto": "tcp", "family": "any", "label": "Redis"},
    {"port": 6690, "proto": "tcp", "family": "any", "label": "Synology Drive"},
    {"port": 8006, "proto": "tcp", "family": "any", "label": "Proxmox"},
    {"port": 9200, "proto": "tcp", "family": "any", "label": "Elasticsearch"},
    {"port": 9300, "proto": "tcp", "family": "any", "label": "Elasticsearch transport"},
    {"port": 27017, "proto": "tcp", "family": "any", "label": "MongoDB"},
]
DEFAULT_EXCEPTION_PORTS = [
    {"port": 20443, "proto": "tcp", "family": "any", "label": "SSLVPN"},
    {"port": 20443, "proto": "udp", "family": "any", "label": "SSLVPN"},
    {"port": 58964, "proto": "tcp", "family": "any", "label": "RDP public"},
    {"port": 58964, "proto": "udp", "family": "any", "label": "RDP public"},
    {"port": 3389, "proto": "tcp", "family": "any", "label": "RDP direct"},
    {"port": 3389, "proto": "udp", "family": "any", "label": "RDP direct"},
]
DEFAULT_POLICY = {
    "enabled": True,
    "mode": "observe",
    "ban_seconds": BAN_SECONDS_DEFAULT,
    "max_bans": 65536,
    "protect_all_active_redirects": True,
    "auto_detect_rdp": True,
    "auto_detect_sslvpn": True,
    "log_rate_per_second": 2,
    "log_burst": 10,
    "sensitive_ports": DEFAULT_SENSITIVE_PORTS,
    "exception_ports": DEFAULT_EXCEPTION_PORTS,
}


def run(*args, input_text=None):
    return subprocess.run(
        list(args), input=input_text, text=True, capture_output=True,
        timeout=20, check=True
    ).stdout


def ensure_enforcement_schema(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS guard_bans(
            ip TEXT PRIMARY KEY,
            family INTEGER NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            trigger_port INTEGER,
            proto TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '',
            dst TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT 'sensitive_port_hit'
        );
        CREATE INDEX IF NOT EXISTS idx_guard_bans_expiry
            ON guard_bans(expires_at);
        CREATE INDEX IF NOT EXISTS idx_guard_bans_last_seen
            ON guard_bans(last_seen DESC);
        CREATE TABLE IF NOT EXISTS guard_block_events(
            id TEXT PRIMARY KEY,
            ts INTEGER NOT NULL,
            ip TEXT NOT NULL,
            family INTEGER NOT NULL,
            trigger_port INTEGER NOT NULL,
            proto TEXT NOT NULL,
            path TEXT NOT NULL,
            dst TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_guard_block_events_ts
            ON guard_block_events(ts);
    """)
    conn.commit()


def _parse_port_entries(raw):
    if not isinstance(raw, list):
        raise ValueError("port_list_must_be_array")
    result = set()
    labels = {}
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("port_entry_must_be_object")
        port = item.get("port")
        if isinstance(port, bool):
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        proto = str(item.get("proto", "tcp")).lower()
        if proto not in ("tcp", "udp"):
            continue
        family_raw = item.get("family", "any")
        if family_raw in ("any", "dual", 0, None, ""):
            families = (4, 6)
        elif str(family_raw).lower() in ("4", "ipv4"):
            families = (4,)
        elif str(family_raw).lower() in ("6", "ipv6"):
            families = (6,)
        else:
            continue
        label = str(item.get("label", "")).strip()[:80]
        for family in families:
            key = (family, proto, port)
            result.add(key)
            if label:
                labels[key] = label
    return result, labels


def read_policy(path=None):
    path = Path(path or CONFIG_PATH)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("policy_must_be_object")
    except FileNotFoundError:
        raw = {}
    except (OSError, ValueError, json.JSONDecodeError):
        result = dict(DEFAULT_POLICY)
        result["enabled"] = False
        result["mode"] = "disabled"
        result["policy_error"] = "invalid_policy"
        return result

    policy = dict(DEFAULT_POLICY)
    policy.update(raw)
    policy["enabled"] = raw.get("enabled", DEFAULT_POLICY["enabled"]) is True
    mode = str(raw.get("mode", DEFAULT_POLICY["mode"])).lower()
    policy["mode"] = mode if mode in ("observe", "enforce", "disabled") else "disabled"
    if mode not in ("observe", "enforce", "disabled"):
        policy["enabled"] = False
        policy["policy_error"] = "invalid_mode"
    if not policy["enabled"]:
        policy["mode"] = "disabled"
    try:
        seconds = int(raw.get("ban_seconds", BAN_SECONDS_DEFAULT))
        policy["ban_seconds"] = min(MAX_BAN_SECONDS, max(3600, seconds))
        size = int(raw.get("max_bans", 65536))
        policy["max_bans"] = min(131072, max(1024, size))
        policy["log_rate_per_second"] = min(20, max(1, int(raw.get("log_rate_per_second", 2))))
        policy["log_burst"] = min(100, max(1, int(raw.get("log_burst", 10))))
    except (TypeError, ValueError):
        policy["enabled"] = False
        policy["mode"] = "disabled"
        policy["policy_error"] = "invalid_numeric_policy"
        return policy
    for key in ("protect_all_active_redirects", "auto_detect_rdp", "auto_detect_sslvpn"):
        policy[key] = raw.get(key, DEFAULT_POLICY[key]) is True
    try:
        policy["sensitive_set"], policy["sensitive_labels"] = _parse_port_entries(
            raw.get("sensitive_ports", DEFAULT_SENSITIVE_PORTS)
        )
        policy["exception_set"], policy["exception_labels"] = _parse_port_entries(
            raw.get("exception_ports", DEFAULT_EXCEPTION_PORTS)
        )
    except ValueError as exc:
        policy["enabled"] = False
        policy["mode"] = "disabled"
        policy["policy_error"] = str(exc)
        return policy
    policy.pop("sensitive_ports", None)
    policy.pop("exception_ports", None)
    return policy


def _parse_uci_sections(text, wanted):
    sections = []
    current = None

    def finish():
        if current is not None and current.get("_type") in wanted:
            sections.append(dict(current))

    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^config\s+(\S+)(?:\s+(.+))?$", line)
        if match:
            finish()
            try:
                tokens = shlex.split(match.group(2) or "")
            except ValueError:
                tokens = []
            current = {
                "_type": match.group(1),
                "_section": tokens[0] if tokens else "",
            }
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
    return sections


def _protos(section):
    values = section.get("_list_proto") or str(section.get("proto", "tcp")).split()
    result = sorted({str(value).lower() for value in values} & {"tcp", "udp"})
    return result or ["tcp"]


def _is_rdp_service(item):
    name = str(item.get("name", "")).lower()
    return int(item.get("dest_port") or 0) == 3389 or bool(
        re.search(r"\brdp\b|remote[ _-]?desktop", name)
    )


def _is_sslvpn_name(value):
    return bool(re.search(r"ssl[ _-]*vpn", str(value or "").lower()))


def build_policy(uci_text, nft_text, config_path=None, now=None):
    policy = read_policy(config_path)
    if not policy["enabled"]:
        policy.update({
            "protected": set(), "exceptions": set(),
            "protected_labels": {}, "active_redirect_count": 0,
            "conflict_count": 0,
        })
        return policy

    protected = set(policy["sensitive_set"])
    exceptions = set(policy["exception_set"])
    protected_labels = dict(policy["sensitive_labels"])
    for key, label in policy["exception_labels"].items():
        protected_labels.setdefault(key, label)

    inventory = build_inventory(uci_text, nft_text, now=now)
    active = [row for row in inventory if row.get("runtime_active")]
    conflicts = [row for row in active if row.get("conflict")]
    for row in active:
        if row.get("conflict"):
            continue
        family = int(row["family"])
        proto = str(row["proto"]).lower()
        port = int(row["public_port"])
        key = (family, proto, port)
        if policy["protect_all_active_redirects"]:
            protected.add(key)
            protected_labels.setdefault(key, str(row.get("name") or "WAN redirect"))
        name = str(row.get("name") or "")
        if policy["auto_detect_rdp"] and _is_rdp_service(row):
            exceptions.add(key)
            protected_labels.setdefault(key, "RDP exception")
        if policy["auto_detect_sslvpn"] and _is_sslvpn_name(name):
            exceptions.add(key)
            protected_labels.setdefault(key, "SSLVPN exception")

    for section in _parse_uci_sections(uci_text, {"rule"}):
        if section.get("src", "wan") != "wan" or section.get("enabled", "1") == "0":
            continue
        if str(section.get("target", "")).upper() != "ACCEPT":
            continue
        name = str(section.get("name") or "")
        is_rdp = policy["auto_detect_rdp"] and (
            "rdp" in name.lower() or _safe_int(section.get("dest_port")) == 3389
        )
        is_vpn = policy["auto_detect_sslvpn"] and _is_sslvpn_name(name)
        if not (is_rdp or is_vpn):
            continue
        ports = _parse_port_range(section.get("dest_port"))
        for port in ports:
            for proto in _protos(section):
                for family in (4, 6):
                    key = (family, proto, port)
                    exceptions.add(key)
                    protected_labels.setdefault(
                        key, "RDP exception" if is_rdp else "SSLVPN exception"
                    )

    protected.difference_update(exceptions)
    return {
        **policy,
        "protected": protected,
        "exceptions": exceptions,
        "protected_labels": protected_labels,
        "active_redirect_count": len(active),
        "conflict_count": len(conflicts),
        "conflicting_ports": sorted({
            int(row["public_port"]) for row in conflicts
        }),
    }


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_port_range(value):
    result = set()
    for token in str(value or "").replace(",", " ").split():
        if "-" in token:
            left, right = token.split("-", 1)
            a, b = _safe_int(left), _safe_int(right)
            if a and b and 1 <= a <= b <= 65535 and b - a <= 128:
                result.update(range(a, b + 1))
        else:
            port = _safe_int(token)
            if port and 1 <= port <= 65535:
                result.add(port)
    return result


def _port_condition(ports):
    values = sorted(set(int(port) for port in ports))
    if not values:
        return ""
    if len(values) == 1:
        return "ct original proto-dst != %d" % values[0]
    return "ct original proto-dst != { %s }" % ", ".join(str(x) for x in values)


def _family_prefix(family):
    return "ip" if family == 4 else "ip6"


def _render_ban_rules(family, wan, exceptions, ban_set):
    addr = _family_prefix(family)
    src = addr + " saddr"
    result = []
    for proto in ("tcp", "udp"):
        ports = [
            port for fam, item_proto, port in exceptions
            if fam == family and item_proto == proto
        ]
        condition = _port_condition(ports)
        suffix = (" " + condition) if condition else ""
        result.append(
            'add rule inet fw4 CHAIN iifname "%s" %s @%s meta l4proto %s%s '
            'counter drop' % (wan, src, ban_set, proto, suffix)
        )
    result.append(
        'add rule inet fw4 CHAIN iifname "%s" %s @%s '
        'meta l4proto != { tcp, udp } counter drop' % (wan, src, ban_set)
    )
    return result


def _render_trigger_rule(family, proto, port, path, wan, ban_set, ttl):
    addr = _family_prefix(family)
    marker = "GEOWAN_BLOCK%d|%s|%s|%d|" % (
        family, path, proto.upper(), port
    )
    return (
        'add rule inet fw4 CHAIN iifname "%s" %s saddr != @%s '
        'meta nfproto ipv%d meta l4proto %s ct state new '
        'ct original proto-dst %d update @%s { %s saddr timeout %ds } '
        'counter log prefix "%s" level warning drop'
    ) % (
        wan, addr, ban_set, family, proto, port, ban_set, addr, ttl, marker
    )


def render_chain_rules(policy, wan_device, hook, mode=None):
    if not IFNAME.fullmatch(str(wan_device or "")):
        raise ValueError("invalid_wan_device")
    if hook not in ("input", "forward"):
        raise ValueError("invalid_hook")
    mode = mode or policy.get("mode", "observe")
    chain = INPUT_CHAIN if hook == "input" else FORWARD_CHAIN
    rules = []
    protected = sorted(policy.get("protected", set()))
    exceptions = policy.get("exceptions", set())
    for family in (4, 6):
        ban_set = BAN4_SET if family == 4 else BAN6_SET
        if mode == "enforce":
            for line in _render_ban_rules(family, wan_device, exceptions, ban_set):
                rules.append(line.replace("CHAIN", chain))
        for fam, proto, port in protected:
            if fam != family:
                continue
            marker = "GEOWAN_SENS%d|%s|%s|%d|" % (
                family, "I" if hook == "input" else "F", proto.upper(), port
            )
            common = (
                'iifname "%s" meta nfproto ipv%d meta l4proto %s '
                'ct state new ct original proto-dst %d counter'
            ) % (wan_device, family, proto, port)
            if mode == "enforce":
                rule = _render_trigger_rule(
                    family, proto, port, "I" if hook == "input" else "F",
                    wan_device, ban_set, policy["ban_seconds"]
                )
                rules.append(rule.replace("CHAIN", chain))
            else:
                rules.append(
                    'add rule inet fw4 %s %s limit rate %d/second burst %d packets '
                    'log prefix "%s" level info' % (
                        chain, common, policy["log_rate_per_second"],
                        policy["log_burst"], marker
                    )
                )
    return rules


def render_enforcement_script(policy, wan_device, input_exists=False,
                              forward_exists=False, sets_exist=False):
    mode = policy.get("mode", "observe")
    lines = []
    if mode == "enforce":
        existing_sets = sets_exist if isinstance(sets_exist, set) else (
            {BAN4_SET, BAN6_SET} if sets_exist else set()
        )
        if BAN4_SET not in existing_sets:
            lines.append(
                "add set inet fw4 %s { type ipv4_addr; flags dynamic,timeout; timeout %ds; "
                "size %d; comment %s; }" % (
                    BAN4_SET, policy["ban_seconds"], policy["max_bans"],
                    json.dumps(SET_COMMENTS[BAN4_SET])
                )
            )
        if BAN6_SET not in existing_sets:
            lines.append(
                "add set inet fw4 %s { type ipv6_addr; flags dynamic,timeout; timeout %ds; "
                "size %d; comment %s; }" % (
                    BAN6_SET, policy["ban_seconds"], policy["max_bans"],
                    json.dumps(SET_COMMENTS[BAN6_SET])
                )
            )
    for name, hook, exists in (
        (INPUT_CHAIN, "input", input_exists),
        (FORWARD_CHAIN, "forward", forward_exists),
    ):
        if exists:
            lines.append("flush chain inet fw4 %s" % name)
        else:
            lines.append(
                "add chain inet fw4 %s { type filter hook %s priority -2; "
                "policy accept; comment %s; }" % (
                    name, hook, json.dumps(CHAIN_COMMENTS[name])
                )
            )
        lines.extend(render_chain_rules(policy, wan_device, hook, mode))
    return "\n".join(lines) + "\n"


def _chain_state(name, hook, command_runner):
    try:
        output = command_runner("nft", "list", "chain", "inet", "fw4", name)
    except subprocess.CalledProcessError:
        return False
    priority = re.search(r"\bpriority\s+(?:filter\s+)?-\s*2\b", output)
    if (
        "type filter" not in output
        or ("hook " + hook) not in output
        or priority is None
        or "policy accept" not in output
        or ('comment "%s"' % CHAIN_COMMENTS[name]) not in output
    ):
        raise RuntimeError("enforcement_chain_name_conflict:" + name)
    return True


def _set_state(name, family, command_runner):
    try:
        output = command_runner("nft", "list", "set", "inet", "fw4", name)
    except subprocess.CalledProcessError:
        return False
    expected_type = "ipv4_addr" if family == 4 else "ipv6_addr"
    flags = re.search(r"\bflags\s+([^;]+)", output)
    flag_text = flags.group(1).replace(" ", "") if flags else ""
    if (
        "type " + expected_type not in output
        or ('comment "%s"' % SET_COMMENTS[name]) not in output
        or "dynamic" not in flag_text
        or "timeout" not in flag_text
    ):
        raise RuntimeError("enforcement_set_name_conflict:" + name)
    return True


def parse_nft_set_members(output, family):
    data = json.loads(output)
    result = {}
    for row in data.get("nftables", []):
        item = row.get("set", {})
        if not item:
            continue
        for entry in item.get("elem", []):
            obj = entry.get("elem", entry)
            raw = obj.get("val") if isinstance(obj, dict) else obj
            expires = obj.get("expires") if isinstance(obj, dict) else None
            if isinstance(raw, dict):
                raw = raw.get("prefix", raw.get("val"))
            try:
                ip = ipaddress.ip_address(raw)
                if (
                    ip.version != family or ip.is_multicast or ip.is_unspecified
                    or ip.is_loopback or ip.is_link_local
                ):
                    continue
            except (TypeError, ValueError):
                continue
            ttl = BAN_SECONDS_DEFAULT
            if isinstance(expires, (int, float)):
                ttl = min(MAX_BAN_SECONDS, max(1, int(expires)))
            result[str(ip)] = ttl
    return result


def _restore_and_reconcile_set(conn, family, set_name, now, command_runner):
    raw = command_runner("nft", "-j", "list", "set", "inet", "fw4", set_name)
    current = parse_nft_set_members(raw, family)
    rows = conn.execute(
        "SELECT ip,first_seen,last_seen,expires_at,trigger_port,proto,path,dst,reason "
        "FROM guard_bans WHERE family=? AND expires_at>?",
        (family, now)
    ).fetchall()
    pending = []
    for ip, first, last, expiry, port, proto, path, dst, reason in rows:
        ttl = min(MAX_BAN_SECONDS, max(1, int(expiry) - now))
        if ip not in current:
            pending.append("%s timeout %ds" % (ip, ttl))
    for start in range(0, len(pending), 64):
        chunk = pending[start:start + 64]
        command_runner(
            "nft", "add", "element", "inet", "fw4", set_name,
            "{ " + ", ".join(chunk) + " }"
        )

    for ip, ttl in current.items():
        existing = conn.execute(
            "SELECT expires_at FROM guard_bans WHERE ip=?", (ip,)
        ).fetchone()
        if existing:
            if int(existing[0]) <= now:
                conn.execute(
                    "UPDATE guard_bans SET first_seen=?,last_seen=?,expires_at=?,"
                    "reason='kernel_set_recovered' WHERE ip=?",
                    (now, now, now + ttl, ip)
                )
            continue
        conn.execute("""
            INSERT OR IGNORE INTO guard_bans(
                ip,family,first_seen,last_seen,expires_at,reason
            ) VALUES(?,?,?,?,?,?)
        """, (ip, family, now, now, now + ttl, "kernel_set_recovered"))
    conn.execute("DELETE FROM guard_bans WHERE expires_at<=?", (now,))
    return len(current), len(pending)


def _wan_device(command_runner):
    try:
        data = json.loads(command_runner(
            "ubus", "call", "network.interface.wan", "status"
        ))
        value = data.get("l3_device") or data.get("device") or data.get("ifname")
        if value and IFNAME.fullmatch(str(value)):
            return str(value)
    except (OSError, subprocess.CalledProcessError, ValueError, json.JSONDecodeError):
        pass
    for key in ("network.wan.device", "network.wan.ifname"):
        try:
            value = command_runner("uci", "-q", "get", key).strip()
            if value and IFNAME.fullmatch(value):
                return value
        except (OSError, subprocess.CalledProcessError):
            pass
    return ""


def validate_enforcement_rules(command_runner=None, config_path=None):
    runner = command_runner or run
    policy = read_policy(config_path)
    if not policy["enabled"]:
        raise RuntimeError("enforcement_policy_disabled_or_invalid")
    uci_text = runner("uci", "-q", "export", "firewall")
    nft_text = runner("nft", "-a", "list", "chain", "inet", "fw4", "dstnat_wan")
    policy = build_policy(uci_text, nft_text, config_path)
    wan = _wan_device(runner)
    if not wan:
        raise RuntimeError("wan_device_unavailable")
    input_exists = _chain_state(INPUT_CHAIN, "input", runner)
    forward_exists = _chain_state(FORWARD_CHAIN, "forward", runner)
    existing_sets = set()
    if policy["mode"] == "enforce":
        if _set_state(BAN4_SET, 4, runner):
            existing_sets.add(BAN4_SET)
        if _set_state(BAN6_SET, 6, runner):
            existing_sets.add(BAN6_SET)
    script = render_enforcement_script(
        policy, wan, input_exists, forward_exists, existing_sets
    )
    runner("nft", "-c", "-f", "-", input_text=script)
    return {
        "wan_device": wan,
        "mode": policy["mode"],
        "protected_port_count": len(policy["protected"]),
        "exception_port_count": len(policy["exceptions"]),
        "active_redirect_count": policy["active_redirect_count"],
        "conflict_count": policy["conflict_count"],
        "ban_seconds": policy["ban_seconds"],
        "input_chain_exists": input_exists,
        "forward_chain_exists": forward_exists,
    }


def refresh_enforcement(conn, now=None, config_path=None, command_runner=None):
    now = int(time.time()) if now is None else int(now)
    ensure_enforcement_schema(conn)
    runner = command_runner or run
    policy = read_policy(config_path)
    try:
        if policy.get("policy_error"):
            return {
                "enabled": False, "mode": "degraded", "chain_installed": False,
                "active_bans": conn.execute(
                    "SELECT COUNT(*) FROM guard_bans WHERE expires_at>?", (now,)
                ).fetchone()[0],
                "last_error": policy["policy_error"],
            }
        if not policy["enabled"] or policy["mode"] == "disabled":
            for name, hook in ((INPUT_CHAIN, "input"), (FORWARD_CHAIN, "forward")):
                if _chain_state(name, hook, runner):
                    runner("nft", "delete", "chain", "inet", "fw4", name)
            conn.execute("DELETE FROM guard_bans WHERE expires_at<=?", (now,))
            conn.commit()
            return {
                "enabled": False, "mode": "disabled", "chain_installed": False,
                "active_bans": conn.execute(
                    "SELECT COUNT(*) FROM guard_bans WHERE expires_at>?", (now,)
                ).fetchone()[0],
                "last_error": policy.get("policy_error", ""),
            }

        uci_text = runner("uci", "-q", "export", "firewall")
        nft_text = runner("nft", "-a", "list", "chain", "inet", "fw4", "dstnat_wan")
        policy = build_policy(uci_text, nft_text, config_path, now)
        if not policy["enabled"]:
            raise RuntimeError(policy.get("policy_error") or "invalid_enforcement_policy")
        wan = _wan_device(runner)
        if not wan:
            raise RuntimeError("wan_device_unavailable")

        sets_exist = False
        set_counts = {4: 0, 6: 0}
        restored = {4: 0, 6: 0}
        if policy["mode"] == "enforce":
            for name, family in ((BAN4_SET, 4), (BAN6_SET, 6)):
                exists = _set_state(name, family, runner)
                if not exists:
                    definition = (
                        "add set inet fw4 %s { type %s; flags dynamic,timeout; timeout %ds; "
                        "size %d; comment %s; }"
                    ) % (
                        name, "ipv4_addr" if family == 4 else "ipv6_addr",
                        policy["ban_seconds"], policy["max_bans"],
                        json.dumps(SET_COMMENTS[name])
                    )
                    runner("nft", "-f", "-", input_text=definition + "\n")
            sets_exist = True

        input_exists = _chain_state(INPUT_CHAIN, "input", runner)
        forward_exists = _chain_state(FORWARD_CHAIN, "forward", runner)
        script = render_enforcement_script(
            policy, wan, input_exists, forward_exists, sets_exist
        )
        runner("nft", "-f", "-", input_text=script)

        if policy["mode"] == "enforce":
            for family, name in ((4, BAN4_SET), (6, BAN6_SET)):
                set_counts[family], restored[family] = _restore_and_reconcile_set(
                    conn, family, name, now, runner
                )
        conn.execute("DELETE FROM guard_bans WHERE expires_at<=?", (now,))
        conn.commit()
        active = conn.execute(
            "SELECT COUNT(*) FROM guard_bans WHERE expires_at>?", (now,)
        ).fetchone()[0]
        return {
            "enabled": True,
            "mode": policy["mode"],
            "chain_installed": True,
            "wan_device": wan,
            "protected_port_count": len(policy["protected"]),
            "exception_port_count": len(policy["exceptions"]),
            "active_redirect_count": policy["active_redirect_count"],
            "conflict_count": policy["conflict_count"],
            "ban_seconds": policy["ban_seconds"],
            "active_bans": active,
            "kernel_bans_v4": set_counts[4],
            "kernel_bans_v6": set_counts[6],
            "restored_v4": restored[4],
            "restored_v6": restored[6],
            "last_error": "",
        }
    except (OSError, subprocess.CalledProcessError, RuntimeError, ValueError) as exc:
        conn.rollback()
        return {
            "enabled": False, "mode": "degraded", "chain_installed": False,
            "active_bans": conn.execute(
                "SELECT COUNT(*) FROM guard_bans WHERE expires_at>?", (now,)
            ).fetchone()[0],
            "last_error": str(exc)[:240],
        }


def parse_block_log(line, now=None, boot="unknown-boot", ban_seconds=BAN_SECONDS_DEFAULT):
    match = BLOCK_MARKER.search(str(line or ""))
    if not match:
        return None
    family = 4 if match.group(1) == "4" else 6
    path = "input" if match.group(2) == "I" else "forward"
    proto = match.group(3)
    port = int(match.group(4))
    if not 1 <= port <= 65535:
        return None
    fields = dict(FIELDS.findall(str(line)))
    try:
        source = ipaddress.ip_address(fields.get("SRC", ""))
        if (
            source.version != family or source.is_multicast
            or source.is_unspecified or source.is_loopback or source.is_link_local
        ):
            return None
        dest = ipaddress.ip_address(fields.get("DST", ""))
    except ValueError:
        return None
    src_port = _safe_int(fields.get("SPT"))
    if src_port is not None and not 1 <= src_port <= 65535:
        src_port = None
    now = int(time.time()) if now is None else int(now)
    stamp = now
    found = SYSLOG_TIME.match(str(line))
    if found:
        try:
            import datetime as dt
            parsed = dt.datetime.strptime(
                "%d %s" % (dt.datetime.fromtimestamp(now).year, found.group(1)),
                "%Y %b %d %H:%M:%S"
            )
            stamp = int(parsed.timestamp())
            if stamp > now + 86400:
                stamp = int(parsed.replace(year=parsed.year - 1).timestamp())
        except ValueError:
            pass
    event_id = hashlib.sha256(
        (str(boot) + "\0" + str(line)).encode("utf-8")
    ).hexdigest()
    return {
        "id": event_id, "ts": stamp, "ip": str(source), "family": family,
        "trigger_port": port, "proto": proto, "path": path,
        "dst": str(dest), "expires_at": now + int(ban_seconds),
    }


def insert_block_log_samples(conn, now=None, lines=None, boot="unknown-boot",
                             ban_seconds=None, config_path=None,
                             command_runner=None):
    now = int(time.time()) if now is None else int(now)
    policy = read_policy(config_path)
    ttl = int(ban_seconds or policy.get("ban_seconds", BAN_SECONDS_DEFAULT))
    if lines is None:
        runner = command_runner or run
        try:
            lines = runner("logread").splitlines()
        except (OSError, subprocess.CalledProcessError):
            lines = []
    ensure_enforcement_schema(conn)
    inserted = 0
    for line in lines:
        item = parse_block_log(line, now, boot, ttl)
        if not item:
            continue
        cur = conn.execute("""
            INSERT OR IGNORE INTO guard_block_events(
                id,ts,ip,family,trigger_port,proto,path,dst
            ) VALUES(?,?,?,?,?,?,?,?)
        """, (
            item["id"], item["ts"], item["ip"], item["family"],
            item["trigger_port"], item["proto"], item["path"], item["dst"]
        ))
        if cur.rowcount <= 0:
            continue
        conn.execute("""
            INSERT INTO guard_bans(
                ip,family,first_seen,last_seen,expires_at,
                trigger_port,proto,path,dst,reason
            ) VALUES(?,?,?,?,?,?,?,?,?,'sensitive_port_hit')
            ON CONFLICT(ip) DO UPDATE SET
                last_seen=MAX(guard_bans.last_seen,excluded.last_seen),
                expires_at=MAX(guard_bans.expires_at,excluded.expires_at),
                trigger_port=COALESCE(guard_bans.trigger_port,excluded.trigger_port),
                proto=CASE WHEN guard_bans.proto='' THEN excluded.proto ELSE guard_bans.proto END,
                path=CASE WHEN guard_bans.path='' THEN excluded.path ELSE guard_bans.path END,
                dst=CASE WHEN guard_bans.dst='' THEN excluded.dst ELSE guard_bans.dst END
        """, (
            item["ip"], item["family"], item["ts"], item["ts"],
            item["expires_at"], item["trigger_port"], item["proto"],
            item["path"], item["dst"]
        ))
        inserted += 1
    conn.execute("DELETE FROM guard_block_events WHERE ts<?", (now - 90 * 86400,))
    conn.execute("DELETE FROM guard_bans WHERE expires_at<=?", (now,))
    return inserted


def enforcement_blocklist(conn, now=None, limit=100):
    now = int(time.time()) if now is None else int(now)
    ensure_enforcement_schema(conn)
    return [{
        "ip": row[0], "family": row[1], "first_seen": row[2],
        "last_seen": row[3], "expires_at": row[4],
        "trigger_port": row[5], "proto": row[6], "path": row[7],
        "dst": row[8], "reason": row[9],
        "country_code": row[10] or "", "country_name": row[11] or "",
        "city": row[12] or "", "asn": row[13], "asn_org": row[14] or "",
        "lookup_status": row[15] or "pending",
    } for row in conn.execute("""
        SELECT b.ip,b.family,b.first_seen,b.last_seen,b.expires_at,
               b.trigger_port,b.proto,b.path,b.dst,b.reason,
               g.country_code,g.country_name,g.city,g.asn,g.asn_org,g.lookup_status
        FROM guard_bans b LEFT JOIN geoip_cache g ON g.ip=b.ip
        WHERE b.expires_at>?
        ORDER BY b.last_seen DESC,b.ip LIMIT ?
    """, (now, max(1, min(1000, int(limit)))))]


def enforcement_status(conn, now=None):
    now = int(time.time()) if now is None else int(now)
    policy = read_policy()
    active = conn.execute(
        "SELECT COUNT(*) FROM guard_bans WHERE expires_at>?", (now,)
    ).fetchone()[0]
    return {
        "enabled": bool(policy["enabled"]),
        "mode": policy["mode"],
        "ban_seconds": policy["ban_seconds"],
        "active_bans": active,
        "default_sensitive_ports": len(policy.get("sensitive_set", ())),
        "last_error": policy.get("policy_error", ""),
    }
