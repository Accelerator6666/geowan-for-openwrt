#!/bin/sh
# Read-only preflight for GeoWAN Console on OpenWrt.
set -u
FAIL=0
pass() { printf '[ OK ] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; FAIL=1; }

BASE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

echo "===== SYSTEM ====="
if [ "$(id -u)" = 0 ]; then pass "root"; else fail "run as root"; fi
if command -v ubus >/dev/null 2>&1; then ubus call system board; else fail "ubus missing"; fi
nft --version 2>&1 || fail "nft missing"
fw4 -V 2>&1 | head -n 2 || true

echo
echo "===== SOURCE CHECKOUT ====="
if [ -f "$BASE/agent/geowan_profile.py" ] && [ -f "$BASE/agent/geowan_guard.py" ] && [ -f "$BASE/agent/geowan_alerts.py" ] && [ -f "$BASE/agent/geowan_enforce.py" ] && [ -f "$BASE/agent/geowan_rpc.py" ] && [ -f "$BASE/guard-alert-policy.example.json" ] && [ -f "$BASE/enforcement.example.json" ]; then
    if /usr/bin/python3 -m py_compile "$BASE"/agent/*.py "$BASE/rpcd/geowan"; then
        pass "GeoWAN Python source syntax"
    else
        fail "GeoWAN Python source syntax"
    fi
    if PYTHONPATH="$BASE/agent" /usr/bin/python3 -c 'import geowan_agent, geowan_alerts, geowan_enforce'; then
        pass "GeoWAN monitor/enforcement module import"
    else
        fail "GeoWAN alert module import"
    fi
    if /usr/bin/python3 "$BASE/rpcd/geowan" list | /usr/bin/python3 -c '
import json,sys
d=json.load(sys.stdin)
required={"lookup","list_bans","get_ban","analytics","source_profile","asn_profile","correlations","guard_overview"}
assert set(d)==required, d
assert d["guard_overview"] == {"period":"24h", "public_port":0, "alert_rule":"all", "alert_severity":"all"}, d
'; then
        pass "rpcd read-only method schemas"
    else
        fail "rpcd read-only method schemas"
    fi
    if /usr/bin/python3 - "$BASE" <<'PY'
import os,sqlite3,sys,tempfile
sys.path.insert(0, os.path.join(sys.argv[1], "agent"))
from geowan_guard import ensure_guard_schema
with tempfile.TemporaryDirectory() as root:
    db=sqlite3.connect(os.path.join(root, "legacy.sqlite3"))
    db.execute("""CREATE TABLE guard_alerts(
        alert_id TEXT PRIMARY KEY,rule_id TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'notice',src TEXT NOT NULL,
        created_at INTEGER NOT NULL,first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,last_alert_at INTEGER NOT NULL,
        window_start INTEGER NOT NULL,window_seconds INTEGER NOT NULL,
        sample_count INTEGER NOT NULL,unique_public_ports INTEGER NOT NULL,
        public_ports TEXT NOT NULL DEFAULT '[]',
        occurrence_count INTEGER NOT NULL DEFAULT 1
    )""")
    ensure_guard_schema(db)
    columns={row[1] for row in db.execute("PRAGMA table_info(guard_alerts)")}
    required={"target_port","details_json","risk_score","risk_factors"}
    assert required <= columns, columns
    db.close()
PY
    then
        pass "v0.6.1 alert database additive migration"
    else
        fail "v0.6.1 alert database additive migration"
    fi
else
    fail "GeoWAN source modules missing"
fi

echo
echo "===== DEPENDENCIES ====="
if [ -x /usr/bin/python3 ]; then
    /usr/bin/python3 -c 'import sys,sqlite3,json,ipaddress; print("Python",sys.version.split()[0],"SQLite",sqlite3.sqlite_version)' \
      && pass "Python standard library + SQLite" || fail "Python SQLite import"
    /usr/bin/python3 -c 'import maxminddb; print("maxminddb",maxminddb.__version__ if hasattr(maxminddb,"__version__") else "available")' \
      && pass "Optional offline MMDB reader" || warn "Optional GeoIP reader missing; install python3-maxminddb to enable country/city/ASN enrichment"
else
    fail "/usr/bin/python3 missing"
fi
[ -d /usr/share/luci/menu.d ] && pass "LuCI menu directory" || fail "LuCI missing"
[ -d /usr/share/rpcd/acl.d ] && pass "rpcd ACL directory" || fail "rpcd missing"
[ -x /usr/local/sbin/update-geowan.sh ] && pass "CN prefix-list updater exists (not executed)" || warn "CN prefix-list updater not found"

echo
echo "===== FIREWALL VALIDATION (NO RELOAD) ====="
if fw4 check; then pass "fw4 check"; else fail "fw4 check"; fi

echo
echo "===== REQUIRED NFT OBJECTS ====="
for object in \
    "set inet fw4 geo_cn4" "set inet fw4 geo_cn6" \
    "set inet fw4 geo_black4" "set inet fw4 geo_black6" \
    "chain inet fw4 geo_filter" "chain inet fw4 geo_wan_input" \
    "chain inet fw4 geo_wan_forward"; do
    set -- $object
    kind="$1"; family="$2"; table="$3"; name="$4"
    if nft list "$kind" "$family" "$table" "$name" >/dev/null 2>&1; then
        pass "$object"
    else
        fail "$object"
    fi
done

echo
echo "===== BLACKLIST SET JSON SAMPLE ====="
for name in geo_black4 geo_black6; do
    echo "--- $name ---"
    nft -j list set inet fw4 "$name" 2>&1 | head -c 1200
    echo
done

echo
echo "===== ACTIVE WAN DNAT INVENTORY SOURCE (READ ONLY) ====="
if nft list chain inet fw4 dstnat_wan 2>/dev/null; then
    pass "runtime WAN DNAT chain readable"
else
    fail "runtime WAN DNAT chain unavailable"
fi

echo
echo "===== GUARD NFT SYNTAX CHECK (NO APPLY) ====="
if /usr/bin/python3 - "$BASE" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "agent"))
from geowan_guard import validate_guard_rules
result = validate_guard_rules()
print("WAN device:", result["wan_device"])
print("Services:", result["service_count"])
print("Active:", result["active_service_count"])
print("Conflicts:", result["conflict_count"])
print("Observation rules:", result["rule_count"])
print("nft -c syntax check: PASS (no rules applied)")
PY
then
    pass "Sensitive Port Guard nft syntax"
else
    fail "Sensitive Port Guard nft syntax"
fi
echo
echo "===== GLOBAL SENSITIVE-PORT ENFORCEMENT PREFLIGHT (NO APPLY) ====="
if PYTHONPATH="$BASE/agent" /usr/bin/python3 - <<'PY'
from geowan_enforce import validate_enforcement_rules
result = validate_enforcement_rules()
print("WAN device:", result["wan_device"])
print("Mode:", result["mode"])
print("Protected tuples:", result["protected_port_count"])
print("Exception tuples:", result["exception_port_count"])
print("Active WAN redirects:", result["active_redirect_count"])
print("Conflicting redirects:", result["conflict_count"])
print("Default ban TTL:", result["ban_seconds"], "seconds")
print("nft -c INPUT/FORWARD check: PASS (no rules applied)")
PY
then
    pass "Global sensitive-port INPUT/FORWARD nft syntax"
else
    fail "Global sensitive-port INPUT/FORWARD nft syntax"
fi

echo
echo "===== GUARD CHAIN (READ ONLY) ====="
if nft list chain inet fw4 geo_guard_forward 2>/dev/null; then
    pass "Guard observation chain already present"
else
    warn "Guard observation chain not installed yet"
fi
echo
echo "===== ACTIVE GEO FILTER ====="
nft -a list chain inet fw4 geo_filter 2>&1 | sed -n '1,24p'
echo
echo "===== RECENT GEOWAN LOG SAMPLES ====="
logread 2>/dev/null | grep -E 'GEOWAN[46]' | tail -n 5 || true

echo
echo "===== STORAGE AND EXISTING SCHEDULE ====="
df -h /overlay 2>/dev/null || true
[ -d /etc/geowan-console/geoip/current ] && ls -lh /etc/geowan-console/geoip/current/ 2>/dev/null || echo "No offline GeoIP database installed"
grep -F 'geowan-console' /etc/crontabs/root 2>/dev/null || echo "No GeoWAN Console cron entries"
echo
if [ "$FAIL" -eq 0 ]; then
    echo "PREFLIGHT RESULT: PASS (read-only; no rules changed)"
else
    echo "PREFLIGHT RESULT: FAIL (do not install yet)"
fi
exit "$FAIL"
