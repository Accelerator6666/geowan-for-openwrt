#!/bin/sh
# Read-only preflight for GeoWAN Console on OpenWrt.
set -u
FAIL=0
pass() { printf '[ OK ] %s\n' "$1"; }
warn() { printf '[WARN] %s\n' "$1"; }
fail() { printf '[FAIL] %s\n' "$1"; FAIL=1; }

echo "===== SYSTEM ====="
if [ "$(id -u)" = 0 ]; then pass "root"; else fail "run as root"; fi
if command -v ubus >/dev/null 2>&1; then ubus call system board; else fail "ubus missing"; fi
nft --version 2>&1 || fail "nft missing"
fw4 -V 2>&1 | head -n 2 || true

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
