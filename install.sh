#!/bin/sh
# Install the companion dashboard; existing GeoWAN / DNAT rules untouched.
set -eu
BASE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
[ -f "$BASE/agent/geowan_agent.py" ] || { echo "Run from project directory"; exit 1; }
[ -x /sbin/fw4 ] || { echo "OpenWrt firewall4 required"; exit 1; }
[ -x /usr/bin/python3 ] || {
    echo "Python3 required. For OpenWrt 25.12 use: apk update && apk add python3 python3-sqlite3"
    exit 1
}
/usr/bin/python3 -c 'import sqlite3, json, ipaddress' || {
    echo "Missing Python SQLite module. Install python3-sqlite3."
    exit 1
}
[ -d /usr/share/luci/menu.d ] || { echo "LuCI is required"; exit 1; }
[ -d /usr/share/rpcd/acl.d ] || { echo "rpcd is required"; exit 1; }

# Fail closed if live GeoWAN objects are absent. This does not reload fw4.
for object in \
    "set inet fw4 geo_cn4" "set inet fw4 geo_cn6" \
    "set inet fw4 geo_black4" "set inet fw4 geo_black6" \
    "chain inet fw4 geo_filter" "chain inet fw4 geo_wan_input" \
    "chain inet fw4 geo_wan_forward"; do
    set -- $object
    kind="$1"; family="$2"; table="$3"; name="$4"
    nft list "$kind" "$family" "$table" "$name" >/dev/null 2>&1 || {
        echo "Required nftables object missing: $object"
        echo "Run preflight.sh and resolve the mismatch before installing."
        exit 1
    }
done
fw4 check >/dev/null || {
    echo "fw4 check failed. Installation stopped; firewall was not reloaded."
    exit 1
}

# Validate the rpcd executable against the source checkout before touching
# installed files or services. This catches stale v0.1 module directories.
RPC_LIST="$(/usr/bin/python3 "$BASE/rpcd/geowan" list)" || {
    echo "rpcd plugin list self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_LIST" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert set(data) == {"lookup","list_bans","get_ban","analytics","source_profile","asn_profile","correlations"}, data
assert data["lookup"] == {"ip":""}, data
assert data["get_ban"] == {"ip":""}, data
assert data["analytics"] == {"period":"24h"}, data
assert data["source_profile"] == {"ip":"", "period":"24h"}, data
assert data["asn_profile"] == {"asn":15169, "period":"24h"}, data
assert data["correlations"] == {"period":"24h"}, data
assert data["list_bans"]["page_size"] == 50, data
' || {
    echo "rpcd plugin list response invalid; installation stopped."
    exit 1
}

RPC_PRIVATE="$(printf '%s' '{"ip":"10.0.0.1"}' | /usr/bin/python3 "$BASE/rpcd/geowan" call lookup)" || {
    echo "rpcd plugin call self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_PRIVATE" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data.get("lookup_status") == "non_global", data
' || {
    echo "rpcd plugin call response invalid; installation stopped."
    exit 1
}
RPC_BAD_FILTER="$(printf '%s' '{"port":70000}' | /usr/bin/python3 "$BASE/rpcd/geowan" call list_bans)" || {
    echo "rpcd blacklist self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_BAD_FILTER" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data.get("error") == "invalid_parameters", data
' || {
    echo "rpcd blacklist validation response invalid; installation stopped."
    exit 1
}

RPC_BAD_DETAIL="$(printf '%s' '{"ip":"not-an-ip"}' | /usr/bin/python3 "$BASE/rpcd/geowan" call get_ban)" || {
    echo "rpcd detail self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_BAD_DETAIL" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data.get("error") == "invalid_ip", data
' || {
    echo "rpcd detail validation response invalid; installation stopped."
    exit 1
}
RPC_BAD_ANALYTICS="$(printf '%s' '{"period":"all"}' | /usr/bin/python3 "$BASE/rpcd/geowan" call analytics)" || {
    echo "rpcd analytics self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_BAD_ANALYTICS" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data.get("error") == "invalid_period", data
' || {
    echo "rpcd analytics validation response invalid; installation stopped."
    exit 1
}

RPC_BAD_SOURCE_PROFILE="$(printf '%s' '{"ip":"not-an-ip","period":"24h"}' | /usr/bin/python3 "$BASE/rpcd/geowan" call source_profile)" || {
    echo "rpcd source profile self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_BAD_SOURCE_PROFILE" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data.get("error") == "invalid_ip", data
' || {
    echo "rpcd source profile validation response invalid; installation stopped."
    exit 1
}
RPC_BAD_ASN_PROFILE="$(printf '%s' '{"asn":0,"period":"24h"}' | /usr/bin/python3 "$BASE/rpcd/geowan" call asn_profile)" || {
    echo "rpcd ASN profile self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_BAD_ASN_PROFILE" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data.get("error") == "invalid_asn", data
' || {
    echo "rpcd ASN profile validation response invalid; installation stopped."
    exit 1
}
RPC_BAD_CORRELATIONS="$(printf '%s' '{"period":"all"}' | /usr/bin/python3 "$BASE/rpcd/geowan" call correlations)" || {
    echo "rpcd correlations self-test failed; installation stopped."
    exit 1
}
printf '%s' "$RPC_BAD_CORRELATIONS" | /usr/bin/python3 -c '
import json,sys
data=json.load(sys.stdin)
assert data.get("error") == "invalid_period", data
' || {
    echo "rpcd correlations validation response invalid; installation stopped."
    exit 1
}

echo "rpcd plugin self-tests passed."

# Stop an existing v0.2 monitor before replacing its executable or service file.
if [ -x /etc/init.d/geowan-monitor ]; then
    /etc/init.d/geowan-monitor stop 2>/dev/null || :
fi

mkdir -p /usr/libexec/geowan-console \
    /usr/share/luci/menu.d /usr/share/rpcd/acl.d /usr/libexec/rpcd \
    /www/luci-static/resources/view/geowan \
    /www/luci-static/resources/geowan \
    /etc/geowan-console /tmp/geowan-console
chmod 700 /etc/geowan-console

cp "$BASE/agent/geowan_agent.py" /usr/libexec/geowan-console/agent.py
cp "$BASE/agent/geowan_geoip.py" /usr/libexec/geowan-console/geowan_geoip.py
cp "$BASE/agent/geowan_profile.py" /usr/libexec/geowan-console/geowan_profile.py
cp "$BASE/agent/geowan_rpc.py" /usr/libexec/geowan-console/geowan_rpc.py
cp "$BASE/rpcd/geowan" /usr/libexec/rpcd/geowan
cp "$BASE/scripts/task.sh" /usr/libexec/geowan-console/task.sh
cp "$BASE/scripts/update.sh" /usr/libexec/geowan-console/update.sh
cp "$BASE/scripts/update-geoip.sh" /usr/libexec/geowan-console/update-geoip.sh
cp "$BASE/scripts/init.sh" /etc/init.d/geowan-console
cp "$BASE/scripts/monitor.init.sh" /etc/init.d/geowan-monitor
cp "$BASE/luci/overview.js" /www/luci-static/resources/view/geowan/overview.js
cp "$BASE/luci/geowan.css" /www/luci-static/resources/geowan/geowan.css
cp "$BASE/luci/menu.json" /usr/share/luci/menu.d/luci-app-geowan-console.json
cp "$BASE/luci/acl.json" /usr/share/rpcd/acl.d/luci-app-geowan-console.json

chmod 700 /usr/libexec/geowan-console/agent.py \
    /usr/libexec/geowan-console/task.sh \
    /usr/libexec/geowan-console/update.sh \
    /usr/libexec/geowan-console/update-geoip.sh
chmod 755 /usr/libexec/rpcd/geowan
chmod 755 /etc/init.d/geowan-console
chmod 755 /etc/init.d/geowan-monitor
chmod 644 /usr/share/luci/menu.d/luci-app-geowan-console.json \
    /usr/share/rpcd/acl.d/luci-app-geowan-console.json \
    /www/luci-static/resources/view/geowan/overview.js \
    /www/luci-static/resources/geowan/geowan.css

# Keep GeoIP downloads manual until the DB-IP release and local reader are
# validated on this router; telemetry reconciliation remains scheduled.
grep -Fq '# geowan-console-collect' /etc/crontabs/root 2>/dev/null || \
  echo '*/5 * * * * /usr/libexec/geowan-console/task.sh >/tmp/geowan-console-cron.log 2>&1 # geowan-console-collect' >> /etc/crontabs/root

/etc/init.d/geowan-console enable
/etc/init.d/geowan-monitor enable
/etc/init.d/cron enable
/etc/init.d/cron restart
/etc/init.d/rpcd restart
rm -f /tmp/luci-indexcache
/usr/libexec/geowan-console/task.sh
/etc/init.d/geowan-monitor start
echo "GeoWAN Console installed. Open LuCI -> Services -> GeoWAN 安全面板."
echo "Database: /etc/geowan-console/telemetry.sqlite3"
echo "Fast monitor: counters every 5s, blacklist inventory/log scan every 15s; 5-minute reconciliation remains enabled."
if ! /usr/bin/python3 -c 'import maxminddb' >/dev/null 2>&1; then
    echo "GeoIP lookup is optional and inactive. Install with: apk add python3-maxminddb"
fi
echo "No new TCP/UDP port and no firewall rules modified."
