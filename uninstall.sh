#!/bin/sh
set -eu
/etc/init.d/geowan-monitor stop 2>/dev/null || :
/etc/init.d/geowan-monitor disable 2>/dev/null || :

# Remove only the dedicated Guard base chain; leave fw4 GeoWAN chains and sets intact.
if nft list chain inet fw4 geo_guard_forward >/dev/null 2>&1; then
    GUARD_CHAIN_STATE="$(nft list chain inet fw4 geo_guard_forward 2>/dev/null || true)"
    if printf '%s\n' "$GUARD_CHAIN_STATE" | grep -q 'type filter' &&
       printf '%s\n' "$GUARD_CHAIN_STATE" | grep -q 'hook forward priority -2' &&
       printf '%s\n' "$GUARD_CHAIN_STATE" | grep -q 'policy accept' &&
       printf '%s\n' "$GUARD_CHAIN_STATE" | grep -Fq 'comment "GeoWAN Sensitive Port Guard v0.6.0"'; then
        nft delete chain inet fw4 geo_guard_forward
    else
        echo "WARNING: geo_guard_forward does not match the expected Guard base-chain signature; leaving it untouched."
    fi
fi
/etc/init.d/geowan-console disable 2>/dev/null || :
sed -i '/# geowan-console-collect/d; /# geowan-console-update/d' /etc/crontabs/root
/etc/init.d/cron restart
rm -f /usr/libexec/rpcd/geowan
rm -f /etc/init.d/geowan-console /etc/init.d/geowan-monitor \
    /usr/share/luci/menu.d/luci-app-geowan-console.json \
    /usr/share/rpcd/acl.d/luci-app-geowan-console.json \
    /www/luci-static/resources/view/geowan/overview.js \
    /www/luci-static/resources/geowan/geowan.css
rm -rf /usr/libexec/geowan-console
rm -f /tmp/luci-indexcache
/etc/init.d/rpcd restart
if [ "${1:-}" = "--purge-data" ]; then
    rm -rf /etc/geowan-console
    echo "Uninstalled and purged telemetry"
else
    echo "Uninstalled. Persistent telemetry retained at /etc/geowan-console"
fi
echo "Existing GeoWAN rules/sets and port forwarding unchanged; Guard-owned chain removed when verified."
