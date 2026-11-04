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
# Remove only v0.7 enforcement chains/sets with exact ownership signatures.
for item in "geo_guard_enforce_input input" "geo_guard_enforce_forward forward"; do
    set -- $item
    name="$1"; hook="$2"
    if nft list chain inet fw4 "$name" >/dev/null 2>&1; then
        state="$(nft list chain inet fw4 "$name" 2>/dev/null || true)"
        comment="GeoWAN v0.7.0 Global Source Enforcement"
        if printf '%s\\n' "$state" | grep -q "type filter" &&
           printf '%s\\n' "$state" | grep -q "hook $hook priority -2" &&
           printf '%s\\n' "$state" | grep -q "policy accept" &&
           printf '%s\\n' "$state" | grep -Fq "$comment"; then
            nft delete chain inet fw4 "$name"
        else
            echo "WARNING: $name ownership signature mismatch; leaving chain untouched."
        fi
    fi
done
for item in "geo_guard_ban4 ipv4_addr" "geo_guard_ban6 ipv6_addr"; do
    set -- $item
    name="$1"; addrtype="$2"
    if nft list set inet fw4 "$name" >/dev/null 2>&1; then
        state="$(nft list set inet fw4 "$name" 2>/dev/null || true)"
        comment="GeoWAN v0.7.0 Global Source Ban"
        if printf '%s\\n' "$state" | grep -q "type $addrtype" &&
           printf '%s\\n' "$state" | grep -Eq "flags .*dynamic.*timeout|flags .*timeout.*dynamic" &&
           printf '%s\\n' "$state" | grep -Fq "$comment"; then
            nft delete set inet fw4 "$name"
        else
            echo "WARNING: $name ownership signature mismatch; leaving set untouched."
        fi
    fi
done

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
