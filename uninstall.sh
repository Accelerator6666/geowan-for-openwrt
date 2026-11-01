#!/bin/sh
set -eu
/etc/init.d/geowan-monitor stop 2>/dev/null || :
/etc/init.d/geowan-monitor disable 2>/dev/null || :
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
echo "GeoWAN rules and port forwarding unchanged."
