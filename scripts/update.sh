#!/bin/sh
# Manual GeoIP refresh wrapper. Do not schedule until updater passes fw4 validation.
set -eu
LOCK=/tmp/geowan-console.update.lock
mkdir "$LOCK" 2>/dev/null || exit 0
trap 'rmdir "$LOCK" 2>/dev/null || :' EXIT
UPDATER=/usr/local/sbin/update-geowan.sh
[ -x "$UPDATER" ] || { echo "GeoWAN updater not installed"; exit 1; }

# Snapshot existing expiring sets before any possible firewall reload.
/usr/bin/python3 /usr/libexec/geowan-console/agent.py collect

# The existing updater may fail after a reload/rollback. Always attempt restore.
set +e
"$UPDATER"
UPDATER_RC=$?
set -e

/usr/bin/python3 /usr/libexec/geowan-console/agent.py restore
/usr/bin/python3 /usr/libexec/geowan-console/agent.py collect
exit "$UPDATER_RC"
