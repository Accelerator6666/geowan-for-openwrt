#!/bin/sh
# Restore expiring bans if fw4 was reloaded, then collect new telemetry.
set -eu
LOCK=/tmp/geowan-console.collect.lock
mkdir "$LOCK" 2>/dev/null || exit 0
trap 'rmdir "$LOCK" 2>/dev/null || :' EXIT
/usr/bin/python3 /usr/libexec/geowan-console/agent.py restore
/usr/bin/python3 /usr/libexec/geowan-console/agent.py collect
