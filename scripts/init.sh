#!/bin/sh /etc/rc.common
START=98
USE_PROCD=0
start() {
    /usr/libexec/geowan-console/task.sh >/tmp/geowan-console-boot.log 2>&1
}
