# clusterfuck AKA kast

an attack environment for simulating realistic attack vectors against Kubernetes clusters to validate security controls and defenses.

![Kubernetes Attack Simulation](https://img.shields.io/badge/Kubernetes-Attack_Simulation-red)
![Security Testing](https://img.shields.io/badge/Security-Testing-blue)
![Purple Team](https://img.shields.io/badge/Purple-Team-purple)

# overview

clusterfuck simulates advanced container escape and privilege escalation techniques commonly used by attackers targeting Kubernetes environments. The toolkit allows security teams to:

- evaluate effectiveness of security controls
- validate detection capabilities
- test incident response procedures
- conduct purple team exercises

# key features

- **container dscape techniques**: eimulates privileged container attacks with host filesystem access
- **credential exfiltration**: extracts and exfiltrates Kubernetes service account tokens
- **network reconnaissance**: performs port scanning and network mapping 
- **persistence mechanisms**: demonstrates common persistence techniques including cron jobs
- **command & control**: establishes reverse shell connections to a simulated C2 server
- **payload delivery**: includes a full payload server for realistic attack simulation
- **cloud credential theft**: simulates AWS credential theft (with dummy or real credentials)
- **process hiding**: demonstrates anti-forensics techniques

# prerequisites

- kubernetes cluster (minikube, kind, EKS, GKE, etc.)
- `kubectl` configured with appropriate permissions
- basic understanding of Kubernetes security concepts

# quick start

## build images

```bash
# package attack sim payloads
tar -cf sim.tar dropper.sh run.sh exfil.py portscan.py

# build attack simulation image
docker build -f Dockerfile.sim -t bilals12/attack-sim:latest .
docker push bilals12/attack-sim:latest

# build payload server image
docker build -f Dockerfile.payload -t bilals12/payload-server:latest .
docker push bilals12/payload-server:latest
```

## deploy

minimal setup (no AWS credential theft demo):
```bash
# deploy payload server (C2)
kubectl apply -f payload-server.yaml

# deploy attack simulation
kubectl apply -f attack-sim-deploy.yaml

# monitor execution
kubectl logs -f sim-pod
```

advanced setup (includes AWS credential theft):
```bash
# create AWS credentials secret
kubectl apply -f aws-credentials.yaml

# deploy infrastructure
kubectl apply -f payload-server.yaml
kubectl apply -f attack-sim-deploy.yaml

# monitor logs
kubectl logs -f sim-pod
```

## monitor results

```bash
# view attack telemetry report
kubectl exec sim-pod -- cat /dev/shm/.../...HIDDEN.../report.json

# view payload server logs (exfiltration events)
kubectl logs -f $(kubectl get pods -l app=payload-server -o name | head -n1)

# list exfiltrated files
kubectl exec $(kubectl get pods -l app=payload-server -o name | head -n1) -- ls -la /payloads/uploads
```

# configuration

environment variables in [attack-sim-deploy.yaml](attack-sim-deploy.yaml):

| Variable | Default | Description |
|----------|---------|-------------|
| `PAYLOAD_SERVER` | `payload-server.default.svc.cluster.local` | C2 server hostname |
| `PAYLOAD_PORT` | `8080` | C2 server port |
| `MINER_DURATION` | `60` | Cryptominer runtime (seconds) |
| `AWS_CREDENTIAL_PATH` | `/etc/bsssq-secrets/aws` | AWS credentials mount path |

environment variables in [payload-server.yaml](payload-server.yaml):

| Variable | Default | Description |
|----------|---------|-------------|
| `ATTACK_DEBUG` | `0` | Set to `1` for verbose logging |

# architecture

## components

1. **attack-sim**: privileged pod executing attack techniques in parallel
2. **payload-server**: C2 server collecting exfiltration data and providing reverse shells

## attack stages

| Stage | Technique | Expected Detection |
|-------|-----------|-------------------|
| **Credential Theft** | K8s service account token extraction | File access on sensitive paths |
| **Process Hiding** | LD_PRELOAD + eBPF rootkit (www) | Suspicious library loading |
| **Container Escape** | Mount syscall manipulation, cgroup attacks | Privileged syscall usage |
| **Cryptomining** | XMRig execution (hidden via LD_PRELOAD) | High CPU, network to mining pool |
| **Port Scanning** | Concurrent TCP probes | Network reconnaissance activity |
| **Credential Sweep** | AWS credentials, kubeconfig, SSH keys | File enumeration patterns |
| **Data Exfiltration** | HTTP POST to C2 server | Outbound connections with file data |
| **Reverse Shells** | Multiple C2 connection methods | Unexpected outbound shells |

## files

| File | Purpose |
|------|---------|
| [dropper.sh](dropper.sh) | Initial payload downloader with validation (25 lines) |
| [run.sh](run.sh) | Main attack orchestration with parallel execution (161 lines) |
| [exfil.py](exfil.py) | Reusable exfiltration helper with retry logic (47 lines) |
| [portscan.py](portscan.py) | Concurrent port scanner (30 lines) |
| [Dockerfile.sim](Dockerfile.sim) | Attack container image definition (34 lines) |
| [Dockerfile.payload](Dockerfile.payload) | C2 server image with silent mode (120 lines) |
| [attack-sim-deploy.yaml](attack-sim-deploy.yaml) | Attack pod manifest with misconfigurations (77 lines) |
| [payload-server.yaml](payload-server.yaml) | C2 server deployment (55 lines) |
| [aws-credentials.yaml](aws-credentials.yaml) | Plain K8s secret with dummy AWS credentials |
| [sealed-aws-credentials.yaml](sealed-aws-credentials.yaml) | SealedSecret template (requires cluster sealing key) |

# expected wiz detections

when running in a Wiz-monitored cluster, expect these findings:

| Finding Type | Technique | Wiz Rule |
|--------------|-----------|----------|
| Container Escape | Privileged container + host mounts | Privileged container with sensitive host path mounts |
| Credential Access | Service account token read | Suspicious file access to K8s token path |
| Defense Evasion | LD_PRELOAD manipulation | Suspicious LD_PRELOAD usage |
| Cryptomining | XMRig execution | Cryptominer detected (XMRig) |
| Network Scan | Port enumeration | Port scanning activity detected |
| Exfiltration | HTTP POST with stolen data | Data exfiltration via HTTP |
| C2 Communication | Reverse shell connections | Reverse shell connection detected |
| Process Injection | eBPF rootkit (www binary) | eBPF program loaded |

# security notice

⚠️ **DEFENSIVE USE ONLY**: this toolkit is for validating CSPM/EDR detection capabilities in controlled environments you own or have explicit permission to test.

**Contains**:
- Privileged container configurations (deliberate misconfigurations)
- Dummy AWS credentials (no real cloud access)
- Attack simulation binaries (xmx2, www, noumt, pt)

**DO NOT**:
- Use in production environments
- Deploy without security monitoring
- Modify for malicious purposes

# cleanup

```bash
# remove attack simulation
kubectl delete -f attack-sim-deploy.yaml

# remove payload server
kubectl delete -f payload-server.yaml

# remove secrets
kubectl delete secret aws-credentials --ignore-not-found
kubectl delete sealedsecret aws-credentials --ignore-not-found

# verify cleanup
kubectl get pods -l app=attack-sim
kubectl get pods -l app=payload-server
```

# troubleshooting

**Issue**: dropper.sh fails with "Server unreachable"
- **Fix**: verify payload-server is running: `kubectl get pods -l app=payload-server`

**Issue**: no exfiltration data captured
- **Fix**: check NetworkPolicy allows egress: `kubectl describe netpol allow-payload-access`

**Issue**: miner not detected by Wiz
- **Fix**: increase `MINER_DURATION` to 120s in attack-sim-deploy.yaml

**Issue**: sealed secret decryption fails
- **Fix**: regenerate with cluster's sealing key (see sealed-aws-credentials.yaml)

# performance

refactoring results from 844-line monolithic run.sh:

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Total runtime | ~67s | ~35s | 48% faster |
| Code size (run.sh) | 844 lines | 161 lines | 81% reduction |
| Port scan duration | 12-20s | 2s | 6x faster |
| Parallel execution | No | Yes | Better detection coverage |

# license

MIT - for educational and defensive security purposes only