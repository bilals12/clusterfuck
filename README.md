# clusterfuck

![Kubernetes Attack Simulation](https://img.shields.io/badge/Kubernetes-Attack_Simulation-red)
![Security Testing](https://img.shields.io/badge/Security-Testing-blue)
![Purple Team](https://img.shields.io/badge/Purple-Team-purple)

A Kubernetes attack simulation framework for testing security monitoring and detection capabilities. This toolkit deploys realistic post-exploitation techniques within containerized environments to validate whether security controls will detect real attacks.

## purpose

This framework simulates attack patterns observed in actual Kubernetes compromises, including container escapes, credential theft, cryptomining, data exfiltration, and command-and-control communications. Security teams use it to:

- Test detection coverage for container-based attacks
- Validate CSPM, EDR, and SIEM alert configurations
- Measure incident response effectiveness
- Conduct purple team exercises with realistic attack scenarios

# attack capabilities

- **Container escape**: Executes privileged container attacks with host filesystem mounting and namespace manipulation
- **Credential exfiltration**: Extracts Kubernetes service account tokens and AWS credentials from mounted secrets
- **Network reconnaissance**: Performs concurrent port scanning and cluster network mapping
- **Persistence mechanisms**: Installs cron-based persistence and demonstrates common backdoor techniques
- **Command & control**: Establishes reverse shell connections to a simulated C2 infrastructure
- **Data exfiltration**: Transfers stolen credentials and sensitive files over HTTP
- **Cryptomining**: Deploys XMRig miner with process hiding via LD_PRELOAD manipulation
- **Defense evasion**: Uses eBPF-based rootkits and anti-forensics techniques to evade detection

# prerequisites

- Kubernetes cluster (local: minikube/kind, cloud: EKS/GKE/AKS)
- `kubectl` configured with cluster-admin permissions
- Docker for building container images
- Understanding of Kubernetes security primitives and common attack vectors

# deployment

## build container images

```bash
# Package attack simulation payloads
tar -cf sim.tar dropper.sh run.sh exfil.py portscan.py

# Build and push attack simulation container
docker build -f Dockerfile.sim -t bilals12/attack-sim:latest .
docker push bilals12/attack-sim:latest

# Build and push C2 payload server
docker build -f Dockerfile.payload -t bilals12/payload-server:latest .
docker push bilals12/payload-server:latest
```

## deploy to cluster

Basic deployment without AWS credential theft simulation:

```bash
# Deploy C2 payload server
kubectl apply -f payload-server.yaml

# Deploy attack simulation pod
kubectl apply -f attack-sim-deploy.yaml

# Stream attack execution logs
kubectl logs -f sim-pod
```

Full deployment including AWS credential theft:

```bash
# Create AWS credentials secret (uses dummy credentials by default)
kubectl apply -f aws-credentials.yaml

# Deploy complete attack infrastructure
kubectl apply -f payload-server.yaml
kubectl apply -f attack-sim-deploy.yaml

# Monitor attack progression
kubectl logs -f sim-pod
```

## observe attack telemetry

```bash
# View attack execution report with timestamps and results
kubectl exec sim-pod -- cat /dev/shm/.../...HIDDEN.../report.json

# Monitor C2 server logs for exfiltration events
kubectl logs -f $(kubectl get pods -l app=payload-server -o name | head -n1)

# List files exfiltrated to C2 server
kubectl exec $(kubectl get pods -l app=payload-server -o name | head -n1) -- ls -la /payloads/uploads
```

# configuration

## attack simulation parameters

Configure these environment variables in [attack-sim-deploy.yaml](attack-sim-deploy.yaml):

| Variable | Default | Description |
|----------|---------|-------------|
| `PAYLOAD_SERVER` | `payload-server.default.svc.cluster.local` | C2 server hostname (cluster DNS) |
| `PAYLOAD_PORT` | `8080` | C2 server listening port |
| `MINER_DURATION` | `60` | Cryptominer execution time in seconds |
| `AWS_CREDENTIAL_PATH` | `/etc/bsssq-secrets/aws` | Path to mounted AWS credentials secret |

## C2 server parameters

Configure these environment variables in [payload-server.yaml](payload-server.yaml):

| Variable | Default | Description |
|----------|---------|-------------|
| `ATTACK_DEBUG` | `0` | Enable verbose logging (`1` for debug output) |

# architecture

## system components

1. **attack-sim**: Privileged pod that executes attack techniques in parallel using bash orchestration
2. **payload-server**: HTTP-based C2 server that receives exfiltrated data and serves reverse shell payloads

## attack execution flow

| Stage | Technique | Detection Signature |
|-------|-----------|---------------------|
| **Credential Theft** | Extract Kubernetes service account JWT tokens | File read on `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| **Process Hiding** | LD_PRELOAD manipulation + eBPF rootkit deployment | Suspicious shared library injection, eBPF program loading |
| **Container Escape** | Host filesystem mounting, cgroup manipulation | Privileged container syscalls, sensitive host path access |
| **Cryptomining** | XMRig miner with LD_PRELOAD-based hiding | Elevated CPU usage, connections to mining pools |
| **Port Scanning** | Concurrent TCP connection attempts across port ranges | Rapid connection attempts to multiple ports |
| **Credential Sweep** | Search for AWS credentials, kubeconfigs, SSH keys | File enumeration in sensitive directories |
| **Data Exfiltration** | HTTP POST of stolen files to C2 infrastructure | Outbound HTTP with authentication data payloads |
| **Reverse Shells** | Establish persistent C2 channels | Unexpected reverse TCP connections |

## file structure

| File | Purpose |
|------|---------|
| [dropper.sh](dropper.sh) | Stage-1 payload downloader with checksum validation |
| [run.sh](run.sh) | Main attack orchestrator executing techniques in parallel |
| [exfil.py](exfil.py) | HTTP-based exfiltration utility with retry logic |
| [portscan.py](portscan.py) | Multi-threaded TCP port scanner |
| [Dockerfile.sim](Dockerfile.sim) | Attack simulation container image build definition |
| [Dockerfile.payload](Dockerfile.payload) | C2 server container image with Flask-based HTTP server |
| [attack-sim-deploy.yaml](attack-sim-deploy.yaml) | Kubernetes pod manifest with intentionally insecure configurations |
| [payload-server.yaml](payload-server.yaml) | C2 server deployment and service definitions |
| [aws-credentials.yaml](aws-credentials.yaml) | Kubernetes secret containing dummy AWS credentials |
| [sealed-aws-credentials.yaml](sealed-aws-credentials.yaml) | SealedSecret version requiring cluster-specific sealing key |

# detection validation

This framework generates telemetry for testing security monitoring platforms. When deployed in a Wiz-monitored cluster, expect the following detection alerts:

| Attack Category | Simulated Technique | Expected Wiz Detection Rule |
|-----------------|---------------------|----------------------------|
| Container Escape | Privileged container with host path mounts | Privileged container with sensitive host path mounts |
| Credential Access | Kubernetes service account token extraction | Suspicious file access to service account token path |
| Defense Evasion | LD_PRELOAD shared library injection | Suspicious LD_PRELOAD environment variable usage |
| Cryptomining | XMRig cryptocurrency miner execution | Cryptominer process detected (XMRig signature) |
| Discovery | TCP port scanning across IP ranges | Port scanning activity from container |
| Exfiltration | HTTP exfiltration of credentials | Outbound data transfer with sensitive content |
| Command & Control | Reverse shell establishment | Reverse shell connection initiated |
| Persistence | eBPF-based rootkit loading | eBPF program loaded in container |

# security notice

**This toolkit is designed exclusively for authorized security testing in controlled environments.**

## intended use

- Purple team exercises in dedicated test clusters
- Security control validation with proper authorization
- Detection engineering and threat hunting development
- Incident response training scenarios

## scope limitations

This framework includes:
- Intentionally misconfigured privileged containers
- Simulated attack binaries (xmx2, www, noumt, pt)
- Dummy AWS credentials with no real cloud access
- C2 infrastructure for controlled exfiltration testing

## restrictions

- Only deploy in non-production, isolated test environments
- Require explicit authorization before deployment
- Do not modify for unauthorized security testing
- Ensure security monitoring is active during testing

# cleanup

Remove all attack simulation components from the cluster:

```bash
# Delete attack simulation pod
kubectl delete -f attack-sim-deploy.yaml

# Delete C2 payload server
kubectl delete -f payload-server.yaml

# Delete credential secrets
kubectl delete secret aws-credentials --ignore-not-found
kubectl delete sealedsecret aws-credentials --ignore-not-found

# Verify complete removal
kubectl get pods -l app=attack-sim
kubectl get pods -l app=payload-server
```

# troubleshooting

## payload server connection failures

**Symptom**: dropper.sh reports "Server unreachable" or connection timeout

**Resolution**:
```bash
# Verify payload server pod is running
kubectl get pods -l app=payload-server

# Check service DNS resolution
kubectl exec sim-pod -- nslookup payload-server.default.svc.cluster.local
```

## missing exfiltration data

**Symptom**: No data appears in C2 server uploads directory

**Resolution**:
```bash
# Verify NetworkPolicy allows egress to payload server
kubectl describe netpol allow-payload-access

# Check C2 server logs for connection attempts
kubectl logs -l app=payload-server
```

## cryptominer not detected

**Symptom**: Security monitoring does not alert on XMRig execution

**Resolution**: Increase miner execution time to allow detection rules to trigger:
- Edit `MINER_DURATION` to `120` in attack-sim-deploy.yaml
- Redeploy simulation pod

## sealed secret decryption errors

**Symptom**: SealedSecret fails to decrypt in target cluster

**Resolution**: Regenerate sealed secret using the target cluster's sealing key (see sealed-aws-credentials.yaml for template)

# performance metrics

Results from refactoring the original 844-line monolithic attack script:

| Metric | Original | Optimized | Improvement |
|--------|----------|-----------|-------------|
| Total execution time | ~67 seconds | ~35 seconds | 48% faster |
| Main script size | 844 lines | 161 lines | 81% reduction |
| Port scan duration | 12-20 seconds | 2 seconds | 6x faster |
| Attack parallelization | Sequential | Concurrent | Improved detection coverage |

The refactored architecture executes multiple attack techniques simultaneously, reducing overall runtime while generating more realistic attack patterns for detection testing.

# license

MIT - for educational and defensive security purposes only