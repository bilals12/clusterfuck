# clusterfuck AKA kast

an attack environment for simulating realistic attack vectors against Kubernetes clusters to validate security controls and defenses.

![Kubernetes Attack Simulation](https://img.shields.io/badge/Kubernetes-Attack_Simulation-red)
![Security Testing](https://img.shields.io/badge/Security-Testing-blue)
![Purple Team](https://img.shields.io/badge/Purple-Team-purple)

## overview

clusterfuck simulates advanced container escape and privilege escalation techniques commonly used by attackers targeting Kubernetes environments. The toolkit allows security teams to:

- evaluate effectiveness of security controls
- validate detection capabilities
- test incident response procedures
- conduct purple team exercises

## key features

- **Container Escape Techniques**: Simulates privileged container attacks with host filesystem access
- **Credential Exfiltration**: Extracts and exfiltrates Kubernetes service account tokens
- **Network Reconnaissance**: Performs port scanning and network mapping 
- **Persistence Mechanisms**: Demonstrates common persistence techniques including cron jobs
- **Command & Control**: Establishes reverse shell connections to a simulated C2 server
- **Payload Delivery**: Includes a full payload server for realistic attack simulation
- **Cloud Credential Theft**: Simulates AWS credential theft (with dummy credentials)
- **Process Hiding**: Demonstrates anti-forensics techniques

## prerequisites

- kubernetes cluster (minikube, kind, EKS, GKE, etc.)
- `kubectl` configured with appropriate permissions
- basic understanding of Kubernetes security concepts

## quick start

for a minimal setup that demonstrates key attack paths:

```bash
# Deploy the payload server (C2 simulation)
kubectl apply -f payload-server.yaml

# Deploy the attack simulation pod
kubectl apply -f attack-sim-deploy.yaml

# Watch the attack simulation logs
kubectl logs -f sim-pod

# View captured data on the payload server
kubectl logs -f $(kubectl get pods -l app=payload-server -o name | head -n1)
```

advanced setup:
if you want to demonstrate AWS credential theft (this works with sealed secrets too):
```bash
# create AWS credentials secret with dummy data
kubectl apply -f aws-credentials.yaml
kubectl apply -f sealed-aws-credentials.yaml


# deploy the attack simulation
kubectl apply -f attack-sim-deploy.yaml
```

examining captured data:

```bash 
# list exfiltrated files
kubectl exec -it $(kubectl get pods -l app=payload-server -o name | head -n1) -- ls -la /payloads/uploads

# view shell connection logs
kubectl exec -it $(kubectl get pods -l app=payload-server -o name | head -n1) -- ls -la /payloads/shells

# view a specific captured file (e.g., stolen token)
kubectl exec -it $(kubectl get pods -l app=payload-server -o name | head -n1) -- cat /payloads/uploads/$(kubectl exec -it $(kubectl get pods -l app=payload-server -o name | head -n1) -- ls -t /payloads/uploads | head -1)
```

# architecture
clusterfuck consists of two main components:

1. attack simulation pod: a privileged container that executes various attack techniques

2. payload server: a simulated C2 server that receives exfiltrated data and provides reverse shell connections

the simulation follows common attack phases including:

- initial access (via privileged container)
- discovery
- credential access
- privilege escalation
- persistence
- defense evasion
- lateral movement
- data exfiltration

# security notice

this simulation contains:

- privileged container access - demonstrates container escape techniques
- dummy AWS credentials - no real cloud access is possible
- kubernetes attack techniques - for educational purposes only

⚠️ IMPORTANT: only run this simulation in isolated, non-production environments.

# customization
you can modify the environment variables in attack-sim-deploy.yaml to:

- change target server names
- adjust ports
- enable/disable cloud enumeration

# cleanup

```bash
kubectl delete -f attack-sim-deploy.yaml
kubectl delete -f payload-server.yaml
kubectl delete secret aws-credentials --ignore-not-found
```

# disclaimer
this toolkit is for educational and defensive purposes only. it should be used exclusively in environments you own or have explicit permission to test.