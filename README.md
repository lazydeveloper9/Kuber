# ☸️ K8sWhisperer: The Air-Gapped Autonomous SRE Agent

**K8sWhisperer** is a 100% offline, AI-driven Site Reliability Engineering (SRE) agent for Kubernetes. It continuously monitors cluster state, detects anomalies, diagnoses root causes from pod logs, and executes surgical remediation plans—all without ever sending your sensitive cluster data to the cloud.

## 🚀 The Problem & Our Solution
Modern AI debugging tools require sending proprietary cluster logs and environment variables to external APIs (like OpenAI or Anthropic). This is a massive security risk for enterprise environments. 

**Our Solution:** We built an autonomous agent powered by a locally hosted **Llama 3.2 (3B)** model. By transforming dense Kubernetes JSON into structured, semantic state graphs, we allow a lightweight local LLM to perform complex deductive reasoning with zero data leaks and zero API costs.

## ✨ Key Features
* **🔒 100% Air-Gapped:** Runs entirely locally via Ollama. No API keys, no internet dependency.
* **🛡️ Zero-Trust Execution (RBAC):** The agent operates under a strict, custom `ClusterRole`. It is physically blocked by the Kubernetes API from executing destructive commands outside its predefined scope.
* **🛑 Human-in-the-Loop Safety Gate:** High-risk actions (like deleting pods or patching deployments) pause the pipeline and require manual SRE approval before execution.
* **🔄 Continuous Polling:** Scans all namespaces every 30 seconds for real-time anomaly detection (`CrashLoopBackOff`, `OOMKilled`, etc.).
* **📝 Persistent Audit Logs:** Generates a detailed `audit_log.json` explaining the *why* and *how* of every remediation action.

## 🧠 Architecture (The 6-Node Pipeline)
Instead of relying on a single, hallucination-prone prompt, K8sWhisperer uses a deterministic state graph:
1. **Observe:** Polls the Kube-API for Pods, Events, and Node states across all namespaces.
2. **Detect:** Identifies distressed resources (e.g., matching `BackOff` events).
3. **Diagnose:** Extracts and analyzes specific container logs.
4. **Plan:** The LLM drafts a structured, JSON-formatted `RemediationPlan`.
5. **Execute:** Translates the AI's plan into safe `kubectl` commands (pending human approval).
6. **Explain:** Documents the incident and resolution.

## 📂 Project Structure
```text
k8swhisperer/
├── core/
│   ├── state.py         # Pydantic data models
│   ├── observe.py       # API polling & JSON parsing
│   ├── detect.py        # Anomaly identification
│   ├── diagnose.py      # Log extraction & analysis
│   ├── plan.py          # Remediation strategy generation
│   ├── execute.py       # Rule-based kubectl execution
│   └── explain.py       # Audit logging
├── manifests/
│   ├── rbac.yaml        # Strict Security Roles
│   └── crashloop.yaml   # Demo vulnerable application
├── requirements.txt     # Python dependencies
├── run_agent.py         # Main 30s continuous loop
├── reset_demo.py        # 1-click test environment reset
└── safe_restart.py      # Graceful Minikube reboot utility
```
Blockchain Anchoring

Audit log hashes are anchored on Stellar Testnet for external integrity proof.
Includes anchor status tracking (pending, anchored, failed) and receipt verification APIs.
Blockchain Verification APIs

Verify full local hash-chain consistency.
Verify per-log on-chain receipt and memo/hash match.
Re-anchor logs when needed for recovery/retry workflows.
Compliance & Readiness Reporting

Built-in compliance report for all pipeline stages with pass/fail evidence.
Useful for demos, audits, and operational governance checks.
Smart Contract Capabilities
Smart-Contract-Ready Audit Model

Current design already produces deterministic, verifiable hash records suitable for contract-based attestation.
On-Chain Policy Automation (Extensible)

Architecture supports adding smart-contract policy enforcement, such as:
approval quorum validation,
time-locked or role-gated execution windows,
immutable on-chain compliance attestations.
Upgradeable Governance Path

Existing blockchain proof flow can be extended to a dedicated smart contract layer (e.g., Soroban/EVM-compatible) without changing core incident-response logic.

🛠️ Installation & Setup
Prerequisites
Docker Desktop (or equivalent container runtime)

Minikube & Kubectl

Ollama (Running locally)

Python 3.10+

1. Download the Local LLM
Ensure Ollama is running, then pull the required model:

Bash
```
ollama pull llama3.2
```
2. Install Dependencies
Bash
```
pip install -r requirements.txt
```
4. Prime the Cluster
Start Minikube and apply the agent's required security sandbox:

Bash
```
minikube start
```
```
kubectl apply -f manifests/rbac.yaml
```
🎮 Running the Demo
We have included a built-in demo scenario to simulate a failing application missing crucial environment variables.

1. Break the Cluster:
In a terminal, run the setup script. This applies a broken deployment and waits for it to hit a CrashLoopBackOff state.

Bash
```
python reset_demo.py
```
2. Start the Agent:
In your terminal, launch the continuous polling loop.

Bash
```
python run_agent.py
```
Watch as the agent observes the crash, diagnoses the missing DB_CONNECTION_STRING, and pauses for your approval to inject the patch!

```
***

This README acts as your project's resume. When the judges look at it, they will immediately see that you understand core DevOps concepts (like RBAC, Air-Gapping, and CI/CD pipelines) on top of the AI implementation.

Would you like to do a final "mock pitch" where I ask you a challenging question a judge might ask ab
```
UI
<img width="1913" height="908" alt="image" src="https://github.com/user-attachments/assets/ef34104f-b444-4c4b-b16e-410fdb84c929" />

<img width="1910" height="914" alt="image" src="https://github.com/user-attachments/assets/e732e6a4-fdf5-4256-88e5-74b7098cc0aa" />

<img width="1912" height="904" alt="image" src="https://github.com/user-attachments/assets/1c2ebcd6-7500-4e19-bc0f-4ba55d9917b3" />

<img width="1910" height="909" alt="Screenshot 2026-03-30 113507" src="https://github.com/user-attachments/assets/0a30c1e7-30dc-4904-b464-cd45af8fe7fd" />

<img width="1910" height="914" alt="Screenshot 2026-03-30 113348" src="https://github.com/user-attachments/assets/36b7ee6f-1fa0-433b-a922-b15084796779" />

<img width="1603" height="907" alt="Screenshot 2026-03-30 113402" src="https://github.com/user-attachments/assets/bb3e512d-ee99-49c4-960e-037a86176b31" />

