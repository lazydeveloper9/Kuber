import subprocess
import json
from .state import ClusterState

RBAC_FLAG = "--as=system:serviceaccount:default:k8swhisperer-sa"
# Changed from "-n default" to "-A" for ALL namespaces
NAMESPACE_FLAG = ["-A"] 
IGNORED_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease"}
MAX_WARNING_EVENTS = 8

def run_kubectl(cmd_list: list) -> dict:
    """Helper to run kubectl commands and parse JSON."""
    cmd = ["kubectl"] + cmd_list + NAMESPACE_FLAG + ["-o", "json", RBAC_FLAG]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            print(f"   ⚠️ Error running {' '.join(cmd_list)}: {result.stderr.strip()}")
            return {}
    except Exception as e:
        print(f"   ⚠️ Exception running {' '.join(cmd_list)}: {e}")
        return {}

def observe_node(state: ClusterState) -> dict:
    """01 Observe: Polls ALL namespaces for pods, events, and nodes."""
    print(">>> [01] Observing Cluster State (All Namespaces)...")
    
    # 1. Fetch Pods across all namespaces
    pods_raw = run_kubectl(["get", "pods"])
    pods_data = []
    for item in pods_raw.get("items", []):
        meta = item.get("metadata", {})
        status = item.get("status", {})
        namespace = meta.get("namespace", "unknown")

        # Ignore noisy control-plane/system namespaces for demo clarity.
        if namespace in IGNORED_NAMESPACES:
            continue
        
        # Calculate total restarts for the pod
        restarts = 0
        for container in status.get("containerStatuses", []):
            restarts += container.get("restartCount", 0)
            
        pods_data.append({
            "name": meta.get("name", "unknown"),
            "namespace": namespace,
            "phase": status.get("phase", "unknown"),
            "restarts": restarts
        })

    # 2. Fetch Events across all namespaces
    events_raw = run_kubectl(["get", "events"])
    events_data = []
    warning_candidates = []
    for evt in events_raw.get("items", []):
        # We only care about Warnings for anomalies
        if evt.get("type") == "Warning":
            namespace = evt.get("involvedObject", {}).get("namespace")
            if namespace in IGNORED_NAMESPACES:
                continue
            warning_candidates.append({
                "reason": evt.get("reason"),
                "message": evt.get("message"),
                "resource": evt.get("involvedObject", {}).get("name"),
                "namespace": namespace,
                "timestamp": evt.get("lastTimestamp") or evt.get("eventTime") or evt.get("metadata", {}).get("creationTimestamp", "")
            })

    # Keep only the most recent warning events to avoid overwhelming the detector/planner.
    warning_candidates.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    events_data = [
        {
            "reason": evt.get("reason"),
            "message": evt.get("message"),
            "resource": evt.get("resource"),
            "namespace": evt.get("namespace"),
        }
        for evt in warning_candidates[:MAX_WARNING_EVENTS]
    ]

    # 3. Fetch Node States
    nodes_raw = run_kubectl(["get", "nodes"])
    nodes_data = []
    for node in nodes_raw.get("items", []):
        meta = node.get("metadata", {})
        status = node.get("status", {})
        
        # Find if the node is Ready
        ready_status = "Unknown"
        for condition in status.get("conditions", []):
            if condition.get("type") == "Ready":
                ready_status = condition.get("status")
                
        nodes_data.append({
            "name": meta.get("name"),
            "status": "Ready" if ready_status == "True" else "NotReady"
        })

    print(f"   ✅ Fetched {len(pods_data)} Pods, {len(events_data)} Warning Events, and {len(nodes_data)} Nodes.")

    return {"events": [{"pods": pods_data, "recent_events": events_data, "nodes": nodes_data}]}