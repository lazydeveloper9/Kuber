import subprocess
import json
import time
from .state import ClusterState

RBAC_FLAG = "--as=system:serviceaccount:default:k8swhisperer-sa"
NAMESPACE = ["-n", "default"]


def run_kubectl_json(cmd_parts: list) -> dict:
    """Runs kubectl and parses JSON output."""
    cmd = ["kubectl"] + cmd_parts + NAMESPACE + ["-o", "json", RBAC_FLAG]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return {}
        return json.loads(result.stdout)
    except Exception:
        return {}


def is_pod_healthy(pod: dict) -> bool:
    """A pod is considered healthy if Running and no container is waiting in CrashLoopBackOff."""
    status = pod.get("status", {})
    if status.get("phase") != "Running":
        return False
    for container in status.get("containerStatuses", []):
        waiting = container.get("state", {}).get("waiting", {})
        if waiting.get("reason") == "CrashLoopBackOff":
            return False
    return True


def get_candidate_pods(target: str, deployment_name: str | None = None) -> list:
    """Find pods related to the target resource."""
    pods_data = run_kubectl_json(["get", "pods"])
    items = pods_data.get("items", [])
    candidates = []

    for pod in items:
        name = pod.get("metadata", {}).get("name", "")
        if name == target:
            candidates.append(pod)
        elif deployment_name and name.startswith(f"{deployment_name}-"):
            candidates.append(pod)

    return candidates


def verify_resolution(target: str, deployment_name: str | None = None) -> tuple[bool, str]:
    """Re-fetch pod state and report whether the incident appears resolved."""
    candidates = get_candidate_pods(target, deployment_name)
    if not candidates:
        return False, "No related pods found after execution."

    healthy = [pod for pod in candidates if is_pod_healthy(pod)]
    if healthy:
        names = [pod.get("metadata", {}).get("name", "unknown") for pod in healthy]
        return True, f"Resolution verified. Healthy pod(s): {', '.join(names)}"

    summaries = []
    for pod in candidates:
        meta = pod.get("metadata", {})
        status = pod.get("status", {})
        reason = status.get("reason", "")
        phase = status.get("phase", "Unknown")
        summaries.append(f"{meta.get('name', 'unknown')} phase={phase} reason={reason}")
    return False, "Pods are still unhealthy: " + "; ".join(summaries)

def execute_node(state: ClusterState) -> dict:
    """05 Execute: Runs the surgical kubectl action to remediate the anomaly."""
    print(">>> [05] Executing Remediation Plan...")
    plan = state.get("plan")
    
    if not plan:
        return {"result": "No plan to execute."}
        
    target = plan.target_resource
    action = plan.action_type
    
    try:
        if action == "patch_env":
            # Hackathon logic: K8s pods are ephemeral. To fix a pod permanently, 
            # we patch its parent Deployment. We extract the deployment name by 
            # stripping the random pod hashes (e.g., api-gateway-crash-xxx-yyy -> api-gateway-crash)
            deployment_name = "-".join(target.split("-")[:-2])
            
            print(f"   🛠️ Patching Environment Variable on Deployment: {deployment_name}...")
            
            cmd = [
                "kubectl", "set", "env", f"deployment/{deployment_name}", 
                "DB_CONNECTION_STRING=mysql://user:pass@db:3306/prod"
            ] + NAMESPACE + [RBAC_FLAG]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"   ✅ Successfully patched ENV on {deployment_name}.")
                print("   ⏳ Waiting 30 seconds for rollout/recovery...")
                time.sleep(30)
                resolved, verification_msg = verify_resolution(target, deployment_name)
                final_msg = f"Successfully patched ENV on {deployment_name}. {verification_msg}"
                print(f"   {'✅' if resolved else '⚠️'} {verification_msg}")
                return {"result": final_msg}
            else:
                err_msg = f"Failed to patch: {result.stderr.strip()}"
                print(f"   ❌ {err_msg}")
                return {"result": err_msg}
                
        elif action == "restart_pod":
            print(f"   ♻️ Deleting pod {target} to force a restart...")
            cmd = ["kubectl", "delete", "pod", target] + NAMESPACE + [RBAC_FLAG]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                err_msg = f"Failed to restart pod: {result.stderr.strip()}"
                print(f"   ❌ {err_msg}")
                return {"result": err_msg}

            print("   ⏳ Waiting 30 seconds for replacement pod to stabilize...")
            time.sleep(30)
            resolved, verification_msg = verify_resolution(target)
            final_msg = f"Pod {target} deleted for restart. {verification_msg}"
            print(f"   {'✅' if resolved else '⚠️'} {verification_msg}")
            return {"result": final_msg}
            
        else:
            return {"result": f"Action {action} is not supported yet."}
            
    except Exception as e:
        return {"result": f"Execution failed: {e}"}