import subprocess
from .state import ClusterState

RBAC_FLAG = "--as=system:serviceaccount:default:k8swhisperer-sa"
NAMESPACE = ["-n", "default"]

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
                success_msg = f"Successfully patched ENV on {deployment_name}."
                print(f"   ✅ {success_msg}")
                return {"result": success_msg}
            else:
                err_msg = f"Failed to patch: {result.stderr.strip()}"
                print(f"   ❌ {err_msg}")
                return {"result": err_msg}
                
        elif action == "restart_pod":
            print(f"   ♻️ Deleting pod {target} to force a restart...")
            cmd = ["kubectl", "delete", "pod", target] + NAMESPACE + [RBAC_FLAG]
            subprocess.run(cmd, capture_output=True)
            return {"result": f"Pod {target} deleted for restart."}
            
        else:
            return {"result": f"Action {action} is not supported yet."}
            
    except Exception as e:
        return {"result": f"Execution failed: {e}"}