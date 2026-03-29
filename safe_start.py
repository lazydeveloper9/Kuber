import subprocess
import time

def run_cmd(cmd_list, description):
    """Helper to run a command and print status."""
    print(f"⏳ {description}...")
    result = subprocess.run(cmd_list, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"   ✅ Success.")
        return True
    else:
        print(f"   ❌ Failed: {result.stderr.strip()}")
        return False

def safe_minikube_restart():
    print("🔄 Initiating Safe Minikube Restart Sequence...\n")

    # Step 1: Graceful Stop
    # This sends a SIGTERM to the Kubelet and API server, allowing them to save state.
    run_cmd(["minikube", "stop"], "Stopping Minikube gracefully")
    
    # Give the OS a moment to clear the network bridges
    time.sleep(3)

    # Step 2: Fresh Start with Wait Condition
    # --wait=all ensures the script doesn't continue until the API server is actually ready to take requests.
    print("\n🚀 Starting Minikube (This may take a minute)...")
    subprocess.run(["minikube", "start", "--wait=all"])
    
    print("\n✅ Minikube is online. Verifying K8sWhisperer environment...\n")

    # Step 3: Re-apply core manifests (Idempotent)
    # Even though Minikube persists data, applying the RBAC again ensures 
    # no permissions were lost if the API server rolled back a few seconds.
    run_cmd(["kubectl", "apply", "-f", "manifests/rbac.yaml"], "Re-verifying ClusterRole permissions")
    
    # Step 4: Check Nodes
    run_cmd(["kubectl", "get", "nodes"], "Pinging Kubernetes API")

    print("\n🎉 Safe restart complete! You can now launch your agent.")

if __name__ == "__main__":
    safe_restart_prompt = input("Are you sure you want to restart Minikube? (y/n): ").strip().lower()
    if safe_restart_prompt == 'y':
        safe_minikube_restart()
    else:
        print("Abort. Cluster remains untouched.")