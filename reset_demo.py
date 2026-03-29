import os
import subprocess
import time

def reset_environment():
    print("🔄 Initiating K8sWhisperer Demo Reset...\n")

    # 1. Delete the patched deployment
    print("🧨 Destroying current deployment...")
    subprocess.run(["kubectl", "delete", "deployment", "api-gateway-crash", "-n", "default"], 
                   capture_output=True)

    # 2. Clear the AI's memory (Audit Log)
    log_file = "audit_log.json"
    if os.path.exists(log_file):
        os.remove(log_file)
        print("🧹 Cleared audit_log.json")

    # 3. Apply the broken YAML
    print("🏗️ Deploying broken API Gateway...")
    subprocess.run(["kubectl", "apply", "-f", "manifests/crashloop.yaml"], 
                   capture_output=True)

    print("\n⏳ Allowing K8s to bake the error state (Waiting 15 seconds for Restarts)...")
    time.sleep(15)

    # 4. Show the broken state to confirm
    print("\n📊 Current Pod Status:")
    subprocess.run(["kubectl", "get", "pods", "-n", "default"])
    
    print("\n✅ Demo environment reset! The cluster is screaming for help. You may now run your agent.")

if __name__ == "__main__":
    reset_environment()