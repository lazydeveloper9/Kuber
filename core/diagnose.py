import subprocess
from .state import ClusterState
from langchain_ollama import ChatOllama

# Initialize your local offline model
llm = ChatOllama(model="llama3.2", temperature=0)

RBAC_FLAG = "--as=system:serviceaccount:default:k8swhisperer-sa"
NAMESPACE = ["-n", "default"]

def get_pod_logs(pod_name: str) -> str:
    """Fetches the last 50 lines of logs. If crashing, checks previous container."""
    cmd = ["kubectl", "logs", pod_name, "--tail=50"] + NAMESPACE + [RBAC_FLAG]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        # If the pod just crashed, standard logs might be empty. Use --previous.
        if not result.stdout.strip():
            cmd_prev = ["kubectl", "logs", pod_name, "--previous", "--tail=50"] + NAMESPACE + [RBAC_FLAG]
            res_prev = subprocess.run(cmd_prev, capture_output=True, text=True, timeout=10)
            return res_prev.stdout if res_prev.returncode == 0 else "No logs found."
        return result.stdout
    except Exception as e:
        return f"Error fetching logs: {e}"

def get_pod_describe(pod_name: str) -> str:
    """Fetches describe output, truncating to the bottom to get the Events section."""
    cmd = ["kubectl", "describe", "pod", pod_name] + NAMESPACE + [RBAC_FLAG]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        # The 'Events' section is at the bottom. We slice the last 1500 chars so we don't choke the small LLM.
        return result.stdout[-1500:] if result.stdout else result.stderr
    except Exception as e:
        return f"Error fetching describe: {e}"

def diagnose_node(state: ClusterState) -> dict:
    """
    03 Diagnose: Analyzes logs and describe output to find the root cause.
    """
    print(">>> [03] Diagnosing Root Cause with Local Llama 3.2...")
    anomalies = state.get("anomalies", [])
    
    if not anomalies:
        return {"diagnosis": "Cluster is healthy. No anomalies detected."}
    
    target_pod = anomalies[0].affected_resource
    print(f"   🔍 Fetching logs and describe data for {target_pod}...")
    
    # 1. Fetch the raw data from the cluster
    logs = get_pod_logs(target_pod)
    describe_data = get_pod_describe(target_pod)
    
    # 2. Ask the local LLM to synthesize it
    prompt = f"""
    You are an expert Kubernetes Diagnostician.
    A pod named {target_pod} is failing with anomaly type: {anomalies[0].type}.
    
    Here are the recent logs from the pod:
    --- LOGS START ---
    {logs.strip()}
    --- LOGS END ---
    
    Here is the recent describe/events data:
    --- DESCRIBE START ---
    {describe_data.strip()}
    --- DESCRIBE END ---
    
    INSTRUCTIONS:
    Write a concise, plain-English 1 to 2 sentence root cause diagnosis based ONLY on the logs and events provided.
    Start your response directly with the diagnosis. Do not use introductory filler like "Based on the logs..." or "The root cause is...".
    """
    
    # Note: We do NOT use structured output here. We just want a raw string from the LLM.
    diagnosis_msg = llm.invoke(prompt)
    
    final_diagnosis = diagnosis_msg.content.strip()
    print(f"   🧠 Diagnosis: {final_diagnosis}")
    
    return {"diagnosis": final_diagnosis}