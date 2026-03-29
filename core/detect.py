import json
from .state import ClusterState, AnomalyList
from langchain_ollama import ChatOllama

# Initialize your local offline model
llm = ChatOllama(model="llama3.2", temperature=0)

def detect_node(state: ClusterState) -> dict:
    """
    02 Detect: Local LLM reads the normalized cluster data and classifies anomalies.
    """
    print(">>> [02] Detecting Anomalies with Local Llama 3.2...")
    events = state.get("events", [])
    
    if not events or not events[0].get("pods"):
        return {"anomalies": []}

    try:
        structured_llm = llm.with_structured_output(AnomalyList)
        
        # --- THE FIX: Pre-chew the JSON into plain text for the small model ---
        simplified_text = "CURRENT POD STATES:\n"
        for pod in events[0].get("pods", []):
            simplified_text += f"- Pod: {pod.get('name')} | Phase: {pod.get('phase')} | Restarts: {pod.get('restarts')}\n"
            
        simplified_text += "\nRECENT EVENTS:\n"
        for evt in events[0].get("recent_events", []):
            simplified_text += f"- {evt.get('reason')} on {evt.get('resource')}: {evt.get('message')}\n"
        # ----------------------------------------------------------------------
        
        prompt = f"""
        You are a Kubernetes SRE. Read the following cluster status and report any anomalies.

        RULES FOR ANOMALIES:
        1. If a Pod has Restarts > 0, it is a HIGH severity anomaly. The type MUST be "CrashLoopBackOff".
        2. If an Event reason is "BackOff" or "Error", it is a HIGH severity anomaly. The type MUST be "CrashLoopBackOff".

        CLUSTER STATUS:
        {simplified_text}

        INSTRUCTIONS:
        Based ONLY on the CLUSTER STATUS above, generate the structured output.
        If a pod has restarts, you MUST output an anomaly.
        The `affected_resource` MUST be the exact name of the pod.
        """
        
        anomaly_result = structured_llm.invoke(prompt)
        
        if anomaly_result and anomaly_result.anomalies:
            print(f"   🚨 Found {len(anomaly_result.anomalies)} anomaly!")
            for a in anomaly_result.anomalies:
                print(f"      - {a.type} on {a.affected_resource} (Confidence: {a.confidence})")
        else:
            print("   ✅ Cluster looks healthy.")
            
        return {"anomalies": anomaly_result.anomalies if anomaly_result else []}
        
    except Exception as e:
        print(f"⚠️ Local LLM anomaly detection failed: {e}")
        return {"anomalies": []}