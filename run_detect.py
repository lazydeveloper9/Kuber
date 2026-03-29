import json
import re
from langchain_ollama import ChatOllama
from langchain_core.prompts import PromptTemplate
from .state import ClusterState, AnomalyList

def detect_node(state: ClusterState) -> dict:
    """02 Detect: Analyzes cluster state for anomalies using a local LLM."""
    print(">>> [02] Detecting Anomalies with Local Llama 3.2...")
    
    events_data = state.get("events", [])
    if not events_data:
        print("   💤 No cluster data to analyze.")
        return {"anomalies": []}

    # Initialize the local model
    llm = ChatOllama(model="llama3.2", temperature=0)

    prompt = PromptTemplate.from_template(
        """You are a Kubernetes SRE. Analyze the following cluster state JSON.
        Identify any pods that are crashing, failing, or stuck.
        
        Cluster State:
        {cluster_state}
        
        Respond ONLY with a raw JSON list of anomalies. Format strictly as:
        [
            {{"target_resource": "pod-name", "type": "CrashLoopBackOff", "description": "Why it failed"}}
        ]
        If there are no anomalies, return an empty list: []
        """
    )

    chain = prompt | llm

    try:
        # 1. Ask the LLM to analyze the state
        response = chain.invoke({"cluster_state": json.dumps(events_data)})
        raw_output = response.content.strip()
        
        # 2. THE SURGICAL EXTRACTION (Regex)
        # This finds the first '[' and the last ']' and grabs everything inside
        match = re.search(r'\[.*\]', raw_output, re.DOTALL)
        
        if match:
            clean_json_string = match.group(0)
        else:
            # If no list brackets are found, assume no anomalies or bad output
            clean_json_string = "[]"

        # 3. Parse the clean string into Python objects
        parsed_json = json.loads(clean_json_string)

        # Catch weird cases where the LLM double-stringifies the JSON
        if isinstance(parsed_json, str):
            parsed_json = json.loads(parsed_json)
            
        # Ensure it's always a list before handing to Pydantic
        if isinstance(parsed_json, dict):
            parsed_json = [parsed_json]

        # 4. Pass the guaranteed Python List to Pydantic for validation
        validated_data = AnomalyList(anomalies=parsed_json)
        anomalies = validated_data.anomalies
        
        if anomalies:
            print(f"   🚨 Found {len(anomalies)} Anomaly!")
            for a in anomalies:
                print(f"      - {a.target_resource} [{a.type}]")
        else:
            print("   ✅ Cluster is healthy.")

        return {"anomalies": anomalies}

    except json.JSONDecodeError as e:
        print(f"   ⚠️ JSON Error. The LLM output was too messy: {e}")
        print(f"   --- RAW LLM OUTPUT ---\n{raw_output}\n----------------------")
        return {"anomalies": []}
    except Exception as e:
        print(f"   ⚠️ Local LLM anomaly detection failed: {e}")
        return {"anomalies": []}