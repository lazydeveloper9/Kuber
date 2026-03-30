import json
import re
from pydantic import ValidationError
from .state import ClusterState, Anomaly, AnomalyList
from langchain_ollama import ChatOllama

# Initialize your local offline model
llm = ChatOllama(model="llama3.2", temperature=0)
MAX_ANOMALIES = 3

def detect_node(state: ClusterState) -> dict:
    """
    02 Detect: Local LLM reads the normalized cluster data and classifies anomalies.
    """
    print(">>> [02] Detecting Anomalies with Local Llama 3.2...")
    events = state.get("events", [])
    
    if not events or not events[0].get("pods"):
        return {"anomalies": []}

    try:
        # Pre-chew the JSON into plain text for the small model.
        simplified_text = "CURRENT POD STATES:\n"
        for pod in events[0].get("pods", []):
            simplified_text += f"- Pod: {pod.get('name')} | Phase: {pod.get('phase')} | Restarts: {pod.get('restarts')}\n"
            
        simplified_text += "\nRECENT EVENTS:\n"
        for evt in events[0].get("recent_events", []):
            simplified_text += f"- {evt.get('reason')} on {evt.get('resource')}: {evt.get('message')}\n"

        prompt = f"""
        You are a Kubernetes SRE. Read the following cluster status and report any anomalies as JSON.

        RULES FOR ANOMALIES:
        1. If a Pod has Restarts > 0, it is a HIGH severity anomaly. The type MUST be "CrashLoopBackOff".
        2. If an Event reason is "BackOff" or "Error", it is a HIGH severity anomaly. The type MUST be "CrashLoopBackOff".

        CLUSTER STATUS:
        {simplified_text}

        INSTRUCTIONS:
        Respond with ONLY a JSON array (no markdown) of anomaly objects.
        Each object must include: type, severity, affected_resource, confidence.
        If a pod has restarts, you MUST output an anomaly.
        The affected_resource MUST be the exact name of the pod.
        If nothing is wrong, return []
        """

        response = llm.invoke(prompt)
        raw_output = (response.content or "").strip()

        # Extract JSON list even if the model wraps it with extra text.
        match = re.search(r"\[.*\]", raw_output, re.DOTALL)
        candidate = match.group(0) if match else raw_output

        parsed = json.loads(candidate) if candidate else []
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            parsed = []

        normalized = []
        allowed_severity = {"LOW", "MED", "HIGH", "CRITICAL"}
        for item in parsed:
            if not isinstance(item, dict):
                continue
            try:
                confidence = float(item.get("confidence", 0.7))
            except (TypeError, ValueError):
                confidence = 0.7

            severity = str(item.get("severity", "MED")).upper()
            if severity not in allowed_severity:
                severity = "MED"

            normalized.append(
                {
                    "type": item.get("type", "Unknown"),
                    "severity": severity,
                    "affected_resource": item.get("affected_resource") or item.get("target_resource", "unknown"),
                    "confidence": max(0.0, min(1.0, confidence)),
                }
            )

        anomalies = []
        for candidate in normalized:
            try:
                anomalies.append(Anomaly.model_validate(candidate))
            except ValidationError:
                # Skip malformed anomaly records while preserving valid detections.
                continue

        # De-duplicate and cap anomalies so planning stays deterministic and fast.
        seen = set()
        deduped = []
        for anomaly in anomalies:
            key = (anomaly.affected_resource, anomaly.type)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(anomaly)
        deduped.sort(key=lambda a: (a.severity != "HIGH", -a.confidence))
        anomalies = deduped[:MAX_ANOMALIES]

        # Final typed check for the full list shape.
        anomalies = AnomalyList(anomalies=anomalies).anomalies

        if anomalies:
            print(f"   🚨 Found {len(anomalies)} anomaly!")
            for a in anomalies:
                print(f"      - {a.type} on {a.affected_resource} (Confidence: {a.confidence})")
        else:
            print("   ✅ Cluster looks healthy.")
            
        return {"anomalies": anomalies}
        
    except json.JSONDecodeError as e:
        print(f"⚠️ Local LLM anomaly detection failed: invalid JSON from model: {e}")
        return {"anomalies": []}
    except Exception as e:
        print(f"⚠️ Local LLM anomaly detection failed: {e}")
        return {"anomalies": []}