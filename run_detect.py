# run_detect.py
import json
from core.observe import observe_node
from core.detect import detect_node

if __name__ == "__main__":
    print("--- STARTING OBSERVE + DETECT PIPELINE ---")
    
    # 1. Run Observe (Gets real cluster data)
    empty_state = {"events": [], "anomalies": [], "diagnosis": "", "approved": False, "result": "", "audit_log": []}
    observed_state = observe_node(empty_state)
    
    # Merge the result into our state
    current_state = {**empty_state, **observed_state}
    
    # 2. Run Detect (Passes data to Gemini)
    detection_result = detect_node(current_state)
    
    # 3. Print the final AI Output
    print("\n--- LLM STRUCTURED OUTPUT ---")
    anomalies = detection_result.get("anomalies", [])
    if anomalies:
        for anomaly in anomalies:
            # We use model_dump() to print the Pydantic object as a nice dictionary
            print(json.dumps(anomaly.model_dump(), indent=2))
    else:
        print("No anomalies detected.")