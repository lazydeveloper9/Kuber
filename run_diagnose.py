# run_diagnose.py
from core.observe import observe_node
from core.detect import detect_node
from core.diagnose import diagnose_node

if __name__ == "__main__":
    print("--- STARTING K8S WHISPERER PIPELINE ---")
    
    # Stage 0: Initial State
    state = {"events": [], "anomalies": [], "diagnosis": "", "approved": False, "result": "", "audit_log": []}
    
    # Stage 1: Observe (Fetch JSON)
    state.update(observe_node(state))
    
    # Stage 2: Detect (Find Anomaly)
    state.update(detect_node(state))
    
    # Stage 3: Diagnose (Fetch Logs & Find Root Cause)
    state.update(diagnose_node(state))
    
    print("\n========================================")
    print("🎯 FINAL PIPELINE STATE")
    print("========================================")
    print(f"Target Pod: {state['anomalies'][0].affected_resource if state['anomalies'] else 'None'}")
    print(f"Diagnosis:  {state['diagnosis']}")