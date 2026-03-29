# run_plan.py
import json
from core.observe import observe_node
from core.detect import detect_node
from core.diagnose import diagnose_node
from core.plan import plan_node

if __name__ == "__main__":
    print("--- STARTING K8S WHISPERER PIPELINE (STAGES 1-4) ---")
    
    # Stage 0: Initial State
    state = {"events": [], "anomalies": [], "diagnosis": "", "approved": False, "result": "", "audit_log": []}
    
    # Stage 1: Observe (Fetch JSON)
    state.update(observe_node(state))
    
    # Stage 2: Detect (Find Anomaly)
    state.update(detect_node(state))
    
    # Stage 3: Diagnose (Fetch Logs & Find Root Cause)
    state.update(diagnose_node(state))
    
    # Stage 4: Plan (Propose Remediation)
    state.update(plan_node(state))
    
    print("\n========================================")
    print("🎯 FINAL REMEDIATION PLAN")
    print("========================================")
    if state.get("plan"):
        # Print the Pydantic object cleanly
        print(json.dumps(state["plan"].model_dump(), indent=2))
    else:
        print("No plan generated.")