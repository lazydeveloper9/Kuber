import json
import time
from core.observe import observe_node
from core.detect import detect_node
from core.diagnose import diagnose_node
from core.plan import plan_node
from core.execute import execute_node
from core.explain import explain_node

def run_pipeline():
    """Runs a single iteration of the SRE pipeline."""
    state = {"events": [], "anomalies": [], "diagnosis": "", "approved": False, "result": "", "audit_log": []}
    
    state.update(observe_node(state))
    state.update(detect_node(state))
    
    # Only proceed to diagnose/plan if an anomaly is actually detected
    if state.get("anomalies"):
        state.update(diagnose_node(state))
        state.update(plan_node(state))
        
        plan = state.get("plan")
        if plan:
            print("\n" + "!"*50)
            print("🛑 SAFETY GATE: HUMAN APPROVAL REQUIRED")
            print("!"*50)
            print(f"Action: {plan.action_type} | Target: {plan.target_resource} | Risk: {plan.blast_radius.upper()}")
            
            if plan.blast_radius in ["medium", "high"]:
                choice = input("\nApprove this action? (y/n): ").strip().lower()
                state["approved"] = (choice == 'y')
            else:
                print("✅ Low risk. Auto-approving...")
                state["approved"] = True
                
            if state.get("approved"):
                state.update(execute_node(state))
            else:
                print("❌ Action Rejected.")
                state["result"] = "Execution aborted by human."
                
            state.update(explain_node(state))
    else:
        print("   💤 No anomalies detected. Waiting for next cycle...")

def main():
    print("🚀 Starting K8sWhisperer Autonomous Agent (Continuous Polling Mode)...\n")
    try:
        while True:
            print("\n" + "="*50)
            print("⏳ INITIATING 30-SECOND CLUSTER SCAN...")
            print("="*50)
            
            run_pipeline()
            
            print("\n⏲️ Scan complete. Sleeping for 30 seconds... (Press Ctrl+C to exit)")
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n🛑 Shutting down K8sWhisperer agent. Goodbye!")

if __name__ == "__main__":
    main()