# run_agent.py
import json
from core.observe import observe_node
from core.detect import detect_node
from core.diagnose import diagnose_node
from core.plan import plan_node
from core.execute import execute_node
from core.explain import explain_node

def main():
    print("🚀 Starting K8sWhisperer Autonomous Agent (Offline Mode)...\n")
    
    state = {"events": [], "anomalies": [], "diagnosis": "", "approved": False, "result": "", "audit_log": []}
    
    # 1. Pipeline Stages
    state.update(observe_node(state))
    state.update(detect_node(state))
    state.update(diagnose_node(state))
    state.update(plan_node(state))
    
    # 2. The Safety Gate (HITL)
    plan = state.get("plan")
    if plan:
        print("\n" + "!"*50)
        print("🛑 SAFETY GATE: HUMAN APPROVAL REQUIRED")
        print("!"*50)
        print(f"Action: {plan.action_type}")
        print(f"Target: {plan.target_resource}")
        print(f"Risk:   {plan.blast_radius.upper()}")
        
        # Determine if we need to pause
        if plan.blast_radius in ["medium", "high"]:
            choice = input("\nDo you approve this action? (y/n): ").strip().lower()
            if choice == 'y':
                print("✅ Action Approved by Human.")
                state["approved"] = True
            else:
                print("❌ Action Rejected. Aborting execution.")
                state["approved"] = False
                state["result"] = "Execution aborted by human."
        else:
            print("✅ Low risk action. Auto-approving...")
            state["approved"] = True
    else:
        print("No plan to execute. Skipping Safety Gate.")
        
    # 3. Final Stages
    if state.get("approved"):
        state.update(execute_node(state))
        
    state.update(explain_node(state))
    
    print("\n🎉 Pipeline Complete!")
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