import json
import time
import os
import urllib.error
import urllib.request
from core.observe import observe_node
from core.detect import detect_node
from core.diagnose import diagnose_node
from core.plan import plan_node
from core.execute import execute_node
from core.explain import explain_node

DESTRUCTIVE_ACTIONS = {"delete_namespace", "delete_node", "drain_node", "delete_pvc", "scale_to_zero"}
API_BASE_URL = os.getenv("K8SWHISPERER_API_BASE", "http://127.0.0.1:8000")
HITL_TIMEOUT_SECONDS = int(os.getenv("K8SWHISPERER_HITL_TIMEOUT", "300"))
HITL_POLL_SECONDS = int(os.getenv("K8SWHISPERER_HITL_POLL", "5"))

def should_auto_execute(plan) -> bool:
    """Auto-execute only when confidence and risk policy are both satisfied."""
    if not plan:
        return False
    confidence_ok = plan.confidence > 0.8
    blast_ok = str(plan.blast_radius).lower() == "low"
    non_destructive = plan.action_type not in DESTRUCTIVE_ACTIONS
    return confidence_ok and blast_ok and non_destructive

def submit_hitl_request(plan) -> str | None:
    """Submit HITL request to backend so Slack interactive flow can decide approval."""
    payload = {
        "target_resource": plan.target_resource,
        "anomaly_type": plan.action_type, # Using action_type as fallback for missing schema fields in original code
        "action": plan.action_type,
        "confidence": plan.confidence,
        "blast_radius": plan.blast_radius,
    }
    req = urllib.request.Request(
        f"{API_BASE_URL}/api/hitl/request",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body.get("request_id")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None

def wait_for_hitl_decision(request_id: str, timeout_seconds: int = HITL_TIMEOUT_SECONDS) -> bool | None:
    """Poll backend HITL status and return True/False once resolved, else None on timeout/error."""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{API_BASE_URL}/api/hitl/request/{request_id}", timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            status = body.get("status")
            if status == "approved":
                return True
            if status == "rejected":
                return False
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            return None
        time.sleep(HITL_POLL_SECONDS)
    return None

def get_hitl_approval(plan) -> bool:
    """Primary HITL route is Slack-backed API; fallback to terminal approval if unavailable."""
    request_id = submit_hitl_request(plan)
    if request_id:
        print(f"📨 HITL request sent to Slack workflow (request_id={request_id}). Waiting for decision...")
        decision = wait_for_hitl_decision(request_id)
        if decision is not None:
            return decision
        print("⚠️ HITL decision timeout/unavailable. Falling back to terminal approval.")

    choice = input("\nApprove this action? (y/n): ").strip().lower()
    return choice == "y"

def run_pipeline():
    """Runs a single iteration of the SRE pipeline."""
    state = {"events": [], "anomalies": [], "diagnosis": "", "approved": False, "result": "", "audit_log": []}
    
    state.update(observe_node(state))
    state.update(detect_node(state))
    
    if state.get("anomalies"):
        state.update(diagnose_node(state))
        state.update(plan_node(state))
        
        plan = state.get("plan")
        if plan:
            print("\n" + "!"*50)
            print("🛑 SAFETY GATE: HUMAN APPROVAL REQUIRED")
            print("!"*50)
            print(f"Action: {plan.action_type} | Target: {plan.target_resource} | Risk: {plan.blast_radius.upper()}")

            if should_auto_execute(plan):
                print("✅ Policy satisfied (confidence > 0.8, low blast radius, non-destructive). Auto-approving...")
                state["approved"] = True
            else:
                print("🧑‍⚖️ Policy requires HITL Slack approval (or fallback terminal approval).")
                state["approved"] = get_hitl_approval(plan)
                
            if state.get("approved"):
                state.update(execute_node(state))
            else:
                print("❌ Action Rejected.")
                state["result"] = "Execution aborted by human."
                
        else:
            print("   ⚠️ Pipeline aborted early: Remediation plan missing.")
            state["result"] = "Failed to generate remediation plan."
        
        # GUARANTEED AUDIT TRAIL: Now shifted OUTSIDE the conditional branches
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