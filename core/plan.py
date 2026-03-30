from .state import ClusterState, RemediationPlan
from langchain_ollama import ChatOllama

# Initialize your local offline model
llm = ChatOllama(model="llama3.2", temperature=0)

def plan_node(state: ClusterState) -> dict:
    """
    04 Plan: Local LLM proposes a RemediationPlan based on the diagnosis.
    """
    print(">>> [04] Planning Remediation with Local Llama 3.2...")
    anomalies = state.get("anomalies")
    diagnosis = state.get("diagnosis", "")
    
    # Fast-path: If there's no anomaly, there's nothing to plan
    if not anomalies:
        print("   ✅ No anomalies to remediate.")
        return {"plan": None, "approved": False}
        
    target_pod = anomalies[0].affected_resource
    anomaly_type = anomalies[0].type

    plan = None
    try:
        structured_llm = llm.with_structured_output(RemediationPlan)
        
        prompt = f"""
        You are an autonomous Kubernetes SRE agent. Your job is to create a remediation plan.
        
        CURRENT ISSUE:
        - Target Resource: {target_pod}
        - Anomaly Type: {anomaly_type}
        - Diagnosis: {diagnosis}
        
        STRICT RULES FOR PLANNING:
        1. If the Diagnosis mentions "ENV" or "missing": action_type="patch_env", blast_radius="medium", confidence=0.95
        2. If the Anomaly is "OOMKilled": action_type="patch_memory", blast_radius="medium", confidence=0.90
        3. For any other CrashLoopBackOff: action_type="restart_pod", blast_radius="low", confidence=0.75
           
        INSTRUCTIONS:
        Generate the remediation plan. The `target_resource` MUST be exactly "{target_pod}".
        Ensure you only use the action_types and blast_radiuses listed above.
        """
        
        plan = structured_llm.invoke(prompt)
    except Exception as e:
        print(f"   ⚠️ Local LLM structured output failed ({e}). Falling back to heuristics.")
        
    # BULLETPROOF FALLBACK: If LLM fails parsing, guarantee a plan so the pipeline doesn't hang
    if not plan:
        default_action = "patch_env" if "ENV" in diagnosis.upper() or "OOM" in anomaly_type.upper() else "restart_pod"
        plan = RemediationPlan(
            action_type=default_action,
            target_resource=target_pod,
            confidence=0.85,
            blast_radius="medium" if default_action == "patch_env" else "low"
        )
        
    print(f"   📋 Proposed Action: {plan.action_type}")
    print(f"   🎯 Target: {plan.target_resource}")
    print(f"   💥 Blast Radius: {plan.blast_radius} (Confidence: {plan.confidence})")
        
    return {"plan": plan, "approved": False}