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
    diagnosis = state.get("diagnosis")
    
    # Fast-path: If there's no anomaly, there's nothing to plan
    if not anomalies or not diagnosis:
        print("   ✅ No anomalies to remediate.")
        return {"plan": None, "approved": False}
        
    target_pod = anomalies[0].affected_resource
    anomaly_type = anomalies[0].type

    try:
        # Enforce the Pydantic schema for the output
        structured_llm = llm.with_structured_output(RemediationPlan)
        
        # BULLETPROOF PROMPT FOR SMALL MODELS:
        # We explicitly map the diagnosis findings to the required action types.
        prompt = f"""
        You are an autonomous Kubernetes SRE agent. Your job is to create a remediation plan.
        
        CURRENT ISSUE:
        - Target Resource: {target_pod}
        - Anomaly Type: {anomaly_type}
        - Diagnosis: {diagnosis}
        
        STRICT RULES FOR PLANNING:
        1. If the Diagnosis mentions "ENV", "environment variable", "DB_CONNECTION_STRING", or "missing":
           - action_type MUST be "patch_env"
           - blast_radius MUST be "medium"
           - confidence MUST be 0.95
        2. If the Anomaly is "OOMKilled" or Diagnosis mentions "memory":
           - action_type MUST be "patch_memory"
           - blast_radius MUST be "medium"
           - confidence MUST be 0.90
        3. For any other CrashLoopBackOff:
           - action_type MUST be "restart_pod"
           - blast_radius MUST be "low"
           - confidence MUST be 0.75
           
        INSTRUCTIONS:
        Generate the remediation plan. The `target_resource` MUST be exactly "{target_pod}".
        Ensure you only use the action_types and blast_radiuses listed above.
        """
        
        # Invoke the local model
        plan = structured_llm.invoke(prompt)
        
        if plan:
            print(f"   📋 Proposed Action: {plan.action_type}")
            print(f"   🎯 Target: {plan.target_resource}")
            print(f"   💥 Blast Radius: {plan.blast_radius} (Confidence: {plan.confidence})")
        else:
            print("   ⚠️ LLM failed to generate a valid plan.")
            
        return {"plan": plan, "approved": False}
        
    except Exception as e:
        print(f"⚠️ Local LLM plan generation failed: {e}")
        return {"plan": None, "approved": False}