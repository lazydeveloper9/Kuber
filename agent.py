import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.errors import NodeInterrupt

from core.detect import detect_node
from core.diagnose import diagnose_node
from core.execute import execute_node
from core.explain import explain_node
from core.observe import observe_node
from core.plan import plan_node
from core.state import ClusterState

DESTRUCTIVE_ACTIONS = {"delete_namespace", "delete_node", "drain_node", "delete_pvc", "scale_to_zero"}
API_BASE_URL = os.getenv("K8SWHISPERER_API_BASE", "http://127.0.0.1:8000")
API_FALLBACK_BASE_URL = os.getenv("K8SWHISPERER_API_FALLBACK_BASE", "http://127.0.0.1:8001")


def _should_auto_execute(plan: Any) -> bool:
    if not plan:
        return False
    confidence_ok = plan.confidence > 0.8
    blast_ok = str(plan.blast_radius).lower() == "low"
    non_destructive = plan.action_type not in DESTRUCTIVE_ACTIONS
    return confidence_ok and blast_ok and non_destructive


def _submit_hitl_request(plan: Any, thread_id: str) -> str | None:
    payload = {
        "target_resource": plan.target_resource,
        "anomaly_type": plan.action_type,
        "action": plan.action_type,
        "confidence": plan.confidence,
        "blast_radius": plan.blast_radius,
        "thread_id": thread_id,
    }
    for base in [API_BASE_URL, API_FALLBACK_BASE_URL]:
        req = urllib.request.Request(
            f"{base}/api/hitl/request",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                request_id = body.get("request_id")
                if request_id:
                    return request_id
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            continue
    return None


def observe_graph_node(state: ClusterState) -> dict:
    return observe_node(state)


def detect_graph_node(state: ClusterState) -> dict:
    return detect_node(state)


def diagnose_graph_node(state: ClusterState) -> dict:
    return diagnose_node(state)


def plan_graph_node(state: ClusterState) -> dict:
    return plan_node(state)


def safety_gate_node(state: ClusterState, config: dict) -> dict:
    print(">>> [05] Safety Gate: Evaluating policy and approval requirements...")
    plan = state.get("plan")
    if not plan:
        print("   ❌ No remediation plan available. Aborting execution path.")
        return {"approved": False, "result": "Failed to generate remediation plan."}

    if _should_auto_execute(plan):
        print("   ✅ Policy satisfied. Auto-approving low-risk action.")
        return {"approved": True}

    # Resume path: webhook/runner sets hitl_resolved + approved via checkpoint update.
    if state.get("hitl_resolved"):
        if state.get("approved"):
            print("   ✅ Human approval received. Continuing to execute stage.")
            return {"approved": True, "hitl_resolved": False}
        print("   ❌ Human rejected action. Routing to explain/audit stage.")
        return {"approved": False, "result": "Execution aborted by human.", "hitl_resolved": False}

    thread_id = config.get("configurable", {}).get("thread_id", "unknown-thread")
    request_id = _submit_hitl_request(plan, thread_id)

    if not request_id:
        # Do not stall the graph when HITL transport is unavailable.
        print("   ⚠️ HITL endpoint unavailable. Auto-rejecting and continuing to audit.")
        return {"approved": False, "result": "Execution aborted: HITL endpoint unavailable."}

    print(f"   🛑 HITL approval required. request_id={request_id}")

    approval_payload = {
        "thread_id": thread_id,
        "request_id": request_id,
        "action": plan.action_type,
        "target_resource": plan.target_resource,
        "confidence": plan.confidence,
        "blast_radius": plan.blast_radius,
        "message": "Approval required. Resume graph with true/false.",
    }
    raise NodeInterrupt(approval_payload)


def execute_graph_node(state: ClusterState) -> dict:
    return execute_node(state)


def explain_graph_node(state: ClusterState) -> dict:
    return explain_node(state)


def _detect_route(state: ClusterState) -> str:
    if state.get("anomalies"):
        return "diagnose"
    return "explain"


def _safety_route(state: ClusterState) -> str:
    if state.get("approved"):
        return "execute"
    return "explain"


def build_graph():
    graph = StateGraph(ClusterState)
    graph.add_node("observe_step", observe_graph_node)
    graph.add_node("detect_step", detect_graph_node)
    graph.add_node("diagnose_step", diagnose_graph_node)
    graph.add_node("plan_step", plan_graph_node)
    graph.add_node("safety_gate_step", safety_gate_node)
    graph.add_node("execute_step", execute_graph_node)
    graph.add_node("explain_step", explain_graph_node)

    graph.add_edge(START, "observe_step")
    graph.add_edge("observe_step", "detect_step")
    graph.add_conditional_edges("detect_step", _detect_route, {"diagnose": "diagnose_step", "explain": "explain_step"})
    graph.add_edge("diagnose_step", "plan_step")
    graph.add_edge("plan_step", "safety_gate_step")
    graph.add_conditional_edges("safety_gate_step", _safety_route, {"execute": "execute_step", "explain": "explain_step"})
    graph.add_edge("execute_step", "explain_step")
    graph.add_edge("explain_step", END)

    return graph.compile(checkpointer=MemorySaver())


k8s_agent = build_graph()


def default_state() -> ClusterState:
    return {
        "events": [],
        "anomalies": [],
        "diagnosis": "",
        "plan": None,
        "approved": False,
        "result": "",
        "audit_log": [],
        "hitl_resolved": False,
    }


def run_cycle(thread_id: str) -> dict:
    config = {"configurable": {"thread_id": thread_id}}
    return k8s_agent.invoke(default_state(), config=config)


def can_resume_thread(thread_id: str) -> bool:
    config = {"configurable": {"thread_id": thread_id}}
    try:
        state = k8s_agent.get_state(config)
        if state is None:
            return False
        values = getattr(state, "values", None)
        return bool(values)
    except Exception:
        return False


def get_pending_hitl_interrupt(thread_id: str) -> dict | None:
    config = {"configurable": {"thread_id": thread_id}}
    try:
        snapshot = k8s_agent.get_state(config)
    except Exception:
        return None
    if snapshot is None:
        return None

    tasks = getattr(snapshot, "tasks", ()) or ()
    for task in tasks:
        interrupts = getattr(task, "interrupts", ()) or ()
        for interrupt in interrupts:
            value = getattr(interrupt, "value", None)
            if isinstance(value, dict):
                return value
    return None


def resume_cycle(thread_id: str, approved: bool) -> dict:
    config = {"configurable": {"thread_id": thread_id}}
    if not can_resume_thread(thread_id):
        raise ValueError(f"Thread {thread_id} not found in checkpoint state")
    k8s_agent.update_state(config, {"approved": approved, "hitl_resolved": True}, as_node="safety_gate_step")
    return k8s_agent.invoke(None, config=config)


def wait_for_hitl_decision(request_id: str, timeout_seconds: int = 300, poll_seconds: int = 5) -> bool | None:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            for base in [API_BASE_URL, API_FALLBACK_BASE_URL]:
                try:
                    with urllib.request.urlopen(f"{base}/api/hitl/request/{request_id}", timeout=10) as resp:
                        body = json.loads(resp.read().decode("utf-8"))
                    status = body.get("status")
                    if status == "approved":
                        return True
                    if status == "rejected":
                        return False
                    break
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
                    continue
        except Exception:
            return None
        time.sleep(poll_seconds)
    return None
