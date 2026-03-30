import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core.diagnose import diagnose_node
from core.detect import detect_node
from core.execute import execute_node
from core.observe import observe_node
from core.plan import plan_node

app = FastAPI(title="K8sWhisperer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = "frontend"
AUDIT_LOG_FILE = "audit_log.json"
APPROVAL_TOKEN_ENV = "K8SWHISPERER_APPROVAL_TOKEN"
ALLOWED_EXEC_ACTIONS = {"patch_env", "restart_pod"}
K8S_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "").strip()
HITL_APPROVALS: dict[str, dict] = {}


class ResolveActionRequest(BaseModel):
    target_resource: str
    anomaly_type: str
    action: str
    approved: bool


class HitlRequestCreate(BaseModel):
    target_resource: str
    anomaly_type: str
    action: str
    confidence: float
    blast_radius: str


class HitlResolveRequest(BaseModel):
    approved: bool


def _is_approval_token_valid(provided_token: Optional[str]) -> bool:
    expected = os.getenv(APPROVAL_TOKEN_ENV, "").strip()
    if not expected:
        return True
    if not provided_token:
        return False
    return hmac.compare_digest(provided_token, expected)


def _build_runtime_state() -> dict:
    state = {
        "events": [],
        "anomalies": [],
        "diagnosis": "",
        "plan": None,
        "approved": False,
        "result": "",
        "audit_log": [],
    }
    state.update(observe_node(state))
    state.update(detect_node(state))
    return state


def _load_audit_logs() -> list:
    if not os.path.exists(AUDIT_LOG_FILE):
        return []
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except (json.JSONDecodeError, OSError):
        return []
    return []


def _append_audit_log(entry: dict) -> None:
    logs = _load_audit_logs()
    logs.append(entry)
    with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4)


def _severity_to_blast(severity: str) -> str:
    value = (severity or "MED").upper()
    if value in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if value == "LOW":
        return "LOW"
    return "MED"


def _default_action_for_type(anomaly_type: str) -> str:
    t = (anomaly_type or "").lower()
    if "oom" in t or "memory" in t:
        return "Patch deployment memory limits"
    if "crash" in t or "backoff" in t:
        return "Patch missing env vars and restart workload"
    if "pending" in t:
        return "Inspect scheduling constraints and provision capacity"
    return "Restart pod and inspect recent events"


def _send_slack_hitl_message(request_id: str, req: HitlRequestCreate) -> None:
    if not SLACK_WEBHOOK_URL:
        return

    payload = {
        "text": "K8sWhisperer HITL approval required",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "*K8sWhisperer HITL Approval Required*\n"
                        f"Target: `{req.target_resource}`\n"
                        f"Anomaly: `{req.anomaly_type}`\n"
                        f"Action: `{req.action}`\n"
                        f"Confidence: `{req.confidence}` | Blast Radius: `{req.blast_radius}`"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": "approve_action",
                        "value": request_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "style": "danger",
                        "action_id": "reject_action",
                        "value": request_id,
                    },
                ],
            },
        ],
    }
    try:
        import urllib.request

        req_obj = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_obj, timeout=10):
            pass
    except Exception:
        pass


def _resolve_hitl_request_status(request_id: str, approved: bool, actor: str) -> dict:
    record = HITL_APPROVALS.get(request_id)
    if not record:
        raise HTTPException(status_code=404, detail="HITL request not found")
    if record.get("status") != "pending":
        return record
    record["status"] = "approved" if approved else "rejected"
    record["resolved_at"] = datetime.now(timezone.utc).isoformat()
    record["resolved_by"] = actor
    return record


@app.get("/")
def index() -> FileResponse:
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="frontend/index.html not found")
    return FileResponse(index_path)


@app.get("/api/snapshot")
def get_snapshot() -> JSONResponse:
    state = _build_runtime_state()

    anomalies = state.get("anomalies", [])
    queue = []
    for anomaly in anomalies:
        queue.append(
            {
                "target": anomaly.affected_resource,
                "anomaly": anomaly.type,
                "blast": _severity_to_blast(anomaly.severity),
                "conf": f"{round(anomaly.confidence * 100)}%",
                "desc": f"Detected {anomaly.type} on {anomaly.affected_resource}.",
                "action": _default_action_for_type(anomaly.type),
                "confidence": anomaly.confidence,
                "severity": anomaly.severity,
            }
        )

    analysis = {
        "target": "No active anomaly",
        "anomaly": "Healthy",
        "desc": "No anomalies detected in the latest scan.",
        "action": "No remediation required.",
        "conf": "--",
        "blast": "LOW",
        "trafficDesc": "Cluster telemetry currently appears stable.",
        "img": "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&q=80&w=800",
    }

    if anomalies:
        state.update(diagnose_node(state))
        state.update(plan_node(state))
        diagnosis = state.get("diagnosis", "")
        plan = state.get("plan")
        first = queue[0]
        if plan:
            action_text = f"{plan.action_type} on {plan.target_resource}"
            blast = (plan.blast_radius or first["blast"]).upper()
            conf = f"{round(plan.confidence * 100)}%"
        else:
            action_text = first["action"]
            blast = first["blast"]
            conf = first["conf"]
        analysis = {
            "target": first["target"],
            "anomaly": first["anomaly"],
            "desc": diagnosis or first["desc"],
            "action": action_text,
            "conf": conf,
            "blast": blast,
            "trafficDesc": diagnosis or first["desc"],
            "img": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?auto=format&fit=crop&q=80&w=800",
        }

    events = state.get("events", [])
    pods = events[0].get("pods", []) if events else []
    nodes = events[0].get("nodes", []) if events else []
    warnings = events[0].get("recent_events", []) if events else []

    hitl_pending = []
    for request_id, record in HITL_APPROVALS.items():
        if record.get("status") == "pending":
            hitl_pending.append(
                {
                    "request_id": request_id,
                    "target": record.get("target_resource", "unknown"),
                    "anomaly": record.get("anomaly_type", "Unknown"),
                    "blast": str(record.get("blast_radius", "medium")).upper(),
                    "conf": f"{round(float(record.get('confidence', 0.0)) * 100)}%",
                    "action": record.get("action", "No action"),
                    "status": "pending",
                    "source": "hitl",
                }
            )

    audit_rows = list(reversed(_load_audit_logs()))[:10]

    terminal_logs = [
        "> [Observe] Pulling cluster state via kubectl.",
        f"> [Detect] Parsed {len(anomalies)} anomalies from local LLM output.",
        "> [Diagnose] Root-cause analysis generated for top anomaly." if anomalies else "> [Diagnose] Skipped (cluster healthy).",
        "> [Plan] Remediation plan generated." if anomalies else "> [Plan] Skipped (no anomaly).",
        "> [Safety Gate] Waiting for human approval on queued actions." if queue else "> [Safety Gate] No pending action.",
    ]

    payload = {
        "metrics": {
            "pods": len(pods),
            "nodes": len(nodes),
            "anomalies": len(queue),
            "pending": len(hitl_pending) if hitl_pending else len(queue),
            "warning_events": len(warnings),
        },
        "analysis": analysis,
        "queue": queue,
        "hitl_queue": hitl_pending,
        "audit": audit_rows,
        "terminal_logs": terminal_logs,
    }
    return JSONResponse(content=payload)


@app.get("/api/audit")
def get_audit() -> JSONResponse:
    return JSONResponse(content={"audit": list(reversed(_load_audit_logs()))})


@app.post("/api/hitl/request")
def create_hitl_request(req: HitlRequestCreate) -> JSONResponse:
    request_id = str(uuid.uuid4())
    HITL_APPROVALS[request_id] = {
        "status": "pending",
        "target_resource": req.target_resource,
        "anomaly_type": req.anomaly_type,
        "action": req.action,
        "confidence": req.confidence,
        "blast_radius": req.blast_radius,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _send_slack_hitl_message(request_id, req)
    return JSONResponse(content={"request_id": request_id, "status": "pending"})


@app.get("/api/hitl/request/{request_id}")
def get_hitl_request(request_id: str) -> JSONResponse:
    record = HITL_APPROVALS.get(request_id)
    if not record:
        raise HTTPException(status_code=404, detail="HITL request not found")
    return JSONResponse(content={"request_id": request_id, **record})


@app.get("/api/hitl/requests")
def list_hitl_requests() -> JSONResponse:
    items = [{"request_id": request_id, **record} for request_id, record in HITL_APPROVALS.items()]
    return JSONResponse(content={"items": items})


@app.post("/api/hitl/request/{request_id}/resolve")
def resolve_hitl_request(request_id: str, req: HitlResolveRequest) -> JSONResponse:
    record = _resolve_hitl_request_status(request_id, req.approved, actor="web_ui")
    return JSONResponse(content={"request_id": request_id, **record})


@app.post("/slack/interactive")
async def slack_interactive_webhook(request: Request) -> JSONResponse:
    form_data = await request.form()
    payload_str = form_data.get("payload")
    if not payload_str:
        return JSONResponse(content={"error": "No payload"}, status_code=400)

    payload = json.loads(payload_str)
    if payload.get("type") != "block_actions":
        return JSONResponse(content={"status": "ignored"})

    action = payload.get("actions", [{}])[0]
    action_id = action.get("action_id")
    request_id = action.get("value")

    try:
        record = _resolve_hitl_request_status(
            request_id,
            approved=(action_id == "approve_action"),
            actor="slack",
        )
    except HTTPException:
        return JSONResponse(content={"error": "Unknown request_id"}, status_code=404)

    return JSONResponse(content={"text": f"Action {record['status']}."})


@app.post("/api/actions/resolve")
def resolve_action(
    req: ResolveActionRequest,
    x_approval_token: Optional[str] = Header(default=None, alias="X-Approval-Token"),
) -> JSONResponse:
    if not _is_approval_token_valid(x_approval_token):
        raise HTTPException(status_code=401, detail="Invalid approval token")

    if not K8S_NAME_PATTERN.match(req.target_resource):
        raise HTTPException(status_code=400, detail="Invalid target_resource format")

    status = "approved" if req.approved else "rejected"
    result_text = f"Rejected action for {req.target_resource}"

    if req.approved:
        state = _build_runtime_state()
        anomalies = state.get("anomalies", [])
        matched = None
        for anomaly in anomalies:
            if anomaly.affected_resource == req.target_resource and anomaly.type.lower() == req.anomaly_type.lower():
                matched = anomaly
                break

        if not matched:
            raise HTTPException(status_code=409, detail="Anomaly no longer active or does not match target")

        state["anomalies"] = [matched]
        state.update(diagnose_node(state))
        state.update(plan_node(state))
        plan = state.get("plan")

        if not plan:
            raise HTTPException(status_code=409, detail="No remediation plan generated for approved anomaly")
        if plan.target_resource != req.target_resource:
            raise HTTPException(status_code=409, detail="Planned target_resource mismatch")
        if plan.action_type not in ALLOWED_EXEC_ACTIONS:
            raise HTTPException(status_code=400, detail=f"Action {plan.action_type} is not allowlisted for API execution")

        state["approved"] = True
        state.update(execute_node(state))
        result_text = state.get("result", f"Executed {plan.action_type} for {req.target_resource}")

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident_summary": f"{req.anomaly_type} detected on {req.target_resource}.",
        "action_taken": result_text,
        "human_approved": req.approved,
    }
    _append_audit_log(log_entry)
    return JSONResponse(content={"status": status, "message": f"Action {status}.", "audit_entry": log_entry})


if os.path.exists(FRONTEND_DIR):
    app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")
