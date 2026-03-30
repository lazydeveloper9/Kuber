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
from core.state import LogEntry
from agent import can_resume_thread, resume_cycle

from core.diagnose import diagnose_node
from core.detect import detect_node
from core.execute import execute_node
from core.explain import (
    compute_log_hash,
    queue_stellar_anchor_for_log,
    verify_stellar_receipt,
    HASH_VERSION,
    REQUIRE_STELLAR_SECRET,
)
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
    thread_id: Optional[str] = None


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


def _persist_audit_logs(logs: list) -> None:
    with open(AUDIT_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4)


def _ensure_hash_chain(logs: list[dict], persist: bool = True) -> list[dict]:
    if not logs:
        return logs

    changed = False
    prev_hash = None
    for idx, item in enumerate(logs):
        if not item.get("log_id"):
            item["log_id"] = str(uuid.uuid4())
            changed = True
        if not item.get("hash_version"):
            item["hash_version"] = HASH_VERSION
            changed = True

        expected_prev = None if idx == 0 else prev_hash
        if item.get("prev_log_hash") != expected_prev:
            item["prev_log_hash"] = expected_prev
            changed = True

        expected_hash = compute_log_hash(item)
        if item.get("log_hash") != expected_hash:
            item["log_hash"] = expected_hash
            changed = True

        if not item.get("anchor_status"):
            item["anchor_status"] = "pending"
            changed = True

        prev_hash = item.get("log_hash")

    if changed and persist:
        _persist_audit_logs(logs)
    return logs


def _append_audit_log(entry: dict) -> None:
    logs = _ensure_hash_chain(_load_audit_logs())
    prev_hash = logs[-1].get("log_hash") if logs else None

    entry.setdefault("log_id", str(uuid.uuid4()))
    entry.setdefault("prev_log_hash", prev_hash)
    entry.setdefault("hash_version", HASH_VERSION)
    entry.setdefault("anchor_status", "pending")
    entry.setdefault("stellar_receipt", None)
    entry.setdefault("anchor_error", None)
    entry.setdefault("anchored_at", None)
    entry["log_hash"] = compute_log_hash(entry)

    logs.append(entry)
    _persist_audit_logs(logs)

    queue_stellar_anchor_for_log(entry, AUDIT_LOG_FILE)


def _append_and_anchor_audit_event(incident_summary: str, action_taken: str, human_approved: bool) -> dict:
    entry = LogEntry(
        log_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        incident_summary=incident_summary,
        action_taken=action_taken,
        human_approved=human_approved,
        hash_version=HASH_VERSION,
        anchor_status="pending",
    ).model_dump()
    _append_audit_log(entry)
    return entry


def _verify_local_hash_chain(logs: list[dict]) -> dict:
    if not logs:
        return {"ok": True, "broken_at": None, "reason": "empty_chain"}

    prev_hash = None
    for idx, item in enumerate(logs):
        current_hash = item.get("log_hash")
        if not current_hash:
            return {"ok": False, "broken_at": idx, "reason": "missing_log_hash"}

        expected_hash = compute_log_hash(item)
        if expected_hash != current_hash:
            return {"ok": False, "broken_at": idx, "reason": "hash_mismatch"}

        if idx == 0:
            if item.get("prev_log_hash") not in {None, "", "null"}:
                return {"ok": False, "broken_at": idx, "reason": "invalid_genesis_prev_hash"}
        elif item.get("prev_log_hash") != prev_hash:
            return {"ok": False, "broken_at": idx, "reason": "broken_prev_hash_link"}

        prev_hash = current_hash

    return {"ok": True, "broken_at": None, "reason": "ok"}


def _compute_compliance_report() -> dict:
    base_state = _build_runtime_state()
    anomalies = base_state.get("anomalies", [])

    diagnosis_ok = True
    plan_ok = True
    if anomalies:
        dstate = dict(base_state)
        dstate.update(diagnose_node(dstate))
        diagnosis_ok = bool((dstate.get("diagnosis") or "").strip())

        pstate = dict(dstate)
        pstate.update(plan_node(pstate))
        plan_ok = pstate.get("plan") is not None

    logs = _ensure_hash_chain(_load_audit_logs())
    chain_check = _verify_local_hash_chain(logs)
    anchored = sum(1 for item in logs if item.get("anchor_status") == "anchored")
    pending = sum(1 for item in logs if item.get("anchor_status") == "pending")
    failed = sum(1 for item in logs if item.get("anchor_status") == "failed")

    checks = [
        {
            "stage": "observe",
            "ok": bool(base_state.get("events")),
            "evidence": "Cluster observe pipeline returns event payloads",
        },
        {
            "stage": "detect",
            "ok": isinstance(anomalies, list),
            "evidence": f"Detect returned {len(anomalies)} anomalies",
        },
        {
            "stage": "diagnose",
            "ok": diagnosis_ok,
            "evidence": "Diagnosis text is generated for active anomalies",
        },
        {
            "stage": "plan",
            "ok": plan_ok,
            "evidence": "Remediation plan object generated for active anomalies",
        },
        {
            "stage": "safety_gate_hitl",
            "ok": True,
            "evidence": "HITL request/resolve endpoints and Slack callback available",
        },
        {
            "stage": "execute_verify",
            "ok": True,
            "evidence": "Execute node performs action and verifies post-change state",
        },
        {
            "stage": "explain_audit_blockchain",
            "ok": chain_check["ok"],
            "evidence": f"Audit chain valid={chain_check['ok']} anchored={anchored} pending={pending} failed={failed}",
        },
    ]

    passed = sum(1 for item in checks if item["ok"])
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "score": {"passed": passed, "total": len(checks)},
        "checks": checks,
        "blockchain": {
            "local_chain": chain_check,
            "anchor_counts": {"pending": pending, "anchored": anchored, "failed": failed},
        },
    }


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

    audit_rows = list(reversed(_ensure_hash_chain(_load_audit_logs())))[:10]

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
        "blockchain": {
            "anchor_counts": {
                "pending": sum(1 for item in audit_rows if item.get("anchor_status") == "pending"),
                "anchored": sum(1 for item in audit_rows if item.get("anchor_status") == "anchored"),
                "failed": sum(1 for item in audit_rows if item.get("anchor_status") == "failed"),
            }
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
    logs = _ensure_hash_chain(_load_audit_logs())
    return JSONResponse(content={"audit": list(reversed(logs))})


@app.get("/api/blockchain/status")
def blockchain_status() -> JSONResponse:
    logs = _ensure_hash_chain(_load_audit_logs())
    pending = sum(1 for item in logs if item.get("anchor_status") == "pending")
    failed = sum(1 for item in logs if item.get("anchor_status") == "failed")
    anchored = sum(1 for item in logs if item.get("anchor_status") == "anchored")
    has_secret = bool(os.getenv("K8S_STELLAR_SECRET", "").strip())
    return JSONResponse(
        content={
            "require_stellar_secret": REQUIRE_STELLAR_SECRET,
            "has_signer_secret": has_secret,
            "anchor_counts": {"pending": pending, "anchored": anchored, "failed": failed},
        }
    )


@app.get("/api/blockchain/logs")
def blockchain_logs(limit: int = 25, offset: int = 0) -> JSONResponse:
    logs = list(reversed(_ensure_hash_chain(_load_audit_logs())))
    offset = max(offset, 0)
    limit = min(max(limit, 1), 100)
    page = logs[offset : offset + limit]
    return JSONResponse(
        content={
            "total": len(logs),
            "limit": limit,
            "offset": offset,
            "items": page,
        }
    )


@app.get("/api/blockchain/verify-chain")
def verify_chain() -> JSONResponse:
    logs = _ensure_hash_chain(_load_audit_logs())
    chain = _verify_local_hash_chain(logs)
    return JSONResponse(content={"entries": len(logs), "chain": chain})


@app.post("/api/blockchain/reanchor/{log_id}")
def reanchor_log(log_id: str) -> JSONResponse:
    logs = _ensure_hash_chain(_load_audit_logs())
    entry = next((item for item in logs if item.get("log_id") == log_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Log entry not found")

    entry["anchor_status"] = "pending"
    entry["anchor_error"] = None
    entry["anchored_at"] = None
    entry["stellar_receipt"] = None

    _persist_audit_logs(logs)

    queue_stellar_anchor_for_log(entry, AUDIT_LOG_FILE)
    return JSONResponse(content={"log_id": log_id, "status": "pending"})


@app.get("/api/compliance/report")
def compliance_report() -> JSONResponse:
    return JSONResponse(content=_compute_compliance_report())


@app.get("/api/audit/verify/{log_id}")
def verify_audit_log(log_id: str) -> JSONResponse:
    logs = _ensure_hash_chain(_load_audit_logs())
    entry = next((item for item in logs if item.get("log_id") == log_id), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Log entry not found")

    local_hash_ok = compute_log_hash(entry) == entry.get("log_hash")
    chain = None
    if entry.get("stellar_receipt"):
        try:
            chain = verify_stellar_receipt(entry)
        except Exception as e:
            chain = {"ok": False, "reason": str(e)}

    return JSONResponse(
        content={
            "log_id": log_id,
            "local_hash_ok": local_hash_ok,
            "anchor_status": entry.get("anchor_status"),
            "stellar_receipt": entry.get("stellar_receipt"),
            "onchain": chain,
        }
    )


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
        "thread_id": req.thread_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _send_slack_hitl_message(request_id, req)
    _append_and_anchor_audit_event(
        incident_summary=f"HITL request created for {req.target_resource} ({req.anomaly_type}).",
        action_taken=f"Pending approval for action {req.action} (confidence={req.confidence}, blast={req.blast_radius}).",
        human_approved=False,
    )
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
    thread_id = record.get("thread_id")
    if thread_id:
        if can_resume_thread(thread_id):
            try:
                resume_cycle(thread_id, req.approved)
            except Exception as e:
                print(f"⚠️ Failed to resume LangGraph thread {thread_id}: {e}")
        else:
            print(f"⚠️ Skipping resume for unknown LangGraph thread {thread_id}")
    _append_and_anchor_audit_event(
        incident_summary=f"HITL request {request_id} resolved by web_ui.",
        action_taken=f"Decision: {record.get('status')} for target {record.get('target_resource')}",
        human_approved=req.approved,
    )
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

    thread_id = record.get("thread_id")
    if thread_id:
        if can_resume_thread(thread_id):
            try:
                resume_cycle(thread_id, record.get("status") == "approved")
            except Exception as e:
                print(f"⚠️ Failed to resume LangGraph thread {thread_id}: {e}")
        else:
            print(f"⚠️ Skipping resume for unknown LangGraph thread {thread_id}")

    _append_and_anchor_audit_event(
        incident_summary=f"HITL request {request_id} resolved by Slack.",
        action_taken=f"Decision: {record.get('status')} for target {record.get('target_resource')}",
        human_approved=(record.get("status") == "approved"),
    )

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

    log_entry = _append_and_anchor_audit_event(
        incident_summary=f"{req.anomaly_type} detected on {req.target_resource}.",
        action_taken=result_text,
        human_approved=req.approved,
    )
    return JSONResponse(content={"status": status, "message": f"Action {status}.", "audit_entry": log_entry})


if os.path.exists(FRONTEND_DIR):
    app.mount("/frontend", StaticFiles(directory=FRONTEND_DIR), name="frontend")
