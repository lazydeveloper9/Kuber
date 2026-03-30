import base64
import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

import requests
from stellar_sdk import Asset, Keypair, Network, Server, TransactionBuilder
from langchain_ollama import ChatOllama

from .state import ClusterState, LogEntry

STELLAR_HORIZON_URL = "https://horizon-testnet.stellar.org"
FRIENDBOT_URL = "https://friendbot.stellar.org"
HASH_VERSION = "v1"
AUDIT_LOG_FILE = "audit_log.json"
AUDIT_SLACK_WEBHOOK_URL = os.getenv("AUDIT_SLACK_WEBHOOK_URL", "").strip()
REQUIRE_STELLAR_SECRET = os.getenv("K8S_STELLAR_SECRET_REQUIRED", "false").strip().lower() in {"1", "true", "yes"}

_AUDIT_LOCK = threading.Lock()
_summary_llm = ChatOllama(model="llama3.2", temperature=0)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _load_audit_logs(log_file: str = AUDIT_LOG_FILE) -> list:
    if not os.path.exists(log_file):
        return []
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except (json.JSONDecodeError, OSError):
        return []
    return []


def _save_audit_logs(logs: list, log_file: str = AUDIT_LOG_FILE) -> None:
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4)


def compute_log_hash(log_entry_dict: dict) -> str:
    canonical_payload = {
        "log_id": log_entry_dict.get("log_id"),
        "prev_log_hash": log_entry_dict.get("prev_log_hash"),
        "timestamp": log_entry_dict.get("timestamp"),
        "incident_summary": log_entry_dict.get("incident_summary"),
        "action_taken": log_entry_dict.get("action_taken"),
        "human_approved": log_entry_dict.get("human_approved"),
        "hash_version": log_entry_dict.get("hash_version", HASH_VERSION),
    }
    return hashlib.sha256(_canonical_json(canonical_payload).encode("utf-8")).hexdigest()


def _get_stellar_keypair() -> Keypair:
    secret = os.getenv("K8S_STELLAR_SECRET", "").strip()
    if secret:
        return Keypair.from_secret(secret)

    if REQUIRE_STELLAR_SECRET:
        raise RuntimeError("K8S_STELLAR_SECRET is required for deterministic blockchain identity")

    kp = Keypair.random()
    print(f"   [Stellar] Provisioning non-deterministic Testnet account: {kp.public_key}")
    requests.get(f"{FRIENDBOT_URL}/?addr={kp.public_key}", timeout=15)
    os.environ["K8S_STELLAR_SECRET"] = kp.secret
    return kp


def anchor_hash_to_stellar(log_hash: str) -> str:
    server = Server(STELLAR_HORIZON_URL)
    kp = _get_stellar_keypair()
    account = server.load_account(kp.public_key)

    tx = (
        TransactionBuilder(
            source_account=account,
            network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
            base_fee=100,
        )
        .add_hash_memo(bytes.fromhex(log_hash))
        .append_payment_op(destination=kp.public_key, asset=Asset.native(), amount="0.0000001")
        .set_timeout(30)
        .build()
    )
    tx.sign(kp)
    response = server.submit_transaction(tx)
    return response["hash"]


def _update_log_entry(log_id: str, updates: dict, log_file: str = AUDIT_LOG_FILE) -> None:
    with _AUDIT_LOCK:
        logs = _load_audit_logs(log_file)
        for item in logs:
            if item.get("log_id") == log_id:
                item.update(updates)
                break
        _save_audit_logs(logs, log_file)


def _anchor_log_background(log_id: str, log_hash: str, log_file: str = AUDIT_LOG_FILE) -> None:
    try:
        tx_hash = anchor_hash_to_stellar(log_hash)
        _update_log_entry(
            log_id,
            {
                "stellar_receipt": tx_hash,
                "anchor_status": "anchored",
                "anchored_at": datetime.now(timezone.utc).isoformat(),
                "anchor_error": None,
            },
            log_file,
        )
        print(f"   🔗 [Stellar] Anchored log_id={log_id} tx={tx_hash}")
    except Exception as e:
        _update_log_entry(
            log_id,
            {
                "anchor_status": "failed",
                "anchor_error": str(e),
                "anchored_at": datetime.now(timezone.utc).isoformat(),
            },
            log_file,
        )
        print(f"   ❌ [Stellar] Failed to anchor log_id={log_id}: {e}")


def queue_stellar_anchor_for_log(log_entry_dict: dict, log_file: str = AUDIT_LOG_FILE) -> None:
    thread = threading.Thread(
        target=_anchor_log_background,
        args=(log_entry_dict["log_id"], log_entry_dict["log_hash"], log_file),
        daemon=True,
    )
    thread.start()


def verify_stellar_receipt(log_entry_dict: dict) -> dict:
    log_hash = log_entry_dict.get("log_hash")
    tx_hash = log_entry_dict.get("stellar_receipt")
    if not log_hash:
        return {"ok": False, "reason": "missing_log_hash"}
    if not tx_hash:
        return {"ok": False, "reason": "missing_stellar_receipt"}

    server = Server(STELLAR_HORIZON_URL)
    tx = server.transactions().transaction(tx_hash).call()

    memo_type = tx.get("memo_type")
    memo_value = tx.get("memo")
    expected_memo = base64.b64encode(bytes.fromhex(log_hash)).decode("ascii")
    memo_matches = memo_type == "hash" and memo_value == expected_memo

    return {
        "ok": memo_matches,
        "reason": "ok" if memo_matches else "memo_mismatch",
        "memo_type": memo_type,
        "memo": memo_value,
        "expected_memo": expected_memo,
        "tx_hash": tx_hash,
    }


def _generate_human_summary(state: ClusterState) -> str:
    diagnosis = state.get("diagnosis", "No diagnosis")
    plan = state.get("plan")
    result = state.get("result", "No action executed")
    approved = state.get("approved", False)

    plan_text = "No remediation plan generated."
    if plan:
        plan_text = (
            f"Action={plan.action_type}, target={plan.target_resource}, "
            f"confidence={plan.confidence}, blast_radius={plan.blast_radius}."
        )

    prompt = f"""
    You are writing a clear incident audit summary for SREs.
    Keep it to 2 sentences, plain English.
    Mention: what failed, what decision was made, and execution outcome.

    Diagnosis: {diagnosis}
    Plan: {plan_text}
    Human approved: {approved}
    Execution result: {result}
    """

    try:
        msg = _summary_llm.invoke(prompt)
        content = (msg.content or "").strip()
        if content:
            return content
    except Exception:
        pass

    return f"Incident diagnosis: {diagnosis} Decision approved={approved}. Execution outcome: {result}"


def _post_structured_slack_audit(log_entry_dict: dict) -> None:
    if not AUDIT_SLACK_WEBHOOK_URL:
        return

    payload = {
        "text": "K8sWhisperer Audit Summary",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "K8sWhisperer Audit Summary"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Log ID*\n{log_entry_dict.get('log_id')}"},
                    {"type": "mrkdwn", "text": f"*Approved*\n{log_entry_dict.get('human_approved')}"},
                    {"type": "mrkdwn", "text": f"*Anchor Status*\n{log_entry_dict.get('anchor_status')}"},
                    {"type": "mrkdwn", "text": f"*Timestamp*\n{log_entry_dict.get('timestamp')}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary*\n{log_entry_dict.get('incident_summary')}"},
            },
        ],
    }
    try:
        requests.post(AUDIT_SLACK_WEBHOOK_URL, json=payload, timeout=10)
    except Exception:
        pass


def explain_node(state: ClusterState) -> dict:
    """06 Explain & Log: Writes a human-readable log and anchors immutable proof asynchronously."""
    print(">>> [06] Generating Audit Trail...")

    human_summary = _generate_human_summary(state)

    existing_logs = _load_audit_logs(AUDIT_LOG_FILE)
    prev_hash = existing_logs[-1].get("log_hash") if existing_logs else None

    log_entry = LogEntry(
        log_id=str(uuid.uuid4()),
        prev_log_hash=prev_hash,
        timestamp=datetime.now(timezone.utc).isoformat(),
        incident_summary=human_summary,
        action_taken=state.get("result", "No action executed"),
        human_approved=state.get("approved", False),
        hash_version=HASH_VERSION,
        anchor_status="pending",
    )

    entry = log_entry.model_dump()
    entry["log_hash"] = compute_log_hash(entry)

    with _AUDIT_LOCK:
        logs = _load_audit_logs(AUDIT_LOG_FILE)
        logs.append(entry)
        _save_audit_logs(logs, AUDIT_LOG_FILE)

    _post_structured_slack_audit(entry)
    queue_stellar_anchor_for_log(entry, AUDIT_LOG_FILE)
    print(f"   📝 Audit log saved to {AUDIT_LOG_FILE}! (log_id={entry['log_id']}, anchor=pending)")

    return {"audit_log": [LogEntry(**entry)]}
