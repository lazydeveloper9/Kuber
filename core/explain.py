import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from langchain_ollama import ChatOllama

try:
    from web3 import Web3
    from web3.exceptions import Web3Exception

    WEB3_AVAILABLE = True
except Exception:  # pragma: no cover - runtime environment dependent
    Web3 = None

    class Web3Exception(Exception):
        pass

    WEB3_AVAILABLE = False

from .state import ClusterState, LogEntry

HASH_VERSION = "v2"
AUDIT_LOG_FILE = "audit_log.json"
AUDIT_SIDE_DB_FILE = os.getenv("K8S_SIDE_DB_FILE", "audit_side_db.jsonl")
AUDIT_SLACK_WEBHOOK_URL = os.getenv("AUDIT_SLACK_WEBHOOK_URL", "").strip()

REQUIRE_STELLAR_SECRET = os.getenv("K8S_BLOCKCHAIN_PRIVATE_KEY_REQUIRED", "false").strip().lower() in {
    "1",
    "true",
    "yes",
}

_AUDIT_LOCK = threading.Lock()
_summary_llm = ChatOllama(model="llama3.2", temperature=0)

DEFAULT_CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "actionHash", "type": "bytes32"},
            {"internalType": "string", "name": "metadata", "type": "string"},
        ],
        "name": "recordAction",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]


class BlockchainAuditor:
    """Hashes AI remediation actions, stores full payload in Side-DB, and records hash on-chain."""

    def __init__(self) -> None:
        self.rpc_url = os.getenv("K8S_BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545").strip()
        self.chain_id = int(os.getenv("K8S_BLOCKCHAIN_CHAIN_ID", "31337"))
        self.private_key = os.getenv("K8S_BLOCKCHAIN_PRIVATE_KEY", "").strip()
        self.contract_address = os.getenv("K8S_BLOCKCHAIN_CONTRACT_ADDRESS", "").strip()
        self.abi = self._load_abi()

        self.web3: Optional[Web3] = None
        self.account = None
        self.contract = None
        self.contract_id = self.contract_address

        if WEB3_AVAILABLE and self.private_key and self.contract_address:
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if self.web3.is_connected():
                self.account = self.web3.eth.account.from_key(self.private_key)
                self.contract = self.web3.eth.contract(address=Web3.to_checksum_address(self.contract_address), abi=self.abi)

    def _load_abi(self) -> list[dict]:
        abi_raw = os.getenv("K8S_BLOCKCHAIN_CONTRACT_ABI", "").strip()
        if not abi_raw:
            return DEFAULT_CONTRACT_ABI
        try:
            abi = json.loads(abi_raw)
            if isinstance(abi, list):
                return abi
        except json.JSONDecodeError:
            pass
        return DEFAULT_CONTRACT_ABI

    def _canonical_json(self, obj: Any) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def _sha256_hex(self, payload: dict) -> str:
        return hashlib.sha256(self._canonical_json(payload).encode("utf-8")).hexdigest()

    def _side_db_append(self, payload: dict) -> str:
        os.makedirs(os.path.dirname(AUDIT_SIDE_DB_FILE) or ".", exist_ok=True)
        row = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        with open(AUDIT_SIDE_DB_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=True) + "\n")
        return AUDIT_SIDE_DB_FILE

    def notarize_action(self, plan_data: dict) -> str:
        """Hashes plan JSON, stores full payload in Side-DB, sends hash to contract, and returns tx id."""
        action_hash = self._sha256_hex(plan_data)
        side_db_ref = self._side_db_append({"plan_data": plan_data, "action_hash": action_hash})

        metadata = {
            "target_resource": plan_data.get("target_resource", "unknown"),
            "action_type": plan_data.get("action_type", "unknown"),
            "status": plan_data.get("status", "unknown"),
            "timestamp": plan_data.get("timestamp"),
            "side_db_ref": side_db_ref,
        }
        metadata_str = json.dumps(metadata, separators=(",", ":"), ensure_ascii=True)

        if REQUIRE_STELLAR_SECRET and not self.private_key:
            raise RuntimeError("K8S_BLOCKCHAIN_PRIVATE_KEY is required")

        if not WEB3_AVAILABLE or not self.web3 or not self.account or not self.contract:
            # Development fallback: no node configured, still return deterministic pseudo tx id.
            return "local-" + action_hash

        try:
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            gas_price = self.web3.eth.gas_price
            tx = self.contract.functions.recordAction(bytes.fromhex(action_hash), metadata_str).build_transaction(
                {
                    "chainId": self.chain_id,
                    "from": self.account.address,
                    "nonce": nonce,
                    "gas": 300000,
                    "gasPrice": gas_price,
                }
            )
            signed = self.account.sign_transaction(tx)
            tx_hash = self.web3.eth.send_raw_transaction(signed.raw_transaction)
            return tx_hash.hex()
        except Web3Exception as e:
            raise RuntimeError(f"Blockchain transaction failed: {e}") from e

    def verify_receipt(self, tx_id: str, expected_action_hash: str) -> dict:
        if not tx_id:
            return {"ok": False, "reason": "missing_tx_id"}

        if tx_id.startswith("local-"):
            return {
                "ok": tx_id == f"local-{expected_action_hash}",
                "reason": "ok" if tx_id == f"local-{expected_action_hash}" else "local_hash_mismatch",
                "tx_hash": tx_id,
            }

        if not self.web3:
            return {"ok": False, "reason": "web3_not_configured", "tx_hash": tx_id}

        try:
            receipt = self.web3.eth.get_transaction_receipt(tx_id)
            success = int(receipt.get("status", 0)) == 1
            return {
                "ok": success,
                "reason": "ok" if success else "tx_failed",
                "tx_hash": tx_id,
                "block_number": int(receipt.get("blockNumber", 0)),
            }
        except Exception as e:
            return {"ok": False, "reason": str(e), "tx_hash": tx_id}


def notarize_action(plan_data: dict) -> str:
    """Public helper requested by architecture spec: hashes, stores Side-DB payload, and returns tx id."""
    return BlockchainAuditor().notarize_action(plan_data)


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
    return hashlib.sha256(json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _infer_plan_data_from_log(log_entry_dict: dict) -> dict:
    return {
        "target_resource": log_entry_dict.get("target_resource", "unknown"),
        "action_type": log_entry_dict.get("action_type", "audit_action"),
        "timestamp": log_entry_dict.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "status": "approved" if log_entry_dict.get("human_approved") else "rejected",
        "log_id": log_entry_dict.get("log_id"),
        "log_hash": log_entry_dict.get("log_hash"),
    }


def _update_log_entry(log_id: str, updates: dict, log_file: str = AUDIT_LOG_FILE) -> None:
    with _AUDIT_LOCK:
        logs = _load_audit_logs(log_file)
        for item in logs:
            if item.get("log_id") == log_id:
                item.update(updates)
                break
        _save_audit_logs(logs, log_file)


def _anchor_log_background(log_id: str, log_hash: str, log_file: str = AUDIT_LOG_FILE) -> None:
    auditor = BlockchainAuditor()
    try:
        logs = _load_audit_logs(log_file)
        entry = next((item for item in logs if item.get("log_id") == log_id), None)
        if not entry:
            raise RuntimeError("log_entry_not_found")

        plan_data = _infer_plan_data_from_log(entry)
        tx_hash = auditor.notarize_action(plan_data)

        _update_log_entry(
            log_id,
            {
                "stellar_receipt": tx_hash,
                "anchor_status": "anchored",
                "anchored_at": datetime.now(timezone.utc).isoformat(),
                "anchor_error": None,
                "contract_id": auditor.contract_id,
                "action_hash": log_hash,
            },
            log_file,
        )
        print(f"   🔗 [Contract] Anchored log_id={log_id} tx={tx_hash}")
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
        print(f"   ❌ [Contract] Failed to anchor log_id={log_id}: {e}")


def queue_stellar_anchor_for_log(log_entry_dict: dict, log_file: str = AUDIT_LOG_FILE) -> None:
    thread = threading.Thread(
        target=_anchor_log_background,
        args=(log_entry_dict["log_id"], log_entry_dict["log_hash"], log_file),
        daemon=True,
    )
    thread.start()


def verify_stellar_receipt(log_entry_dict: dict) -> dict:
    tx_hash = log_entry_dict.get("stellar_receipt")
    expected_action_hash = log_entry_dict.get("log_hash")
    auditor = BlockchainAuditor()
    return auditor.verify_receipt(tx_hash, expected_action_hash)


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
    try:
        import requests

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
            ],
        }
        requests.post(AUDIT_SLACK_WEBHOOK_URL, json=payload, timeout=10)
    except Exception:
        pass


def explain_node(state: ClusterState) -> dict:
    """06 Explain & Log: Hashes action plan, stores full payload in Side-DB, notarizes hash via smart contract."""
    print(">>> [06] Generating Audit Trail...")

    human_summary = _generate_human_summary(state)

    existing_logs = _load_audit_logs(AUDIT_LOG_FILE)
    prev_hash = existing_logs[-1].get("log_hash") if existing_logs else None

    plan = state.get("plan")
    action_type = plan.action_type if plan else "unknown"
    target_resource = plan.target_resource if plan else "unknown"

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
    entry["action_type"] = action_type
    entry["target_resource"] = target_resource
    entry["log_hash"] = compute_log_hash(entry)

    with _AUDIT_LOCK:
        logs = _load_audit_logs(AUDIT_LOG_FILE)
        logs.append(entry)
        _save_audit_logs(logs, AUDIT_LOG_FILE)

    _post_structured_slack_audit(entry)
    queue_stellar_anchor_for_log(entry, AUDIT_LOG_FILE)
    print(f"   📝 Audit log saved to {AUDIT_LOG_FILE}! (log_id={entry['log_id']}, anchor=pending)")

    return {"audit_log": [LogEntry(**entry)]}
