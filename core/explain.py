import json
import os
import hashlib
import requests
from datetime import datetime, timezone
from stellar_sdk import Server, Keypair, TransactionBuilder, Network, Asset
from .state import ClusterState, LogEntry

def anchor_to_stellar(log_entry_dict: dict) -> str | None:
    """Submits a SHA-256 hash of the log to the Stellar Testnet for immutable proof."""
    print("   🌐 [Stellar] Anchoring audit log to blockchain...")
    
    # Hash the log entry (Privacy: We never put raw cluster data on-chain)
    log_str = json.dumps(log_entry_dict, sort_keys=True)
    log_hash = hashlib.sha256(log_str.encode('utf-8')).hexdigest()
    
    server = Server("https://horizon-testnet.stellar.org")
    
    # Provision Testnet account if secret doesn't exist
    secret = os.getenv("K8S_STELLAR_SECRET")
    if not secret:
        kp = Keypair.random()
        print(f"   [Stellar] Provisioning new Testnet account: {kp.public_key}")
        requests.get(f"https://friendbot.stellar.org/?addr={kp.public_key}")
        secret = kp.secret
        os.environ["K8S_STELLAR_SECRET"] = secret 
    
    kp = Keypair.from_secret(secret)
    
    try:
        account = server.load_account(kp.public_key)
        tx = (
            TransactionBuilder(
                source_account=account,
                network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
                base_fee=100,
            )
            .add_hash_memo(bytes.fromhex(log_hash))
            .append_payment_op(
                destination=kp.public_key,
                asset=Asset.native(),
                amount="0.0000001",
            )
            .set_timeout(30)
            .build()
        )
        tx.sign(kp)
        response = server.submit_transaction(tx)
        print(f"   🔗 [Stellar] Success! Cryptographic proof anchored. Hash: {response['hash']}")
        return response['hash']
        
    except Exception as e:
        print(f"   ❌ [Stellar] Failed to anchor log: {e}")
        return None

def explain_node(state: ClusterState) -> dict:
    """06 Explain & Log: Writes the final action to a persistent JSON file and Anchors to Blockchain."""
    print(">>> [06] Generating Audit Trail...")
    
    log_entry = LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        incident_summary=state.get("diagnosis", "No diagnosis"),
        action_taken=state.get("result", "No action executed"),
        human_approved=state.get("approved", False)
    )
    
    # Anchor to Stellar and update receipt
    stellar_tx_hash = anchor_to_stellar(log_entry.model_dump())
    if stellar_tx_hash:
        log_entry.stellar_receipt = stellar_tx_hash
    
    log_file = "audit_log.json"
    existing_logs = []
    
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                data = json.load(f)
                if isinstance(data, dict):
                    existing_logs = [data]
                elif isinstance(data, list):
                    existing_logs = data
            except json.JSONDecodeError:
                pass 
                
    existing_logs.append(log_entry.model_dump())
    
    with open(log_file, "w") as f:
        json.dump(existing_logs, f, indent=4)
        
    print(f"   📝 Audit log saved to {log_file}!")
    return {"audit_log": [log_entry]}