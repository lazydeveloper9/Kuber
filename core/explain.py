import json
import os
from datetime import datetime, timezone
from .state import ClusterState, LogEntry

def explain_node(state: ClusterState) -> dict:
    """06 Explain & Log: Writes the final action to a persistent JSON file."""
    print(">>> [06] Generating Audit Trail...")
    
    log_entry = LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        incident_summary=state.get("diagnosis", "No diagnosis"),
        action_taken=state.get("result", "No action executed"),
        human_approved=state.get("approved", False)
    )
    
    log_file = "audit_log.json"
    existing_logs = []
    
    # --- BULLETPROOF FILE LOADING ---
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                data = json.load(f)
                # If the file accidentally contains a dict, wrap it in a list
                if isinstance(data, dict):
                    existing_logs = [data]
                elif isinstance(data, list):
                    existing_logs = data
            except json.JSONDecodeError:
                pass # Start fresh if file is corrupted
                
    # Append the new log
    existing_logs.append(log_entry.model_dump())
    
    # Save back to disk
    with open(log_file, "w") as f:
        json.dump(existing_logs, f, indent=4)
        
    print(f"   📝 Audit log saved to {log_file}!")
    
    return {"audit_log": [log_entry]}