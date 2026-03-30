import operator
from typing import TypedDict, Annotated, List, Dict, Any, Optional
from pydantic import BaseModel, Field

class Anomaly(BaseModel):
    type: str = Field(description="e.g., CrashLoopBackOff, OOMKilled, Pending")
    severity: str = Field(description="LOW, MED, HIGH, CRITICAL")
    affected_resource: str = Field(description="Namespace/Pod name")
    confidence: float = Field(ge=0.0, le=1.0)

class AnomalyList(BaseModel):
    anomalies: List[Anomaly] = Field(default_factory=list)

class RemediationPlan(BaseModel):
    action_type: str = Field(description="e.g., restart_pod, patch_memory, delete_pod")
    target_resource: str = Field(description="Namespace/Pod name to act upon")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    blast_radius: str = Field(description="low, medium, high")

class LogEntry(BaseModel):
    log_id: Optional[str] = None
    prev_log_hash: Optional[str] = None
    timestamp: str
    incident_summary: str
    action_taken: str
    human_approved: bool
    hash_version: Optional[str] = "v1"
    log_hash: Optional[str] = None
    anchor_status: Optional[str] = "pending"  # pending | anchored | failed | skipped
    anchor_error: Optional[str] = None
    anchored_at: Optional[str] = None
    stellar_receipt: Optional[str] = None  # Added for Web3 Audit Trail

class ClusterState(TypedDict):
    events: List[Dict[str, Any]]                
    anomalies: List[Anomaly]                    
    diagnosis: str                              
    plan: Optional[RemediationPlan]             
    approved: bool                              
    hitl_resolved: bool
    result: str                                 
    audit_log: Annotated[List[LogEntry], operator.add]