import operator
from typing import TypedDict, Annotated, List, Dict, Any, Optional
from pydantic import BaseModel, Field

# --- Pydantic Models ---

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
    timestamp: str
    incident_summary: str
    action_taken: str
    human_approved: bool

# --- Shared Graph State ---

class ClusterState(TypedDict):
    events: List[Dict[str, Any]]                # Raw kubectl events & pod phases
    anomalies: List[Anomaly]                    # Detected issues
    diagnosis: str                              # LLM root cause string
    plan: Optional[RemediationPlan]             # Proposed fix
    approved: bool                              # HITL decision
    result: str                                 # Execution output
    audit_log: Annotated[List[LogEntry], operator.add]