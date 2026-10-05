"""
CyberFusion XDR Enterprise - Pydantic Schemas & DTOs
OCSF/ECS normalized schema definitions.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import time

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    tenant_id: str
    user: Dict[str, Any]

class LoginRequest(BaseModel):
    email: str
    password: str

class AgentRegistrationRequest(BaseModel):
    hostname: str
    os_type: str
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    agent_version: str = "3.4.0"
    tenant_id: str = "tenant-enterprise-secops"

class AgentHeartbeatRequest(BaseModel):
    agent_id: str
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    status: str = "ONLINE"
    events_queued: int = 0

class AgentCommandTask(BaseModel):
    task_id: str
    action: str # ISOLATE_ENDPOINT, DEISOLATE_ENDPOINT, KILL_PROCESS, QUARANTINE_FILE, COLLECT_EVIDENCE
    parameters: Dict[str, Any] = {}
    created_at: float = Field(default_factory=time.time)

class RawTelemetryBatch(BaseModel):
    agent_id: Optional[str] = None
    tenant_id: str = "tenant-enterprise-secops"
    data_source: str = "EDR" # EDR, NDR, IAM, WAF, DLP, CLOUD, SYSLOG
    mode: str = "LIVE" # LIVE, LAB, DEMO
    events: List[Dict[str, Any]]

class NormalizedSecurityEvent(BaseModel):
    event_uuid: str
    timestamp: float
    tenant_id: str = "tenant-enterprise-secops"
    mode: str = "LIVE"
    data_source: str
    category: str
    action: str
    severity: str = "INFORMATIONAL"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    user_identity: Optional[str] = None
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    url: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    raw_payload: Optional[str] = None
    normalized_payload: Optional[Dict[str, Any]] = None

class ThreatHuntingQuery(BaseModel):
    query_string: str # Lucene/SQL-like DSL e.g. 'process_name = "powershell.exe" AND command_line LIKE "%-enc%"'
    mode: str = "LIVE"
    time_window_minutes: int = 60
    limit: int = 100

class SOARActionRequest(BaseModel):
    incident_id: Optional[str] = None
    action_type: str # ISOLATE_ENDPOINT, KILL_PROCESS, BLOCK_IP_FIREWALL, REVOKE_IAM_SESSION
    target_entity: str # e.g. Hostname, PID, IP, Username
    parameters: Dict[str, Any] = {}
    require_approval: bool = True

class SOARApprovalRequest(BaseModel):
    execution_id: str
    approved: bool
    analyst_comment: str

class IncidentCreateRequest(BaseModel):
    title: str
    description: str
    severity: str = "HIGH"
    tenant_id: str = "tenant-enterprise-secops"
    mode: str = "LIVE"
    entities: Dict[str, Any] = {}
    mitre_tactics: List[str] = []

class IncidentNoteRequest(BaseModel):
    note: str

class ASMScanRequest(BaseModel):
    target: str # e.g. enterprise domain or IP
    scope_confirmed: bool # Must be True to respect authorized scanning requirement
