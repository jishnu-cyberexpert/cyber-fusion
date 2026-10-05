"""
CyberFusion XDR Enterprise - Relational Schema Models
Unified Security Data Plane Models.
"""
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, BigInteger, Index
from app.core.database import Base
import time

class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=False)
    tier = Column(String(32), default="ENTERPRISE") # ENTERPRISE, MSSP, COMMERCIAL
    status = Column(String(32), default="ACTIVE")
    eps_quota = Column(Integer, default=50000)
    created_at = Column(Float, default=time.time)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=False)
    role = Column(String(64), default="TIER1_ANALYST")
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(Float, default=time.time)

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    hostname = Column(String(128), index=True, nullable=False)
    os_type = Column(String(64), nullable=False) # Windows, Linux, macOS
    os_version = Column(String(128))
    ip_address = Column(String(64), index=True)
    mac_address = Column(String(64))
    agent_version = Column(String(32), default="3.4.0")
    status = Column(String(32), default="ONLINE") # ONLINE, OFFLINE, ISOLATED
    isolation_status = Column(Boolean, default=False)
    registered_at = Column(Float, default=time.time)
    last_seen = Column(Float, default=time.time, index=True)
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    pending_tasks = Column(Text, default="[]") # JSON list of agent tasks

class SecurityEvent(Base):
    """Unified Normalized Security Telemetry (ECS / OCSF compliant)."""
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, index=True)
    event_uuid = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(Float, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    mode = Column(String(16), default="LIVE", index=True) # LIVE, LAB, DEMO
    data_source = Column(String(32), index=True) # EDR, NDR, IAM, WAF, DLP, CLOUD, SYSLOG
    category = Column(String(64), index=True) # process, network, authentication, file, dns, alert
    action = Column(String(64), index=True)
    severity = Column(String(16), default="INFORMATIONAL")
    
    # Network fields
    source_ip = Column(String(64), index=True)
    dest_ip = Column(String(64), index=True)
    source_port = Column(Integer)
    dest_port = Column(Integer)
    protocol = Column(String(16))
    
    # Endpoint / Host fields
    hostname = Column(String(128), index=True)
    user_identity = Column(String(128), index=True)
    process_name = Column(String(256), index=True)
    process_pid = Column(Integer)
    parent_process = Column(String(256))
    command_line = Column(Text)
    file_path = Column(Text)
    file_hash = Column(String(128), index=True)
    
    # Web / Cloud / DNS
    domain = Column(String(256), index=True)
    url = Column(Text)
    http_method = Column(String(16))
    http_status = Column(Integer)
    
    # Payloads
    raw_payload = Column(Text)
    normalized_payload = Column(Text) # JSON string
    is_alert = Column(Boolean, default=False)

    __table_args__ = (
        Index("idx_events_lookup", "tenant_id", "mode", "timestamp"),
        Index("idx_events_entities", "hostname", "user_identity", "source_ip"),
    )

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    mode = Column(String(16), default="LIVE", index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text)
    severity = Column(String(16), index=True, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    confidence = Column(Float, default=0.85)
    rule_id = Column(String(64), index=True)
    rule_name = Column(String(256))
    mitre_tactic = Column(String(64), index=True)
    mitre_technique = Column(String(64), index=True)
    mitre_subtechnique = Column(String(64))
    
    # Impacted Entities
    source_ip = Column(String(64))
    dest_ip = Column(String(64))
    affected_host = Column(String(128), index=True)
    affected_user = Column(String(128), index=True)
    
    event_ids = Column(Text, default="[]") # JSON list of security event uuids
    status = Column(String(32), default="NEW", index=True) # NEW, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE
    incident_id = Column(String(64), index=True)
    created_at = Column(Float, default=time.time, index=True)

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    mode = Column(String(16), default="LIVE", index=True)
    title = Column(String(256), nullable=False)
    description = Column(Text)
    severity = Column(String(16), index=True, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(32), default="OPEN", index=True) # OPEN, TRIAGE, INVESTIGATING, CONTAINED, ERADICATED, CLOSED
    assignee = Column(String(128), default="Unassigned")
    mitre_tactics = Column(Text, default="[]") # JSON list
    entities = Column(Text, default="{}") # JSON dict with hosts, users, ips, hashes
    evidence_count = Column(Integer, default=0)
    lead_alert_id = Column(String(64))
    sla_deadline = Column(Float)
    created_at = Column(Float, default=time.time, index=True)
    updated_at = Column(Float, default=time.time)
    closed_at = Column(Float)

class IncidentNote(Base):
    __tablename__ = "incident_notes"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), index=True, nullable=False)
    author = Column(String(128), nullable=False)
    note = Column(Text, nullable=False)
    timestamp = Column(Float, default=time.time)

class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(64), index=True, nullable=False)
    evidence_id = Column(String(64), unique=True, index=True)
    name = Column(String(256), nullable=False)
    evidence_type = Column(String(64)) # FILE, MEMORY_DUMP, PCAP, LOG_EXPORT, REGISTRY
    sha256_hash = Column(String(64), nullable=False)
    source_host = Column(String(128))
    collected_by = Column(String(128))
    collected_at = Column(Float, default=time.time)
    file_size_bytes = Column(BigInteger, default=0)
    custody_chain = Column(Text) # JSON log of handoffs

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(256), nullable=False)
    description = Column(Text)
    severity = Column(String(16), default="MEDIUM")
    confidence = Column(Float, default=0.90)
    rule_type = Column(String(32), default="SIGMA") # SIGMA, IOC, THRESHOLD, SEQUENCE, BEHAVIORAL
    mitre_id = Column(String(64), index=True)
    mitre_name = Column(String(128))
    mitre_tactic = Column(String(64))
    query_logic = Column(Text, nullable=False) # JSON or Sigma condition
    enabled = Column(Boolean, default=True)
    version = Column(String(16), default="1.0.0")
    author = Column(String(128), default="CyberFusion SecOps Team")
    false_positive_guidance = Column(Text)
    last_modified = Column(Float, default=time.time)

class ThreatIntelIOC(Base):
    __tablename__ = "threat_intel_iocs"
    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(32), index=True, nullable=False) # ip, domain, url, sha256, md5, cve
    value = Column(String(256), index=True, nullable=False)
    threat_actor = Column(String(128))
    campaign = Column(String(128))
    malware_family = Column(String(128))
    severity = Column(String(16), default="HIGH")
    confidence = Column(Float, default=0.95)
    source = Column(String(128), default="CyberFusion CTI Feed") # STIX/TAXII, AlienVault, MISP, Internal
    tags = Column(Text, default="[]") # JSON list
    first_seen = Column(Float, default=time.time)
    last_seen = Column(Float, default=time.time)
    expires_at = Column(Float)

class UEBAProfile(Base):
    __tablename__ = "ueba_profiles"
    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(32), index=True) # USER, HOST
    entity_id = Column(String(128), index=True)
    metric_name = Column(String(64), index=True) # login_hour, process_count_hourly, data_egress_bytes
    baseline_mean = Column(Float, default=0.0)
    baseline_std = Column(Float, default=1.0)
    sample_count = Column(Integer, default=0)
    last_updated = Column(Float, default=time.time)

class UEBAAnomaly(Base):
    __tablename__ = "ueba_anomalies"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    entity_type = Column(String(32))
    entity_id = Column(String(128), index=True)
    metric_name = Column(String(64))
    observed_value = Column(Float)
    baseline_mean = Column(Float)
    baseline_std = Column(Float)
    z_score = Column(Float)
    risk_score = Column(Float)
    explanation = Column(Text)
    timestamp = Column(Float, default=time.time, index=True)
    mode = Column(String(16), default="LIVE")

class ASMAsset(Base):
    __tablename__ = "asm_assets"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    asset_target = Column(String(256), index=True, nullable=False) # FQDN, IP, or CIDR
    asset_type = Column(String(32)) # DOMAIN, SUBDOMAIN, IP_ENDPOINT, WEB_APP, API
    resolved_ip = Column(String(64))
    open_ports = Column(Text, default="[]") # JSON list: [80, 443, 8080]
    discovered_services = Column(Text, default="[]") # JSON list
    ssl_cert_issuer = Column(String(256))
    ssl_cert_expiry = Column(String(64))
    cve_findings = Column(Text, default="[]") # JSON list
    risk_score = Column(Float, default=0.0)
    scope_authorized = Column(Boolean, default=True) # Mandatory authorized scope requirement
    last_scanned = Column(Float, default=time.time)

class CNAPPFinding(Base):
    __tablename__ = "cnapp_findings"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    cloud_provider = Column(String(32), index=True) # AWS, AZURE, GCP
    account_id = Column(String(64), index=True)
    resource_id = Column(String(256), index=True)
    resource_type = Column(String(64)) # S3, IAM_ROLE, EC2, AKS, SECURITY_GROUP
    finding_title = Column(String(256), nullable=False)
    severity = Column(String(16), default="HIGH")
    compliance_framework = Column(String(64), default="CIS-Benchmark")
    remediation_command = Column(Text)
    status = Column(String(32), default="ACTIVE")
    detected_at = Column(Float, default=time.time)

class SOARPlaybook(Base):
    __tablename__ = "soar_playbooks"
    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(String(64), unique=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(Text)
    trigger_condition = Column(Text)
    actions = Column(Text) # JSON list of actions: isolate_host, terminate_process, block_ip, notify_soc
    requires_approval = Column(Boolean, default=True)
    enabled = Column(Boolean, default=True)

class SOARActionExecution(Base):
    __tablename__ = "soar_action_executions"
    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String(64), unique=True, index=True)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    playbook_id = Column(String(64), index=True)
    incident_id = Column(String(64), index=True)
    action_type = Column(String(64), nullable=False) # ISOLATE_ENDPOINT, KILL_PROCESS, BLOCK_IP_FIREWALL, REVOKE_IAM_SESSION
    target_entity = Column(String(256), nullable=False)
    # Strictly enforce "NO FALSE CLAIMS": SUCCESS, FAILED, PENDING_APPROVAL, ACTION_NOT_EXECUTED_INTEGRATION_NOT_CONFIGURED
    status = Column(String(64), default="PENDING_APPROVAL", index=True)
    approval_status = Column(String(32), default="PENDING")
    approved_by = Column(String(128))
    execution_output = Column(Text)
    rollback_supported = Column(Boolean, default=True)
    executed_at = Column(Float)
    created_at = Column(Float, default=time.time)

class DLPPolicy(Base):
    __tablename__ = "dlp_policies"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    policy_name = Column(String(128), nullable=False)
    data_type = Column(String(64)) # CREDIT_CARD, SSN, API_KEY, CONFIDENTIAL_KEYWORD, HEALTH_DATA
    detection_regex = Column(String(256))
    enforcement_action = Column(String(32), default="ALERT") # ALERT, BLOCK, QUARANTINE
    enabled = Column(Boolean, default=True)

class AuditRecord(Base):
    __tablename__ = "audit_records"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, index=True, default=time.time)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    actor = Column(String(128), index=True, nullable=False)
    action = Column(String(128), index=True, nullable=False)
    target = Column(String(256), nullable=False)
    result = Column(String(64), nullable=False)
    source_ip = Column(String(64), default="127.0.0.1")
    approval = Column(String(128))
    previous_value = Column(Text)
    new_value = Column(Text)
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False)
    mode = Column(String(16), default="LIVE")

class CorrelatedThreat(Base):
    """
    Correlated Threat Intelligence match derived from event logs vs external security data sources.
    Zero-False-Positive filtered with mandatory Indicator of Compromise (IOC) definition.
    """
    __tablename__ = "correlated_threats"
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, default="tenant-enterprise-secops")
    mode = Column(String(16), default="LIVE", index=True)
    
    # Primary Indicator
    indicator_value = Column(String(256), index=True, nullable=False)
    indicator_type = Column(String(32), index=True, nullable=False) # ip, domain, sha256, hash
    threat_verdict = Column(String(32), index=True, default="MALICIOUS") # MALICIOUS, SUSPICIOUS
    severity = Column(String(16), index=True, default="HIGH") # CRITICAL, HIGH, MEDIUM
    confidence = Column(Float, default=0.90)
    vendor_ratio = Column(String(32)) # e.g. "14/91"
    detection_sources = Column(Text, default="[]") # JSON list of external sources
    
    # Attribution & Threat Intel
    threat_actor = Column(String(128))
    campaign = Column(String(256))
    malware_family = Column(String(128))
    mitre_tactic = Column(String(64))
    mitre_technique = Column(String(64))
    mitre_subtechnique = Column(String(128))
    
    # Comprehensive Structured IOC Definition
    ioc_definition = Column(Text, default="{}") # JSON dict
    
    # Log Correlation Metadata
    associated_events_count = Column(Integer, default=1)
    associated_event_uuids = Column(Text, default="[]") # JSON list
    associated_hosts = Column(Text, default="[]") # JSON list
    associated_processes = Column(Text, default="[]") # JSON list
    associated_users = Column(Text, default="[]") # JSON list
    first_seen = Column(Float, default=time.time, index=True)
    last_seen = Column(Float, default=time.time, index=True)
    
    # SOC Triage & State
    status = Column(String(32), default="ACTIVE", index=True) # ACTIVE, INVESTIGATING, CONTAINED, RESOLVED
    incident_id = Column(String(64), index=True)
    raw_enrichment = Column(Text, default="{}")
    created_at = Column(Float, default=time.time)
    updated_at = Column(Float, default=time.time)

    __table_args__ = (
        Index("idx_correlated_indicator", "indicator_type", "indicator_value"),
        Index("idx_correlated_tenant_mode", "tenant_id", "mode", "status"),
    )
