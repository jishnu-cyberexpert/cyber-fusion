export type EnvironmentMode = 'LIVE' | 'LAB' | 'DEMO';

export interface SystemHealth {
  status: string;
  uptime_seconds: number;
  system: {
    cpu_percent: number;
    memory_percent: number;
    memory_used_mb: number;
    disk_percent: number;
    disk_free_gb: number;
  };
  pipeline: {
    measured_eps: number;
    queue_depth: number;
    max_queue_size: number;
    avg_latency_ms: number;
    total_ingested: number;
    total_processed: number;
    total_dropped: number;
    total_errors: number;
    dlq_depth: number;
  };
  services: {
    fastapi_backend: string;
    sqlite_data_plane: string;
    detection_engine: string;
    xdr_correlation: string;
    active_soc_websockets: number;
  };
}

export interface SecurityEvent {
  event_uuid?: string;
  uuid?: string;
  timestamp: number;
  data_source: string;
  category: string;
  action?: string;
  hostname?: string;
  user?: string;
  user_identity?: string;
  process?: string;
  process_name?: string;
  pid?: number;
  command_line?: string;
  source_ip?: string;
  dest_ip?: string;
  dest_port?: number;
  file_path?: string;
  domain?: string;
  is_alert?: boolean;
  storage_backend?: string;
}

export interface Alert {
  alert_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  confidence: number;
  rule_id: string;
  rule_name: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_subtechnique?: string;
  source_ip?: string;
  dest_ip?: string;
  affected_host?: string;
  affected_user?: string;
  status: string;
  incident_id?: string;
  created_at: number;
}

export interface Incident {
  incident_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'TRIAGE' | 'INVESTIGATING' | 'CONTAINED' | 'ERADICATED' | 'CLOSED';
  assignee: string;
  mitre_tactics: string[];
  entities: {
    hosts?: string[];
    users?: string[];
    ips?: string[];
  };
  evidence_count: number;
  sla_deadline?: number;
  created_at: number;
  updated_at: number;
}

export interface Endpoint {
  agent_id: string;
  hostname: string;
  os_type: string;
  os_version: string;
  ip_address: string;
  mac_address: string;
  agent_version: string;
  status: 'ONLINE' | 'OFFLINE' | 'ISOLATED';
  isolation_status: boolean;
  cpu_percent: number;
  memory_percent: number;
  last_seen: number;
  last_seen_seconds_ago: number;
}

export interface ThreatIntelIOC {
  ioc_type: 'ip' | 'domain' | 'sha256' | 'url';
  value: string;
  threat_actor?: string;
  campaign?: string;
  malware_family?: string;
  severity: string;
  confidence: number;
  source: string;
  tags: string[];
}

export interface SOARPlaybook {
  playbook_id: string;
  name: string;
  description: string;
  trigger_condition: string;
  requires_approval: boolean;
  actions: string[];
}

export interface SOARActionExecution {
  execution_id: string;
  action_type: string;
  target_entity: string;
  status: string;
  approval_status: string;
  approved_by?: string;
  execution_output: string;
  executed_at?: number;
  created_at: number;
}

export interface UEBAAnomaly {
  id: number;
  entity_type: string;
  entity_id: string;
  metric_name: string;
  observed_value: number;
  baseline_mean: number;
  baseline_std: number;
  z_score: number;
  risk_score: number;
  explanation: string;
  timestamp: number;
}

export interface ASMAsset {
  id: number;
  target: string;
  type: string;
  resolved_ip?: string;
  open_ports: number[];
  ssl_cert_issuer?: string;
  ssl_cert_expiry?: string;
  risk_score: number;
  last_scanned: number;
}

export interface CNAPPFinding {
  id?: number;
  cloud_provider: string;
  account_id: string;
  resource_id: string;
  resource_type: string;
  finding_title: string;
  severity: string;
  compliance_framework: string;
  remediation_command: string;
  status: string;
}

export interface AuditRecord {
  id: number;
  timestamp: number;
  actor: string;
  action: string;
  target: string;
  result: string;
  source_ip: string;
  approval?: string;
  current_hash: string;
  prev_hash: string;
  mode: string;
}
