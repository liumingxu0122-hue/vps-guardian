export interface User {
  id: string
  email: string
  role: 'viewer' | 'operator' | 'admin' | 'owner'
  totp_enabled: boolean
}

export interface Host {
  id: string
  name: string
  address: string
  os_name: string | null
  location: string | null
  status: 'healthy' | 'degraded' | 'offline' | 'unknown'
  labels: Record<string, string>
  last_seen_at: string | null
}

export interface Evidence {
  source?: string
  observation?: string
  value?: unknown
  [key: string]: unknown
}

export interface Incident {
  id: string
  title: string
  fault_type: string
  severity: number
  status: 'open' | 'investigating' | 'mitigated' | 'resolved'
  confidence: number
  affected_hosts: string[]
  affected_services: string[]
  evidence: Evidence[]
  excluded_causes: string[]
  recommendations: string[]
  auto_repair_allowed: boolean
  risk: string
  verification_plan: string[]
  first_seen_at: string
  resolved_at: string | null
  timeline: Record<string, unknown>[]
}

export interface Approval {
  id: string
  incident_id: string
  action_name: string
  risk_level: number
  status: 'pending' | 'approved' | 'rejected' | 'dry_run_only' | 'executed' | 'expired'
  parameters: Record<string, unknown>
  impact: Record<string, unknown>
  recovery_point_id: string | null
  rollback_plan: string[]
  requested_at: string
  expires_at: string
  decided_at: string | null
  decided_by: string | null
}

export interface RecoveryPoint {
  id: string
  host_id: string
  service_name: string
  snapshot_id: string
  manifest: Record<string, unknown>
  checksum: string
  verified: boolean
  verified_at: string | null
  created_at: string
}

export interface AuditEntry {
  id: number
  actor_id: string | null
  action: string
  resource_type: string
  resource_id: string | null
  outcome: string
  details: Record<string, unknown>
  source_ip: string | null
  created_at: string
}

export interface ServiceSummary {
  host_id: string
  host_name: string
  kind: string
  status: 'failed' | 'observed'
  summary: string
  collected_at: string
}

export interface Overview {
  generated_at: string
  environment: {
    current: 'development' | 'test' | 'staging' | 'production'
    production_deployed: boolean
    production_status: 'deployed' | 'not_deployed'
    gate_decision: string
  }
  global_health: 'healthy' | 'degraded' | 'critical'
  hosts: {
    total: number
    healthy: number
    degraded: number
    offline: number
    unknown: number
  }
  incidents: { open: number; critical: number }
  pending_approvals: number
  verified_recovery_points: number
  recent_incidents: Array<
    Pick<Incident, 'id' | 'title' | 'status' | 'severity' | 'fault_type' | 'first_seen_at'>
  >
  recovery: {
    repository: string
    status: 'healthy' | 'degraded' | 'unknown'
    accepted_snapshot: string | null
    last_backup_at: string | null
    last_check_at: string | null
    snapshot_count: number
    restore_status: 'passed' | 'failed' | 'unknown'
    retention_policy: string
    rpo_seconds: number | null
    rto_seconds: number | null
    measurement_scope: 'staging_measured' | 'not_measured'
  }
  security: {
    uncovered_critical: number | null
    uncovered_high: number | null
    mtls: string
    crl: string
    certificate_rotation: string
    last_scan_at: string | null
    login_rate_limit: string
    totp: string
    rbac: string
    audit: string
  }
  permissions: {
    role: User['role']
    can_view_recovery: boolean
    can_view_security: boolean
    can_approve: boolean
    dangerous_actions: 'approval_required'
  }
  resource_window: '24h' | '7d'
  resource_series: Record<string, ResourcePoint[]>
  resource_series_truncated: boolean
  host_rows: OperationsHost[]
  topology: TopologyNode[]
  timeline: TimelineEntry[]
}

export interface ResourcePoint {
  at: string
  cpu_percent: number | null
  cpu_source: 'cpu_time' | 'normalized_load' | 'unavailable'
  memory_percent: number | null
  disk_percent: number | null
  network_bytes_per_second: number | null
}

export interface OperationsHost {
  id: string
  name: string
  location: string | null
  status: Host['status']
  last_heartbeat_at: string | null
  agent_serial: string | null
  certificate_status: 'valid' | 'expiring' | 'revoked' | 'missing'
  offline_queue: number
  failed_tasks: number
  queued_tasks: number
  resources: {
    cpu_percent: number | null
    cpu_source: string
    memory_percent: number | null
    disk_percent: number | null
    network_bytes_per_second: number | null
    collected_at: string | null
  }
}

export interface TopologyNode {
  id: string
  label: string
  kind: 'control' | 'gateway' | 'database' | 'web' | 'agent'
  status: Host['status']
}

export interface TimelineEntry {
  id: string
  kind: 'incident' | 'repair' | 'audit'
  severity: number
  host_id: string | null
  title: string
  status: string
  at: string
}

export interface PublicSettings {
  environment: string
  secure_cookies: boolean
  auto_create_schema: boolean
  allowed_origins: string[]
  max_incident_log_bytes: number
  login_attempts_per_10m: number
  nonce_ttl_seconds: number
  features: Record<string, boolean>
}

export interface LatestSnapshot {
  host_id: string
  collected_at: string | null
  payload: Record<string, unknown>
}
