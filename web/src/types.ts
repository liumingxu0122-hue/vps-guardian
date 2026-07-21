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
  data_state: 'normal' | 'no_data' | 'stale' | 'offline' | 'agent_error'
  enabled: boolean
  group_name: string | null
  tags: string[]
  labels: Record<string, string>
  last_seen_at: string | null
  enrolled_at: string | null
  disabled_at: string | null
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
  requested_by: string | null
  target_host_id: string | null
}

export interface EnrollmentToken {
  token: string
  expires_at: string
  install_command: string
}

export interface Agent {
  id: string
  host_id: string
  identity_version: number
  certificate_fingerprint: string
  certificate_serial: string | null
  revoked_at: string | null
  last_heartbeat_at: string | null
  version: string | null
}

export interface ServiceCheck {
  id: string
  name: string
  kind: 'http' | 'https' | 'tcp' | 'icmp' | 'docker' | 'systemd'
  enabled: boolean
  host_id: string | null
  runner_agent_id: string | null
  configuration: Record<string, unknown>
  group_name: string | null
  interval_seconds: number
  timeout_seconds: number
  failure_threshold: number
  recovery_threshold: number
  severity: 'info' | 'warning' | 'critical'
  last_checked_at: string | null
  created_at: string
  updated_at: string
}

export interface AlertRule {
  id: string
  name: string
  enabled: boolean
  source_type: 'service_check' | 'host_liveness' | 'agent_error'
  source_id: string
  severity: 'info' | 'warning' | 'critical'
  group_key: string
  failure_threshold: number
  recovery_threshold: number
  repeat_interval_seconds: number
  escalation_after_seconds: number | null
  recovery_notifications: boolean
  created_at: string
}

export interface Alert {
  id: string
  rule_id: string
  fingerprint: string
  state: 'ok' | 'pending' | 'firing' | 'acknowledged' | 'silenced' | 'resolved'
  consecutive_failures: number
  consecutive_successes: number
  first_observed_at: string
  last_observed_at: string
  fired_at: string | null
  acknowledged_at: string | null
  acknowledged_by: string | null
  silenced_until: string | null
  resolved_at: string | null
  last_notified_at: string | null
  notification_count: number
  summary: string
  details: Record<string, unknown>
}

export interface NotificationChannel {
  id: string
  name: string
  kind: 'telegram' | 'smtp' | 'webhook'
  enabled: boolean
  configuration: Record<string, string>
  rate_limit_per_minute: number
  created_at: string
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
  alerts: { active: number; critical: number; warning: number }
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
  agent_offline_after_seconds: number
  agent_pending_identity_ttl_minutes: number
  approval_ttl_minutes: number
  metric_retention_days: number
  service_result_retention_days: number
  max_metric_rows_per_host: number
  max_results_per_check: number
  external_notifications_enabled: boolean
  features: Record<string, boolean>
}

export interface LatestSnapshot {
  host_id: string
  collected_at: string | null
  payload: Record<string, unknown>
}
