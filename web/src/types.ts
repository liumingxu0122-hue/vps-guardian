export interface User {
  id: string
  email: string
  role: 'viewer' | 'auditor' | 'operator' | 'admin' | 'owner'
  totp_enabled: boolean
  is_active: boolean
  scopes: string[]
  last_login_at: string | null
  password_changed_at: string | null
  totp_enabled_at: string | null
  disabled_at: string | null
  must_change_password: boolean
  identity_setup_required: boolean
  created_by: string | null
  disabled_by: string | null
  created_at: string
}

export interface UserSession {
  id: string
  user_id: string
  issued_at: string
  expires_at: string
  last_seen_at: string
  idle_expires_at: string
  absolute_expires_at: string
  remember_me: boolean
  step_up_until: string | null
  revoked_at: string | null
  revoke_reason: string | null
  user_agent_summary: string
  ip_summary: string
  created_via: string
  last_activity_type: string | null
  device_name: string | null
  current: boolean
}

export interface RecoveryCodeStatus {
  remaining: number
  low: boolean
}

export interface Host {
  id: string
  name: string
  address: string
  os_name: string | null
  location: string | null
  notes: string | null
  desired_os_family: string
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

export interface PortTrafficPolicy {
  id: string
  host_id: string
  name: string
  enabled: boolean
  protocol: 'tcp' | 'udp' | 'both'
  direction: 'rx' | 'tx' | 'both'
  port_start: number
  port_end: number
  interface_name: string | null
  mode: 'monitor_only' | 'enforcing'
  quota_bytes: number | null
  reset_policy: Record<string, unknown>
  egress_rate_bps: number | null
  status: 'pending' | 'active' | 'disabled' | 'error'
  generation: number
  created_at: string
  updated_at: string
}

export interface PortTrafficRuntime {
  policy_id: string
  runtime_rule_state: string
  shaping_state: string
  counter_generation: number
  last_sample_at: string | null
  last_reset_at: string | null
  next_reset_at: string | null
  restore_error: string | null
  updated_at: string
}

export interface PortTrafficSummary {
  policy: PortTrafficPolicy
  runtime: PortTrafficRuntime | null
  current_period_rx: number | null
  current_period_tx: number | null
  current_period_total: number | null
  quota_percent: number | null
  quota_state: 'unlimited' | 'normal' | 'warning' | 'critical' | 'exhausted'
  estimated_exhaustion_at: string | null
  last_sample_at: string | null
  data_gap: boolean
  recent_events: {
    id: string
    kind: 'reset' | 'quota' | 'runtime' | 'shaping' | 'enforcement' | 'gap' | 'spike'
    state: string
    summary: string
    occurred_at: string
  }[]
}

export interface PortTrafficHistoryPoint {
  at: string
  rx_bytes: number | null
  tx_bytes: number | null
  combined_bytes: number | null
  missing_intervals: number
  discontinuity_count: number
  discontinuity_reason: string | null
}

export interface PortTrafficHistory {
  policy_id: string
  resolution: 'raw' | 'hour' | 'day'
  starts_at: string
  ends_at: string
  points: PortTrafficHistoryPoint[]
}

export interface HostPresentation {
  id: string
  name: string
  primary_address: string
  os_name: string | null
  region: string | null
  group: string | null
  provider: string | null
  purpose: string | null
  display_tags: string[]
  health: Host['status']
  data_state: Host['data_state']
  enabled: boolean
  management: 'guardian_and_komari' | 'guardian' | 'komari_only' | 'pending_enrollment'
  agent_state: 'online' | 'stale' | 'never_seen' | 'revoked' | 'not_installed'
  agent_version: string | null
  last_heartbeat_at: string | null
  last_seen_at: string | null
  enrolled_at: string | null
  data_reason: 'available' | 'no_guardian_agent' | 'never_connected' | 'pending_enrollment' | 'disabled' | 'stale' | 'agent_error'
  resource_summary: Record<string, number> | null
  technical_evidence_available: boolean
}

export interface AgentMaintenanceToken {
  id: string
  host_id: string
  kind: 'repair' | 'reinstall' | 'rotate_identity' | 'decommission'
  expires_at: string
  command: string
  status: string
}

export interface AgentMaintenanceEvent {
  status: string
  status_sequence: number
  occurred_at: string
  error_code: string | null
  error_summary: string | null
  rolled_back: boolean
}

export interface AgentMaintenanceSession {
  id: string
  host_id: string
  agent_id: string
  kind: AgentMaintenanceToken['kind']
  status: string
  source_cidr: string | null
  purge_local_state: boolean
  expected_identity_version: number
  old_identity_id: string | null
  new_identity_id: string | null
  approval_id: string | null
  expires_at: string
  completed_at: string | null
  error_code: string | null
  error_summary: string | null
  rolled_back: boolean
  events: AgentMaintenanceEvent[]
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
  status: 'open' | 'acknowledged' | 'investigating' | 'mitigating' | 'resolved'
  assigned_to: string | null
  acknowledged_at: string | null
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
  updated_at: string
  resolved_at: string | null
  resolution_summary: string | null
  postmortem: string | null
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

export type ApprovalStatus =
  | 'pending'
  | 'approved'
  | 'partially_approved'
  | 'approved_with_conditions'
  | 'changes_requested'
  | 'rejected'
  | 'dry_run_only'
  | 'executing'
  | 'executed'
  | 'failed'
  | 'rolled_back'
  | 'expired'
  | 'withdrawn'

export interface ApprovalActor {
  label: string
  role: string | null
}

export interface ApprovalTarget {
  host: string | null
  service: string | null
  scope: string | null
}

export interface ApprovalSummary {
  id: string
  incident_id: string
  action_name: string
  status: ApprovalStatus
  risk_level: number
  target: ApprovalTarget
  requester: ApprovalActor | null
  requested_at: string
  expires_at: string
  progress_label: string
  execution_status: string | null
}

export interface ApprovalFact {
  key: string
  value: string
  tone: 'neutral' | 'info' | 'warning' | 'critical'
}

export interface ApprovalStep {
  order: number
  action: string
  target: string | null
  dry_run: boolean
}

export interface ApprovalTimelineEntry {
  at: string
  event: string
  actor: string | null
  outcome: string | null
}

export interface ApprovalDetail extends ApprovalSummary {
  risk_reason: string
  approver: ApprovalActor | null
  decided_at: string | null
  executed_at: string | null
  impact_facts: ApprovalFact[]
  steps: ApprovalStep[]
  dry_run_available: boolean
  dry_run_status: string | null
  recovery_point_label: string | null
  rollback_available: boolean
  rollback_steps: string[]
  timeline: ApprovalTimelineEntry[]
  raw_evidence_available: boolean
}

export interface ApprovalEvidence {
  approval_id: string
  parameters: Record<string, unknown>
  impact: Record<string, unknown>
}

export interface EnrollmentToken {
  id: string
  host_id: string
  expires_at: string
  install_command: string
  status: string
}

export interface EnrollmentEvent {
  status: string
  sequence: number
  occurred_at: string
  error_code: string | null
  error_summary: string | null
  rolled_back: boolean
}

export interface EnrollmentSession {
  id: string
  host_id: string
  status: string
  sequence: number
  expires_at: string
  used_at: string | null
  revoked_at: string | null
  completed_at: string | null
  source_cidr: string | null
  os_family: string
  error_code: string | null
  error_step: string | null
  error_summary: string | null
  rolled_back: boolean
  events: EnrollmentEvent[]
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
  build_git_sha: string | null
  build_id: string | null
  build_time: string | null
  go_version: string | null
  platform_os: string | null
  platform_arch: string | null
  build_dirty: boolean | null
  binary_sha256: string | null
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
  state: 'ok' | 'pending' | 'firing' | 'acknowledged' | 'silenced' | 'resolved' | 'closed'
  consecutive_failures: number
  consecutive_successes: number
  first_observed_at: string
  last_observed_at: string
  fired_at: string | null
  acknowledged_at: string | null
  acknowledged_by: string | null
  assigned_to: string | null
  silenced_until: string | null
  resolved_at: string | null
  closed_at: string | null
  last_notified_at: string | null
  notification_count: number
  summary: string
  details: Record<string, unknown>
}

export interface NotificationChannel {
  id: string
  name: string
  kind: 'telegram' | 'smtp' | 'discord' | 'webhook'
  enabled: boolean
  configuration: Record<string, string>
  event_scope: string[]
  severity_filter: string[]
  retry_policy: Record<string, number>
  rate_limit_per_minute: number
  created_at: string
}

export interface NotificationDelivery {
  id: string
  channel_id: string
  alert_id: string
  event_type: string
  status: 'pending' | 'delivered' | 'failed' | 'dead_letter'
  attempt_count: number
  next_attempt_at: string
  delivered_at: string | null
  response_code: number | null
  error_summary: string | null
  created_at: string
}

export interface AgentIdentity {
  id: string
  agent_id: string
  generation: number
  rotation_id: string | null
  state: 'pending' | 'active' | 'retiring' | 'revoked' | 'retired'
  certificate_fingerprint: string
  certificate_serial: string | null
  expires_at: string | null
  verified_at: string | null
  successful_heartbeats: number
  last_pending_heartbeat_at: string | null
  activated_at: string | null
  retiring_at: string | null
  revoked_at: string | null
  retired_at: string | null
  created_at: string
}

export interface ServiceCheckResult {
  id: number
  check_id: string
  status: string
  checked_at: string
  latency_ms: number | null
  status_code: number | null
  message: string | null
  details: Record<string, unknown>
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

export interface AuditPresentation {
  event_id: number
  display_action: string
  action_code: string
  category: string
  severity: 'neutral' | 'info' | 'warning' | 'critical'
  result: string
  actor_display: string
  actor_type: 'user' | 'system' | 'agent' | 'unknown'
  resource_display: string
  resource_type: string
  source_display: string
  source_type: 'internal_service' | 'private_network' | 'external_client' | 'unknown'
  created_at: string
  summary: string
  correlation_id: string | null
  request_id: string | null
  evidence_available: boolean
}

export interface AuditEvidence {
  audit_id: number
  action_code: string
  resource_type: string
  resource_id: string | null
  actor_id: string | null
  source_ip: string | null
  changes: Record<string, unknown>
  correlation_id: string | null
}

export interface ServiceSummary {
  host_id: string
  host_name: string
  kind: string
  status: 'healthy' | 'warning' | 'critical' | 'execution_failed' | 'no_data' | 'unsupported' | 'parse_failed'
  reason: string
  counts: Record<string, number>
  parsed: boolean
  summary: string
  evidence_available: boolean
  collected_at: string
}

export interface Overview {
  generated_at: string
  environment: {
    current: 'development' | 'test' | 'staging' | 'production'
    production_deployed: boolean
    production_status: 'deployed' | 'not_deployed'
    gate_decision: string
    version: string
    deployment_commit: string
    deployed_at: string | null
  }
  global_health: 'healthy' | 'degraded' | 'critical' | 'unknown'
  health_reasons: Array<{ severity: string; reason: string; object: string }>
  attention: AttentionItem[]
  hosts: {
    total: number
    inventory_total: number
    unregistered: number
    disabled: number
    healthy: number
    degraded: number
    offline: number
    unknown: number
  }
  checks: { total: number; enabled: number; healthy: number; failed: number; unknown: number }
  agent_versions: Record<string, number>
  expiring_certificates: number
  incidents: { open: number; critical: number }
  alerts: { active: number; critical: number; warning: number }
  pending_approvals: number
  verified_recovery_points: number
  notification_failures: number
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
  resource_window: '1h' | '24h' | '7d' | '30d'
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
  group: string | null
  tags: string[]
  data_state: Host['data_state']
  enabled: boolean
  status: Host['status']
  last_heartbeat_at: string | null
  agent_serial: string | null
  certificate_status: 'valid' | 'expiring' | 'revoked' | 'missing'
  certificate_expires_at: string | null
  agent_version: string | null
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
  deployment_stage: string
  release_version: string
  deployment_commit: string
  deployed_at: string | null
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
  settings_catalog: SettingCatalogItem[]
  secret_status: Record<string, boolean>
  features: Record<string, boolean>
}

export interface SettingCatalogItem {
  key: string
  value: unknown
  source: string
  restart_required: boolean
  risk: 'low' | 'medium' | 'high'
}

export interface AttentionItem {
  id: string
  type: string
  severity: 'critical' | 'warning' | 'info'
  object: string
  reason: string
  observed_at: string | null
  duration_seconds: number | null
  suggested_action: string
  href: string
}

export interface AttentionResponse {
  generated_at: string
  global_health: Overview['global_health']
  health_reasons: Overview['health_reasons']
  items: AttentionItem[]
}

export interface StabilityHost {
  host_id: string
  host_name: string
  group: string | null
  location: string | null
  status: 'scored' | 'no_data' | 'excluded'
  reason: string
  stability_score: number | null
  uptime_score: number | null
  heartbeat_score: number | null
  check_success_score: number | null
  failure_rate: number | null
  mean_recovery_time: number | null
  stale_ratio: number | null
  alert_frequency: number | null
  confidence: number
  sample_count: number
  check_count: number
  is_new: boolean
}

export interface StabilityReport {
  generated_at: string
  window: '1h' | '24h' | '7d' | '30d'
  formula_version: number
  expected_heartbeat_interval_seconds: number
  hosts: StabilityHost[]
  aggregates: Array<{
    group: string
    location: string
    host_count: number
    scored_count: number
    stability_score: number | null
    uptime_score: number | null
    check_success_score: number | null
  }>
}

export interface LatestSnapshot {
  host_id: string
  collected_at: string | null
  payload: Record<string, unknown>
}
