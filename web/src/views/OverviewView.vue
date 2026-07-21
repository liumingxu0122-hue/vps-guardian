<script setup lang="ts">
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Database,
  DatabaseBackup,
  Gauge,
  KeyRound,
  LockKeyhole,
  Network,
  RefreshCw,
  Server,
  ShieldCheck,
  TriangleAlert,
  WifiOff,
} from '@lucide/vue'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { ApiError, request } from '../api'
import { apiErrorKey, translateStatus } from '../i18n'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import TrendChart from '../components/TrendChart.vue'
import type { OperationsHost, Overview, ResourcePoint } from '../types'
import { formatTime, relativeTime, titleize } from '../utils'

const data = ref<Overview | null>(null)
const { t } = useI18n()
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
const permissionDenied = ref(false)
const online = ref(navigator.onLine)
const windowRange = ref<'24h' | '7d'>('24h')
const hostFilter = ref('all')
const timelineHost = ref('all')
const timelineLevel = ref('all')
let pollTimer: number | undefined

const selectedHost = computed(() =>
  data.value?.host_rows.find((host) => host.id === hostFilter.value),
)
const selectedSeries = computed<ResourcePoint[]>(() => {
  if (!data.value) return []
  if (hostFilter.value !== 'all') return data.value.resource_series[hostFilter.value] ?? []
  const buckets = new Map<number, ResourcePoint[]>()
  const interval = windowRange.value === '24h' ? 15 * 60_000 : 60 * 60_000
  for (const point of Object.values(data.value.resource_series).flat()) {
    const bucket = Math.floor(new Date(point.at).getTime() / interval) * interval
    buckets.set(bucket, [...(buckets.get(bucket) ?? []), point])
  }
  return [...buckets.entries()]
    .sort(([left], [right]) => left - right)
    .map(([at, points]) => ({
      at: new Date(at).toISOString(),
      cpu_percent: average(points.map((point) => point.cpu_percent)),
      cpu_source: points.some((point) => point.cpu_source === 'cpu_time')
        ? 'cpu_time'
        : 'normalized_load',
      memory_percent: average(points.map((point) => point.memory_percent)),
      disk_percent: average(points.map((point) => point.disk_percent)),
      network_bytes_per_second: sum(points.map((point) => point.network_bytes_per_second)),
    }))
})
const filteredTimeline = computed(() =>
  (data.value?.timeline ?? []).filter((entry) => {
    const hostMatches = timelineHost.value === 'all' || entry.host_id === timelineHost.value
    const levelMatches =
      timelineLevel.value === 'all' ||
      (timelineLevel.value === 'critical' ? entry.severity >= 4 : entry.severity < 4)
    return hostMatches && levelMatches
  }),
)

function average(values: Array<number | null>): number | null {
  const present = values.filter((value): value is number => value !== null)
  return present.length ? present.reduce((total, value) => total + value, 0) / present.length : null
}

function sum(values: Array<number | null>): number | null {
  const present = values.filter((value): value is number => value !== null)
  return present.length ? present.reduce((total, value) => total + value, 0) : null
}

function values(key: keyof Pick<ResourcePoint, 'cpu_percent' | 'memory_percent' | 'disk_percent' | 'network_bytes_per_second'>): Array<number | null> {
  return selectedSeries.value.map((point) => point[key])
}

function gateLabel(value: string): string {
  if (value === 'go_for_controlled_production_rollout_planning') return t('overview.gatePlanning')
  if (value === 'not_assessed') return t('overview.notAssessed')
  return titleize(value)
}

function healthLabel(value: Overview['global_health']): string {
  return translateStatus(value)
}

function hostName(id: string | null): string {
  if (!id) return t('overview.global')
  return data.value?.host_rows.find((host) => host.id === id)?.name ?? t('overview.removedHost')
}

function certificateLabel(host: OperationsHost): string {
  return translateStatus(host.certificate_status)
}

async function load(background = false): Promise<void> {
  if (background) refreshing.value = true
  else loading.value = true
  error.value = ''
  permissionDenied.value = false
  try {
    const params = new URLSearchParams({ window: windowRange.value })
    if (hostFilter.value !== 'all') params.set('host_id', hostFilter.value)
    data.value = await request<Overview>(`/api/v1/overview?${params}`)
  } catch (caught) {
    permissionDenied.value = caught instanceof ApiError && caught.status === 403
    error.value = caught instanceof ApiError ? t(apiErrorKey(caught.status), { status: caught.status }) : t('overview.fetchFailed')
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

function setConnectivity(): void {
  online.value = navigator.onLine
  if (online.value) void load(true)
}

watch([windowRange, hostFilter], () => void load())
onMounted(() => {
  void load()
  window.addEventListener('online', setConnectivity)
  window.addEventListener('offline', setConnectivity)
  pollTimer = window.setInterval(() => {
    if (document.visibilityState === 'visible' && navigator.onLine) void load(true)
  }, 60_000)
})
onBeforeUnmount(() => {
  window.removeEventListener('online', setConnectivity)
  window.removeEventListener('offline', setConnectivity)
  if (pollTimer) window.clearInterval(pollTimer)
})
</script>

<template>
  <PageHeader :title="t('overview.title')" :description="t('overview.description')">
    <template #actions>
      <div class="overview-context" :aria-label="t('overview.environment')">
        <span class="context-pill staging">Staging</span>
        <span class="context-pill production">{{ t('overview.production') }} · {{ t('overview.notDeployed') }}</span>
      </div>
      <button class="icon-button bordered" type="button" :title="t('common.refresh')" :aria-label="t('common.refresh')" :disabled="refreshing" @click="load(true)">
        <RefreshCw :size="17" :class="{ spinning: refreshing }" />
      </button>
    </template>
  </PageHeader>

  <div v-if="!online" class="overview-notice warning" role="status"><WifiOff :size="17" />{{ t('overview.offline') }}</div>
  <div v-if="error" class="overview-error" role="alert">
    <LockKeyhole v-if="permissionDenied" :size="22" />
    <TriangleAlert v-else :size="22" />
      <div><strong>{{ permissionDenied ? t('overview.permissionDenied') : t('errors.unavailable') }}</strong><span>{{ error }}</span></div>
      <button class="secondary-button" type="button" @click="load()">{{ t('common.retry') }}</button>
  </div>

  <template v-if="data">
    <section class="gate-band" :aria-label="t('overview.gate')">
      <div><ShieldCheck :size="18" /><span>{{ t('overview.currentGate') }}</span><strong>{{ gateLabel(data.environment.gate_decision) }}</strong></div>
      <p>{{ t('overview.productionStatus', { status: translateStatus(data.environment.production_status) }) }}</p>
    </section>

    <section class="operations-status" :aria-label="t('overview.globalHealth')">
      <div class="status-metric" :class="`health-${data.global_health}`"><Activity :size="18" /><span>{{ t('overview.globalHealth') }}</span><strong>{{ healthLabel(data.global_health) }}</strong><small>{{ formatTime(data.generated_at) }} · {{ t('common.updated') }}</small></div>
      <div class="status-metric"><Server :size="18" /><span>{{ t('overview.onlineHosts') }}</span><strong>{{ data.hosts.healthy }} / {{ data.hosts.total }}</strong><small>{{ data.hosts.degraded }} {{ t('status.degraded') }} · {{ data.hosts.offline }} {{ t('status.offline') }}</small></div>
      <div class="status-metric"><AlertTriangle :size="18" /><span>{{ t('overview.currentAlerts') }}</span><strong>{{ data.alerts.active }}</strong><small>{{ data.alerts.critical }} {{ t('status.critical') }} · {{ data.alerts.warning }} Warning</small></div>
      <div class="status-metric"><Clock3 :size="18" /><span>{{ t('overview.measuredRpoRto') }}</span><strong>{{ data.recovery.rpo_seconds ?? '—' }}s / {{ data.recovery.rto_seconds ?? '—' }}s</strong><small>{{ t('overview.measuredReference') }}</small></div>
      <div class="status-metric"><DatabaseBackup :size="18" /><span>{{ t('overview.acceptedSnapshot') }}</span><strong class="mono">{{ data.recovery.accepted_snapshot ?? t('common.none') }}</strong><small>{{ relativeTime(data.recovery.last_check_at) }} · {{ t('common.checks') }}</small></div>
      <div class="status-metric production-state"><ShieldCheck :size="18" /><span>{{ t('overview.production') }}</span><strong>{{ t('overview.notDeployed') }}</strong><small>{{ t('overview.planningOnly') }}</small></div>
    </section>

    <section class="overview-section resource-section">
      <header class="overview-section-heading">
        <div><h2>{{ t('overview.resources') }}</h2><span>{{ selectedHost?.name ?? t('overview.aggregatedHosts') }}</span></div>
        <div class="resource-controls">
          <select v-model="hostFilter" :aria-label="t('overview.filterResources')">
            <option value="all">{{ t('overview.allHosts') }}</option>
            <option v-for="host in data.host_rows" :key="host.id" :value="host.id">{{ host.name }}</option>
          </select>
          <div class="segmented-control" :aria-label="t('overview.range')">
            <button type="button" :class="{ active: windowRange === '24h' }" @click="windowRange = '24h'">{{ t('overview.hours24') }}</button>
            <button type="button" :class="{ active: windowRange === '7d' }" @click="windowRange = '7d'">{{ t('overview.days7') }}</button>
          </div>
        </div>
      </header>
      <div v-if="selectedSeries.length" class="trend-grid-layout">
        <TrendChart label="CPU" :values="values('cpu_percent')" unit="%" tone="green" />
        <TrendChart :label="t('overview.memory')" :values="values('memory_percent')" unit="%" tone="blue" />
        <TrendChart :label="t('overview.disk')" :values="values('disk_percent')" unit="%" tone="amber" />
        <TrendChart :label="t('overview.network')" :values="values('network_bytes_per_second')" unit="B/s" tone="cyan" />
      </div>
      <EmptyState v-else :title="t('overview.noSamples')" :detail="t('overview.waitingSamples')" />
      <div class="threshold-legend"><span><i class="warning"></i>{{ t('overview.warning80') }}</span><span><i class="critical"></i>{{ t('overview.critical90') }}</span><span v-if="data.resource_series_truncated">{{ t('overview.truncated') }}</span></div>
    </section>

    <section class="overview-section hosts-section">
      <header class="overview-section-heading"><div><h2>{{ t('overview.vpsList') }}</h2><span>{{ t('overview.managedHosts', { count: data.host_rows.length }) }}</span></div><RouterLink to="/hosts">{{ t('overview.fullList') }} <ArrowRight :size="14" /></RouterLink></header>
      <div v-if="data.host_rows.length" class="operations-host-table">
        <div class="operations-host-head"><span>{{ t('overview.host') }}</span><span>{{ t('overview.status') }}</span><span>CPU</span><span>{{ t('overview.memory') }}</span><span>{{ t('overview.disk') }}</span><span>{{ t('overview.heartbeat') }}</span><span>{{ t('overview.agentCertificate') }}</span><span>{{ t('overview.queueFailed') }}</span></div>
        <RouterLink v-for="host in data.host_rows" :key="host.id" :to="`/hosts/${host.id}`" class="operations-host-row">
          <span class="ops-host-name"><strong>{{ host.name }}</strong><small>{{ host.location || t('overview.regionMissing') }}</small></span>
          <StatusBadge :status="host.status" />
          <span>{{ host.resources.cpu_percent === null ? '—' : `${host.resources.cpu_percent.toFixed(1)}%` }}</span>
          <span>{{ host.resources.memory_percent === null ? '—' : `${host.resources.memory_percent.toFixed(1)}%` }}</span>
          <span class="disk-value" :class="{ warning: (host.resources.disk_percent ?? 0) >= 80, critical: (host.resources.disk_percent ?? 0) >= 90 }">{{ host.resources.disk_percent === null ? '—' : `${host.resources.disk_percent.toFixed(1)}%` }}</span>
          <span>{{ relativeTime(host.last_heartbeat_at) }}</span>
          <span class="agent-cell"><code>{{ host.agent_serial ?? t('overview.unassigned') }}</code><small :class="`certificate-${host.certificate_status}`">{{ certificateLabel(host) }}</small></span>
          <span>{{ host.offline_queue }} / {{ host.failed_tasks }}</span>
        </RouterLink>
      </div>
      <EmptyState v-else :title="t('overview.noHosts')" />
    </section>

    <div class="overview-two-column">
      <section class="overview-section topology-section">
        <header class="overview-section-heading"><div><h2>{{ t('overview.topology') }}</h2><span>{{ t('overview.noSensitiveTopology') }}</span></div><Network :size="18" /></header>
        <div class="topology-flow">
          <div class="topology-core">
            <div v-for="node in data.topology.filter((item) => item.kind !== 'agent')" :key="node.id" class="topology-node" :class="`node-${node.status}`">
              <component :is="node.kind === 'database' ? Database : node.kind === 'gateway' ? ShieldCheck : node.kind === 'web' ? Network : Gauge" :size="17" />
              <span>{{ node.label }}</span><i></i>
            </div>
          </div>
          <div class="topology-rail" aria-hidden="true"></div>
          <div class="topology-agents">
            <div v-for="node in data.topology.filter((item) => item.kind === 'agent')" :key="node.id" class="topology-node" :class="`node-${node.status}`"><Server :size="16" /><span>{{ node.label }}</span><i></i></div>
            <span v-if="!data.topology.some((item) => item.kind === 'agent')" class="topology-empty">{{ t('overview.noAgents') }}</span>
          </div>
        </div>
      </section>

      <section class="overview-section recovery-section">
        <header class="overview-section-heading"><div><h2>{{ t('overview.recovery') }}</h2><span>{{ data.recovery.repository }}</span></div><StatusBadge :status="data.recovery.status" :label="data.recovery.status === 'healthy' ? t('overview.readable') : translateStatus(data.recovery.status)" /></header>
        <dl class="overview-definition-list">
          <div><dt>{{ t('overview.acceptedSnapshot') }}</dt><dd class="mono">{{ data.recovery.accepted_snapshot ?? t('common.none') }}</dd></div>
          <div><dt>{{ t('overview.latestBackup') }}</dt><dd>{{ formatTime(data.recovery.last_backup_at) }}</dd></div>
          <div><dt>{{ t('overview.latestCheck') }}</dt><dd>{{ formatTime(data.recovery.last_check_at) }}</dd></div>
          <div><dt>Snapshots</dt><dd>{{ data.recovery.snapshot_count }}</dd></div>
          <div><dt>{{ t('overview.isolatedRestore') }}</dt><dd>{{ translateStatus(data.recovery.restore_status) }}</dd></div>
          <div><dt>{{ t('overview.retention') }}</dt><dd>{{ titleize(data.recovery.retention_policy) }}</dd></div>
        </dl>
        <div class="recovery-reference-values"><div><span>RPO</span><strong>{{ data.recovery.rpo_seconds ?? '—' }} {{ t('common.seconds') }}</strong></div><div><span>RTO</span><strong>{{ data.recovery.rto_seconds ?? '—' }} {{ t('common.seconds') }}</strong></div><small>{{ t('overview.measuredReference') }}</small></div>
        <div v-if="!data.permissions.can_view_recovery" class="permission-note"><LockKeyhole :size="15" />{{ t('overview.recoveryPermission') }}</div>
      </section>
    </div>

    <div class="overview-two-column lower-panels">
      <section class="overview-section security-section">
        <header class="overview-section-heading"><div><h2>{{ t('overview.security') }}</h2><span>{{ formatTime(data.security.last_scan_at) }} · {{ t('overview.scanAt') }}</span></div><ShieldCheck :size="18" /></header>
        <div class="security-score"><div><span>{{ t('overview.uncoveredCritical') }}</span><strong>{{ data.security.uncovered_critical ?? '—' }}</strong></div><div><span>{{ t('overview.uncoveredHigh') }}</span><strong>{{ data.security.uncovered_high ?? '—' }}</strong></div></div>
        <ul class="security-controls">
          <li><CheckCircle2 :size="15" /><span>mTLS</span><strong>{{ titleize(data.security.mtls) }}</strong></li>
          <li><CheckCircle2 :size="15" /><span>CRL</span><strong>{{ titleize(data.security.crl) }}</strong></li>
          <li><KeyRound :size="15" /><span>{{ t('overview.certificateRotation') }}</span><strong>{{ translateStatus(data.security.certificate_rotation) }}</strong></li>
          <li><LockKeyhole :size="15" /><span>{{ t('overview.controls') }}</span><strong>{{ t('status.enforced') }}</strong></li>
          <li><ShieldCheck :size="15" /><span>{{ t('overview.audit') }}</span><strong>{{ t('status.append_only') }}</strong></li>
        </ul>
        <div v-if="!data.permissions.can_view_security" class="permission-note"><LockKeyhole :size="15" />{{ t('overview.securityPermission') }}</div>
      </section>

      <section class="overview-section timeline-section">
        <header class="overview-section-heading"><div><h2>{{ t('overview.alertsAudit') }}</h2><span>{{ t('overview.pendingTasks', { count: data.pending_approvals }) }}</span></div></header>
        <div class="timeline-filters">
          <select v-model="timelineLevel" :aria-label="t('overview.levelFilter')"><option value="all">{{ t('overview.allLevels') }}</option><option value="critical">{{ t('overview.severe') }}</option><option value="normal">{{ t('overview.normal') }}</option></select>
          <select v-model="timelineHost" :aria-label="t('overview.timelineHost')"><option value="all">{{ t('overview.allHosts') }}</option><option v-for="host in data.host_rows" :key="host.id" :value="host.id">{{ host.name }}</option></select>
        </div>
        <ol v-if="filteredTimeline.length" class="operations-timeline">
          <li v-for="entry in filteredTimeline.slice(0, 12)" :key="entry.id" :class="`timeline-severity-${entry.severity}`">
            <i></i><div><strong>{{ entry.title }}</strong><span>{{ hostName(entry.host_id) }} · {{ titleize(entry.status) }}</span></div><time>{{ relativeTime(entry.at) }}</time>
          </li>
        </ol>
        <EmptyState v-else :title="t('overview.noTimeline')" />
      </section>
    </div>
  </template>

  <div v-else-if="loading" class="overview-loading" :aria-label="t('overview.loading')">
    <span v-for="item in 12" :key="item"></span>
  </div>
</template>
