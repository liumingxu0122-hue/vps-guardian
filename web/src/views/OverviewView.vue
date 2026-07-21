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

import { ApiError, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import TrendChart from '../components/TrendChart.vue'
import type { OperationsHost, Overview, ResourcePoint } from '../types'
import { formatTime, relativeTime, titleize } from '../utils'

const data = ref<Overview | null>(null)
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
  if (value === 'go_for_controlled_production_rollout_planning') return '允许受控生产规划'
  if (value === 'not_assessed') return '尚未评估'
  return titleize(value)
}

function healthLabel(value: Overview['global_health']): string {
  return value === 'healthy' ? '健康' : value === 'degraded' ? '降级' : '严重'
}

function hostName(id: string | null): string {
  if (!id) return '全局'
  return data.value?.host_rows.find((host) => host.id === id)?.name ?? '已移除主机'
}

function certificateLabel(host: OperationsHost): string {
  return {
    valid: '有效',
    expiring: '即将到期',
    revoked: '已吊销',
    missing: '未绑定',
  }[host.certificate_status]
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
    error.value = caught instanceof Error ? caught.message : '运营数据加载失败'
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
  <PageHeader title="Operations Overview" description="Staging 运行态、资源、灾备与安全门禁">
    <template #actions>
      <div class="overview-context" aria-label="环境状态">
        <span class="context-pill staging">Staging</span>
        <span class="context-pill production">Production 未部署</span>
      </div>
      <button class="icon-button bordered" type="button" title="刷新" aria-label="刷新运营总览" :disabled="refreshing" @click="load(true)">
        <RefreshCw :size="17" :class="{ spinning: refreshing }" />
      </button>
    </template>
  </PageHeader>

  <div v-if="!online" class="overview-notice warning" role="status"><WifiOff :size="17" />网络已断开，当前显示最近一次数据</div>
  <div v-if="error" class="overview-error" role="alert">
    <LockKeyhole v-if="permissionDenied" :size="22" />
    <TriangleAlert v-else :size="22" />
    <div><strong>{{ permissionDenied ? '权限不足' : 'Controller API 不可用' }}</strong><span>{{ error }}</span></div>
    <button class="secondary-button" type="button" @click="load()">重试</button>
  </div>

  <template v-if="data">
    <section class="gate-band" aria-label="发布门禁">
      <div><ShieldCheck :size="18" /><span>当前门禁</span><strong>{{ gateLabel(data.environment.gate_decision) }}</strong></div>
      <p>Production 状态：<b>{{ data.environment.production_status === 'not_deployed' ? '未部署' : '已部署' }}</b></p>
    </section>

    <section class="operations-status" aria-label="全局状态">
      <div class="status-metric" :class="`health-${data.global_health}`"><Activity :size="18" /><span>全局健康</span><strong>{{ healthLabel(data.global_health) }}</strong><small>{{ formatTime(data.generated_at) }} 更新</small></div>
      <div class="status-metric"><Server :size="18" /><span>在线主机</span><strong>{{ data.hosts.healthy }} / {{ data.hosts.total }}</strong><small>{{ data.hosts.degraded }} 降级 · {{ data.hosts.offline }} 离线</small></div>
      <div class="status-metric"><AlertTriangle :size="18" /><span>当前告警</span><strong>{{ data.incidents.open }}</strong><small>{{ data.incidents.critical }} 个严重</small></div>
      <div class="status-metric"><Clock3 :size="18" /><span>实测 RPO / RTO</span><strong>{{ data.recovery.rpo_seconds ?? '—' }}s / {{ data.recovery.rto_seconds ?? '—' }}s</strong><small>Staging 实测参考值</small></div>
      <div class="status-metric"><DatabaseBackup :size="18" /><span>Accepted snapshot</span><strong class="mono">{{ data.recovery.accepted_snapshot ?? '暂无' }}</strong><small>{{ relativeTime(data.recovery.last_check_at) }}校验</small></div>
      <div class="status-metric production-state"><ShieldCheck :size="18" /><span>Production</span><strong>未部署</strong><small>仅允许规划</small></div>
    </section>

    <section class="overview-section resource-section">
      <header class="overview-section-heading">
        <div><h2>资源监控</h2><span>{{ selectedHost?.name ?? '全部主机聚合' }}</span></div>
        <div class="resource-controls">
          <select v-model="hostFilter" aria-label="按主机筛选资源">
            <option value="all">全部主机</option>
            <option v-for="host in data.host_rows" :key="host.id" :value="host.id">{{ host.name }}</option>
          </select>
          <div class="segmented-control" aria-label="趋势时间范围">
            <button type="button" :class="{ active: windowRange === '24h' }" @click="windowRange = '24h'">24 小时</button>
            <button type="button" :class="{ active: windowRange === '7d' }" @click="windowRange = '7d'">7 天</button>
          </div>
        </div>
      </header>
      <div v-if="selectedSeries.length" class="trend-grid-layout">
        <TrendChart label="CPU" :values="values('cpu_percent')" unit="%" tone="green" />
        <TrendChart label="内存" :values="values('memory_percent')" unit="%" tone="blue" />
        <TrendChart label="磁盘" :values="values('disk_percent')" unit="%" tone="amber" />
        <TrendChart label="网络" :values="values('network_bytes_per_second')" unit="B/s" tone="cyan" />
      </div>
      <EmptyState v-else title="当前范围没有资源样本" detail="等待 Agent 上报后自动更新" />
      <div class="threshold-legend"><span><i class="warning"></i>磁盘 Warning ≥ 80%</span><span><i class="critical"></i>Critical ≥ 90%</span><span v-if="data.resource_series_truncated">趋势已限制为最近 50,000 个样本</span></div>
    </section>

    <section class="overview-section hosts-section">
      <header class="overview-section-heading"><div><h2>VPS 列表</h2><span>{{ data.host_rows.length }} 台受管主机</span></div><RouterLink to="/hosts">完整清单 <ArrowRight :size="14" /></RouterLink></header>
      <div v-if="data.host_rows.length" class="operations-host-table">
        <div class="operations-host-head"><span>主机</span><span>状态</span><span>CPU</span><span>内存</span><span>磁盘</span><span>心跳</span><span>Agent / 证书</span><span>队列 / 失败</span></div>
        <RouterLink v-for="host in data.host_rows" :key="host.id" :to="`/hosts/${host.id}`" class="operations-host-row">
          <span class="ops-host-name"><strong>{{ host.name }}</strong><small>{{ host.location || '地区未设置' }}</small></span>
          <StatusBadge :status="host.status" />
          <span>{{ host.resources.cpu_percent === null ? '—' : `${host.resources.cpu_percent.toFixed(1)}%` }}</span>
          <span>{{ host.resources.memory_percent === null ? '—' : `${host.resources.memory_percent.toFixed(1)}%` }}</span>
          <span class="disk-value" :class="{ warning: (host.resources.disk_percent ?? 0) >= 80, critical: (host.resources.disk_percent ?? 0) >= 90 }">{{ host.resources.disk_percent === null ? '—' : `${host.resources.disk_percent.toFixed(1)}%` }}</span>
          <span>{{ relativeTime(host.last_heartbeat_at) }}</span>
          <span class="agent-cell"><code>{{ host.agent_serial ?? '未分配' }}</code><small :class="`certificate-${host.certificate_status}`">{{ certificateLabel(host) }}</small></span>
          <span>{{ host.offline_queue }} / {{ host.failed_tasks }}</span>
        </RouterLink>
      </div>
      <EmptyState v-else title="尚未登记 VPS" />
    </section>

    <div class="overview-two-column">
      <section class="overview-section topology-section">
        <header class="overview-section-heading"><div><h2>服务拓扑</h2><span>不包含地址与凭据</span></div><Network :size="18" /></header>
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
            <span v-if="!data.topology.some((item) => item.kind === 'agent')" class="topology-empty">没有 Agent</span>
          </div>
        </div>
      </section>

      <section class="overview-section recovery-section">
        <header class="overview-section-heading"><div><h2>灾备状态</h2><span>{{ data.recovery.repository }}</span></div><StatusBadge :status="data.recovery.status" :label="data.recovery.status === 'healthy' ? '可读取' : data.recovery.status" /></header>
        <dl class="overview-definition-list">
          <div><dt>Accepted snapshot</dt><dd class="mono">{{ data.recovery.accepted_snapshot ?? '暂无' }}</dd></div>
          <div><dt>最近备份</dt><dd>{{ formatTime(data.recovery.last_backup_at) }}</dd></div>
          <div><dt>最近 restic check</dt><dd>{{ formatTime(data.recovery.last_check_at) }}</dd></div>
          <div><dt>Snapshots</dt><dd>{{ data.recovery.snapshot_count }}</dd></div>
          <div><dt>隔离恢复</dt><dd>{{ data.recovery.restore_status === 'passed' ? '通过' : titleize(data.recovery.restore_status) }}</dd></div>
          <div><dt>保留策略</dt><dd>{{ titleize(data.recovery.retention_policy) }}</dd></div>
        </dl>
        <div class="recovery-reference-values"><div><span>RPO</span><strong>{{ data.recovery.rpo_seconds ?? '—' }} 秒</strong></div><div><span>RTO</span><strong>{{ data.recovery.rto_seconds ?? '—' }} 秒</strong></div><small>Staging 实测参考值</small></div>
        <div v-if="!data.permissions.can_view_recovery" class="permission-note"><LockKeyhole :size="15" />详细恢复操作需要 Operator 权限</div>
      </section>
    </div>

    <div class="overview-two-column lower-panels">
      <section class="overview-section security-section">
        <header class="overview-section-heading"><div><h2>安全状态</h2><span>{{ formatTime(data.security.last_scan_at) }} 扫描</span></div><ShieldCheck :size="18" /></header>
        <div class="security-score"><div><span>未覆盖 Critical</span><strong>{{ data.security.uncovered_critical ?? '—' }}</strong></div><div><span>未覆盖 High</span><strong>{{ data.security.uncovered_high ?? '—' }}</strong></div></div>
        <ul class="security-controls">
          <li><CheckCircle2 :size="15" /><span>mTLS</span><strong>{{ titleize(data.security.mtls) }}</strong></li>
          <li><CheckCircle2 :size="15" /><span>CRL</span><strong>{{ titleize(data.security.crl) }}</strong></li>
          <li><KeyRound :size="15" /><span>证书轮换</span><strong>{{ titleize(data.security.certificate_rotation) }}</strong></li>
          <li><LockKeyhole :size="15" /><span>限流 / TOTP / RBAC</span><strong>强制执行</strong></li>
          <li><ShieldCheck :size="15" /><span>审计</span><strong>Append-only</strong></li>
        </ul>
        <div v-if="!data.permissions.can_view_security" class="permission-note"><LockKeyhole :size="15" />安全详情需要 Admin 权限</div>
      </section>

      <section class="overview-section timeline-section">
        <header class="overview-section-heading"><div><h2>告警与审计</h2><span>{{ data.pending_approvals }} 个待审批任务</span></div></header>
        <div class="timeline-filters">
          <select v-model="timelineLevel" aria-label="按级别筛选"><option value="all">全部级别</option><option value="critical">严重</option><option value="normal">一般</option></select>
          <select v-model="timelineHost" aria-label="按主机筛选时间线"><option value="all">全部主机</option><option v-for="host in data.host_rows" :key="host.id" :value="host.id">{{ host.name }}</option></select>
        </div>
        <ol v-if="filteredTimeline.length" class="operations-timeline">
          <li v-for="entry in filteredTimeline.slice(0, 12)" :key="entry.id" :class="`timeline-severity-${entry.severity}`">
            <i></i><div><strong>{{ entry.title }}</strong><span>{{ hostName(entry.host_id) }} · {{ titleize(entry.status) }}</span></div><time>{{ relativeTime(entry.at) }}</time>
          </li>
        </ol>
        <EmptyState v-else title="当前筛选没有记录" />
      </section>
    </div>
  </template>

  <div v-else-if="loading" class="overview-loading" aria-label="正在加载运营总览">
    <span v-for="item in 12" :key="item"></span>
  </div>
</template>
