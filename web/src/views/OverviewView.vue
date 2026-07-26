<script setup lang="ts">
import { Activity, ChevronRight, RefreshCw } from '@lucide/vue'
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { dashboard, type DashboardTone } from '../dashboard'
import { request } from '../api'
import PageHeader from '../components/v3/PageHeader.vue'
import StatusBadge from '../components/v3/StatusBadge.vue'
import SummaryMetric from '../components/v3/SummaryMetric.vue'
import { relativeTime } from '../utils'

const { locale } = useI18n()
const zh = computed(() => locale.value === 'zh-CN')
interface CurrentResources {
  generated_at: string
  sampled_hosts: number
  current: {
    cpu_percent: number | null
    memory_percent: number | null
    disk_percent: number | null
    network_bytes_per_second: number | null
  }
  delta: {
    cpu_percent: number | null
    memory_percent: number | null
    disk_percent: number | null
  }
}
const resourcePanel = ref<HTMLElement | null>(null)
const resources = ref<CurrentResources | null>(null)
const resourcesLoading = ref(false)
const resourcesError = ref(false)
let resourceObserver: IntersectionObserver | null = null

const labels = computed(() =>
  zh.value
    ? {
        title: '运行概览',
        description: '集中查看健康、待办、可恢复性与发布门禁。',
        updated: '最近更新',
        refresh: '刷新',
        retry: '重试',
        loading: '正在加载运行摘要',
        error: '运行摘要加载失败，没有把错误伪装为空数据。',
        attention: '需要处理',
        attentionDescription: '只显示当前需要决策或操作的项目。',
        queue: '查看处置队列',
        level: '等级',
        item: '事项',
        impact: '影响',
        owner: 'Owner',
        time: '更新时间',
        action: '下一步',
        noAttention: '当前没有需要处理的事项。',
        pulse: '运行脉搏',
        pulseDescription: '当前值与趋势在进入视口后独立加载，不阻塞首屏摘要。',
        loadResources: '加载资源趋势',
        recoverability: '可恢复性与发布门禁',
        verifiedBackup: '最近已验证备份',
        productionGate: 'Production Gate',
        details: '查看详情',
      }
    : {
        title: 'Operational overview',
        description: 'Health, attention, recoverability and release gates in one view.',
        updated: 'Last updated',
        refresh: 'Refresh',
        retry: 'Retry',
        loading: 'Loading operational summary',
        error: 'Operational summary failed to load. The error is not shown as empty data.',
        attention: 'Needs attention',
        attentionDescription: 'Only current items that require a decision or action.',
        queue: 'View response queue',
        level: 'Level',
        item: 'Item',
        impact: 'Impact',
        owner: 'Owner',
        time: 'Updated',
        action: 'Next action',
        noAttention: 'There are no items requiring action.',
        pulse: 'Operational pulse',
        pulseDescription: 'Current values and trends load independently after entering view.',
        loadResources: 'Load resource trends',
        recoverability: 'Recoverability & release gate',
        verifiedBackup: 'Latest verified backup',
        productionGate: 'Production gate',
        details: 'View details',
      },
)

function tone(value: string): DashboardTone {
  if (value === 'healthy' || value === 'verified' || value === 'go') return 'healthy'
  if (value === 'critical' || value === 'failed') return 'critical'
  if (value === 'warning' || value === 'degraded') return 'warning'
  if (value === 'blocked' || value === 'not_deployed') return 'info'
  return 'neutral'
}

function statusLabel(value: string): string {
  const values: Record<string, [string, string]> = {
    healthy: ['正常', 'Healthy'],
    warning: ['警告', 'Warning'],
    critical: ['严重', 'Critical'],
    blocked: ['有阻塞项', 'Blocked'],
    unknown: ['未知', 'Unknown'],
  }
  return values[value]?.[zh.value ? 0 : 1] ?? value
}

function healthReason(): string {
  const value = dashboard.data?.global_health
  if (!value) return '—'
  if (zh.value) {
    if (value.critical) return `${value.critical} 个严重条件需要处理`
    if (value.warning) return `${value.warning} 个警告条件，0 个严重条件`
    return '没有活动的严重或警告条件'
  }
  if (value.critical) return `${value.critical} critical condition(s) require action`
  if (value.warning) return `${value.warning} warning condition(s), no critical conditions`
  return 'No active critical or warning conditions'
}

function backupValue(): string {
  if (!dashboard.data?.backup.verified) return zh.value ? '尚未验证' : 'Not verified'
  return zh.value ? '可恢复' : 'Recoverable'
}

function gateValue(): string {
  if (dashboard.data?.environment.production_deployed) return zh.value ? '已部署' : 'Deployed'
  return zh.value ? '未部署' : 'Not deployed'
}

function duration(seconds: number | null): string {
  if (seconds === null) return zh.value ? '尚未实测' : 'Not measured'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  return `${Math.round(seconds / 3600)}h`
}

function impact(item: NonNullable<typeof dashboard.data>['attention'][number]): string {
  const values = [...item.impact.hosts, ...item.impact.services]
  return values.length ? values.join(' · ') : zh.value ? '未声明影响资源' : 'No impact declared'
}

function localizedIncidentTitle(
  item: NonNullable<typeof dashboard.data>['attention'][number],
): string {
  if (!zh.value) return item.title
  const faultLabels: Record<string, string> = {
    database_corruption: '数据库完整性事件',
    reverse_proxy_backend: '后端服务不可用',
    certificate_expiry: '证书即将到期',
    approval_audit: '审批审计事件',
  }
  if (faultLabels[item.fault_type]) return faultLabels[item.fault_type]
  return /[\u4e00-\u9fff]/u.test(item.title) ? item.title : '需要处理的运行事件'
}

const summaries = computed(() => {
  const data = dashboard.data
  if (!data) return []
  return [
    {
      label: zh.value ? '系统健康' : 'System health',
      value:
        data.global_health.status === 'healthy'
          ? zh.value
            ? '正常'
            : 'Healthy'
          : zh.value
            ? '需要关注'
            : 'Needs attention',
      detail: healthReason(),
      updated: relativeTime(data.global_health.updated_at),
      tone: tone(data.global_health.status),
      statusLabel: statusLabel(data.global_health.status),
    },
    {
      label: 'Guardian Agent',
      value: `${data.agents.online} / ${data.agents.total} ${zh.value ? '在线' : 'online'}`,
      detail:
        data.agents.offline === 0
          ? zh.value
            ? '心跳状态正常'
            : 'Heartbeats are healthy'
          : zh.value
            ? `${data.agents.offline} 个离线或不新鲜`
            : `${data.agents.offline} offline or stale`,
      updated: relativeTime(data.agents.updated_at),
      tone: data.agents.offline ? ('critical' as const) : ('healthy' as const),
      statusLabel: data.agents.offline ? statusLabel('critical') : statusLabel('healthy'),
    },
    {
      label: zh.value ? '活跃告警' : 'Active alerts',
      value: `${data.alerts.active} ${zh.value ? '个' : ''}`,
      detail: zh.value
        ? `${data.alerts.critical} 个严重，${data.alerts.warning} 个警告`
        : `${data.alerts.critical} critical, ${data.alerts.warning} warning`,
      updated: relativeTime(data.alerts.updated_at),
      tone: data.alerts.critical ? ('critical' as const) : data.alerts.warning ? ('warning' as const) : ('healthy' as const),
      statusLabel: data.alerts.critical ? statusLabel('critical') : data.alerts.warning ? statusLabel('warning') : statusLabel('healthy'),
    },
    {
      label: zh.value ? '最近已验证备份' : 'Latest verified backup',
      value: backupValue(),
      detail: data.backup.verified
        ? `${data.backup.scope === 'offsite' ? 'Offsite' : 'Same-host'} · check ${data.backup.check_status}`
        : zh.value
          ? '没有已验证恢复点'
          : 'No verified recovery point',
      updated: relativeTime(data.backup.verified_at),
      tone: data.backup.verified ? ('healthy' as const) : ('warning' as const),
      statusLabel: data.backup.verified ? statusLabel('healthy') : statusLabel('warning'),
    },
    {
      label: 'Production Gate',
      value: gateValue(),
      detail: data.production_gate.decision.replaceAll('_', ' '),
      updated: relativeTime(data.generated_at),
      tone: data.environment.production_deployed ? ('healthy' as const) : ('info' as const),
      statusLabel: data.environment.production_deployed ? statusLabel('healthy') : statusLabel('blocked'),
    },
  ]
})

async function refresh(): Promise<void> {
  await dashboard.load(true).catch(() => undefined)
}

async function loadResources(): Promise<void> {
  if (resourcesLoading.value) return
  resourcesLoading.value = true
  resourcesError.value = false
  try {
    const result = await request<unknown>('/api/v1/dashboard/resources/current')
    if (!isCurrentResources(result)) throw new Error('Invalid current resource summary')
    resources.value = result
  } catch {
    resources.value = null
    resourcesError.value = true
  } finally {
    resourcesLoading.value = false
  }
}

function isCurrentResources(value: unknown): value is CurrentResources {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<CurrentResources>
  return Boolean(
    candidate.current &&
      typeof candidate.current === 'object' &&
      candidate.delta &&
      typeof candidate.delta === 'object' &&
      typeof candidate.sampled_hosts === 'number' &&
      typeof candidate.generated_at === 'string',
  )
}

function resourceValue(value: number | null, kind: 'percent' | 'network'): string {
  if (value === null) return '—'
  if (kind === 'percent') return `${Math.round(value)}%`
  if (value < 1024) return `${Math.round(value)} B/s`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB/s`
  return `${(value / 1024 ** 2).toFixed(1)} MiB/s`
}

function deltaValue(value: number | null): string {
  if (value === null) return zh.value ? '无上一样本' : 'No prior sample'
  if (value === 0) return zh.value ? '与上一样本持平' : 'No change'
  return `${value > 0 ? '+' : ''}${value.toFixed(1)} pp`
}

watch(resourcePanel, (element) => {
  resourceObserver?.disconnect()
  if (!element || typeof IntersectionObserver === 'undefined') return
  resourceObserver = new IntersectionObserver(
    (entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return
      resourceObserver?.disconnect()
      void loadResources()
    },
    { rootMargin: '100px' },
  )
  resourceObserver.observe(element)
})

onMounted(() => void dashboard.load().catch(() => undefined))

onBeforeUnmount(() => resourceObserver?.disconnect())
</script>

<template>
  <PageHeader
    :eyebrow="`${dashboard.data?.environment.stage ?? 'Staging'} / ${labels.title}`"
    :title="labels.title"
    :description="labels.description"
    :updated="dashboard.data ? `${labels.updated} ${relativeTime(dashboard.data.generated_at)}` : undefined"
  >
    <template #actions>
      <button class="proto-button secondary" type="button" :disabled="dashboard.loading" @click="refresh">
        <RefreshCw :size="15" :class="{ spinning: dashboard.loading }" />{{ labels.refresh }}
      </button>
    </template>
  </PageHeader>

  <div v-if="dashboard.error && !dashboard.data" class="v3-module-state error-state" role="alert">
    <strong>{{ labels.error }}</strong>
    <button class="proto-button secondary" type="button" @click="refresh">{{ labels.retry }}</button>
  </div>

  <section v-else-if="dashboard.loading && !dashboard.data" class="proto-summary-grid" :aria-label="labels.loading">
    <div v-for="index in 5" :key="index" class="v3-summary-skeleton"><span></span><b></b><i></i></div>
  </section>

  <template v-else-if="dashboard.data">
    <section class="proto-summary-grid" aria-label="运行摘要">
      <SummaryMetric v-for="summary in summaries" :key="summary.label" v-bind="summary" />
    </section>

    <section class="proto-section">
      <div class="proto-section-heading">
        <div><h2>{{ labels.attention }}</h2><p>{{ labels.attentionDescription }}</p></div>
        <RouterLink class="proto-text-button" to="/attention">{{ labels.queue }} <ChevronRight :size="14" /></RouterLink>
      </div>
      <div v-if="dashboard.data.attention.length" class="proto-table-shell">
        <table class="proto-table attention-table">
          <thead><tr><th>{{ labels.level }}</th><th>{{ labels.item }}</th><th>{{ labels.impact }}</th><th>{{ labels.owner }}</th><th>{{ labels.time }}</th><th>{{ labels.action }}</th></tr></thead>
          <tbody>
            <tr v-for="item in dashboard.data.attention" :key="item.id">
              <td><StatusBadge :tone="item.severity" :label="`S${item.severity_level}`" compact /></td>
              <td><strong>{{ localizedIncidentTitle(item) }}</strong><small>{{ item.fault_type.replaceAll('_', ' ') }}</small></td>
              <td>{{ impact(item) }}</td>
              <td>{{ item.owner ?? (zh ? '未分配' : 'Unassigned') }}</td>
              <td>{{ relativeTime(item.updated_at) }}</td>
              <td><RouterLink class="proto-row-action" :to="item.href">{{ item.next_action && !zh ? item.next_action : zh ? '查看并确认下一步' : 'Review next action' }} <ChevronRight :size="13" /></RouterLink></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="v3-empty-inline"><StatusBadge tone="healthy" :label="statusLabel('healthy')" /><span>{{ labels.noAttention }}</span></div>
    </section>

    <section class="proto-section">
      <div class="proto-section-heading">
        <div><h2>{{ labels.pulse }}</h2><p>{{ labels.pulseDescription }}</p></div>
      </div>
      <div class="proto-pulse-layout">
        <div ref="resourcePanel" class="proto-resource-panel">
          <h3>{{ zh ? '当前资源使用' : 'Current resource use' }}</h3>
          <div v-if="resources" class="v3-current-resources">
            <div><span>CPU</span><strong>{{ resourceValue(resources.current.cpu_percent, 'percent') }}</strong><small>{{ deltaValue(resources.delta.cpu_percent) }}</small></div>
            <div><span>{{ zh ? '内存' : 'Memory' }}</span><strong>{{ resourceValue(resources.current.memory_percent, 'percent') }}</strong><small>{{ deltaValue(resources.delta.memory_percent) }}</small></div>
            <div><span>{{ zh ? '磁盘' : 'Disk' }}</span><strong>{{ resourceValue(resources.current.disk_percent, 'percent') }}</strong><small>{{ deltaValue(resources.delta.disk_percent) }}</small></div>
            <div><span>{{ zh ? '网络' : 'Network' }}</span><strong>{{ resourceValue(resources.current.network_bytes_per_second, 'network') }}</strong><small>{{ zh ? '最近采样速率' : 'Latest sample rate' }}</small></div>
            <small>{{ resources.sampled_hosts }} {{ zh ? '个主机 · 独立轻量查询' : 'hosts · independent lightweight query' }}</small>
          </div>
          <button v-else class="proto-chart-placeholder" type="button" :disabled="resourcesLoading" @click="loadResources">
            <Activity :size="18" /><span>{{ labels.loadResources }}</span>
          </button>
          <p v-if="resourcesError" class="v3-inline-error">
            {{ zh ? '资源摘要加载失败；运行总览仍可用。' : 'Resource summary failed; the operational summary remains available.' }}
          </p>
        </div>
        <div class="proto-gate-panel">
          <h3>{{ labels.recoverability }}</h3>
          <div class="proto-gate-row">
            <StatusBadge :tone="dashboard.data.backup.verified ? 'healthy' : 'warning'" :label="backupValue()" />
            <div><strong>{{ labels.verifiedBackup }}</strong><span>{{ dashboard.data.backup.scope }} · {{ relativeTime(dashboard.data.backup.verified_at) }}</span></div>
            <span>RPO {{ duration(dashboard.data.backup.rpo_seconds) }} · RTO {{ duration(dashboard.data.backup.rto_seconds) }}</span>
          </div>
          <div class="proto-gate-row">
            <StatusBadge :tone="dashboard.data.environment.production_deployed ? 'healthy' : 'info'" :label="gateValue()" />
            <div><strong>{{ labels.productionGate }}</strong><span>{{ dashboard.data.production_gate.decision.replaceAll('_', ' ') }}</span></div>
            <span>{{ dashboard.data.environment.version }}</span>
          </div>
          <ul v-if="dashboard.data.production_gate.blockers.length" class="v3-gate-blockers">
            <li v-for="blocker in dashboard.data.production_gate.blockers" :key="blocker">
              {{ blocker.replaceAll('_', ' ') }}
            </li>
          </ul>
          <RouterLink class="proto-text-button" to="/recovery">{{ labels.details }} <ChevronRight :size="14" /></RouterLink>
        </div>
      </div>
    </section>
  </template>
</template>
