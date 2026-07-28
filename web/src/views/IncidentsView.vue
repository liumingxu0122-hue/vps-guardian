<script setup lang="ts">
import { ChevronDown, ChevronRight, Filter, RefreshCw, Search } from '@lucide/vue'
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import DetailDrawer from '../components/v3/DetailDrawer.vue'
import DataTable from '../components/v3/DataTable.vue'
import PageHeader from '../components/v3/PageHeader.vue'
import StatusBadge, { type StatusTone } from '../components/v3/StatusBadge.vue'
import { session } from '../session'
import type { Incident, User } from '../types'
import { formatTime, relativeTime } from '../utils'

const route = useRoute()
const router = useRouter()
const { locale } = useI18n()
const zh = computed(() => locale.value === 'zh-CN')
const incidents = ref<Incident[]>([])
const users = ref<User[]>([])
const loading = ref(true)
const error = ref('')
const query = ref(typeof route.query.q === 'string' ? route.query.q : '')
const filter = ref<'active' | 'resolved' | 'all'>(
  route.query.status === 'resolved' || route.query.status === 'all' ? route.query.status : 'active',
)
const severityFilter = ref(typeof route.query.severity === 'string' ? route.query.severity : 'all')
const ownerFilter = ref(typeof route.query.owner === 'string' ? route.query.owner : 'all')
const sourceFilter = ref(typeof route.query.source === 'string' ? route.query.source : 'all')
const recordFilter = ref<'all' | 'real' | 'test'>(
  route.query.record === 'real' || route.query.record === 'test' ? route.query.record : 'all',
)
const ageFilter = ref<'all' | '24h' | '7d'>(
  route.query.age === '24h' || route.query.age === '7d' ? route.query.age : 'all',
)
const sortBy = ref<'updated' | 'created'>(
  route.query.sort === 'created' ? 'created' : 'updated',
)
const selected = ref<Incident | null>(null)
const updating = ref(false)
const canOperate = computed(() => ['operator', 'admin', 'owner'].includes(session.user?.role ?? 'viewer'))

const active = computed(() => incidents.value.filter((incident) => incident.status !== 'resolved'))
const resolved = computed(() => incidents.value.filter((incident) => incident.status === 'resolved'))
const unassigned = computed(() => active.value.filter((incident) => !incident.assigned_to).length)
const highSeverity = computed(() => active.value.filter((incident) => incident.severity <= 2).length)
const overTarget = computed(
  () => active.value.filter((incident) => Date.now() - new Date(incident.first_seen_at).getTime() > 24 * 3600_000).length,
)
const meanRecoveryMinutes = computed(() => {
  const durations = resolved.value
    .filter((incident) => incident.resolved_at)
    .map((incident) => (new Date(incident.resolved_at!).getTime() - new Date(incident.first_seen_at).getTime()) / 60_000)
    .filter((value) => Number.isFinite(value) && value >= 0)
  if (!durations.length) return null
  return Math.round(durations.reduce((sum, value) => sum + value, 0) / durations.length)
})

const filtered = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const now = Date.now()
  const output = incidents.value.filter((incident) => {
    if (filter.value === 'active' && incident.status === 'resolved') return false
    if (filter.value === 'resolved' && incident.status !== 'resolved') return false
    if (severityFilter.value !== 'all' && incident.severity !== Number(severityFilter.value)) return false
    if (ownerFilter.value === 'unassigned' && incident.assigned_to) return false
    if (!['all', 'unassigned'].includes(ownerFilter.value) && incident.assigned_to !== ownerFilter.value) return false
    if (sourceFilter.value !== 'all' && incident.fault_type !== sourceFilter.value) return false
    if (recordFilter.value === 'test' && !isTestRecord(incident)) return false
    if (recordFilter.value === 'real' && isTestRecord(incident)) return false
    const createdAge = now - new Date(incident.first_seen_at).getTime()
    if (ageFilter.value === '24h' && createdAge > 24 * 3600_000) return false
    if (ageFilter.value === '7d' && createdAge > 7 * 24 * 3600_000) return false
    const resource = [...incident.affected_hosts, ...incident.affected_services].join(' ')
    return !needle || `${incident.title} ${incident.fault_type} ${resource} ${ownerName(incident)}`.toLowerCase().includes(needle)
  })
  return output.sort((left, right) =>
    sortBy.value === 'created'
      ? right.first_seen_at.localeCompare(left.first_seen_at)
      : right.updated_at.localeCompare(left.updated_at),
  )
})
const availableSources = computed(() => [...new Set(incidents.value.map((incident) => incident.fault_type))].sort())

watch(
  [query, filter, severityFilter, ownerFilter, sourceFilter, recordFilter, ageFilter, sortBy],
  () => {
  void router.replace({
    query: {
      ...route.query,
      q: query.value || undefined,
      status: filter.value === 'active' ? undefined : filter.value,
      severity: severityFilter.value === 'all' ? undefined : severityFilter.value,
      owner: ownerFilter.value === 'all' ? undefined : ownerFilter.value,
      source: sourceFilter.value === 'all' ? undefined : sourceFilter.value,
      record: recordFilter.value === 'all' ? undefined : recordFilter.value,
      age: ageFilter.value === 'all' ? undefined : ageFilter.value,
      sort: sortBy.value === 'updated' ? undefined : sortBy.value,
      selected: selected.value?.id,
    },
  })
  },
)

watch(selected, (value) => {
  void router.replace({
    query: { ...route.query, selected: value?.id || undefined },
  })
})

function severityTone(severity: number): StatusTone {
  if (severity <= 2) return 'critical'
  if (severity <= 3) return 'warning'
  if (severity === 4) return 'info'
  return 'neutral'
}

function statusTone(status: Incident['status']): StatusTone {
  if (status === 'resolved') return 'healthy'
  if (status === 'mitigating') return 'warning'
  if (status === 'open') return 'critical'
  return 'info'
}

function statusLabel(status: Incident['status']): string {
  const labels: Record<Incident['status'], [string, string]> = {
    open: ['待处理', 'Open'],
    acknowledged: ['已确认', 'Acknowledged'],
    investigating: ['调查中', 'Investigating'],
    mitigating: ['缓解中', 'Mitigating'],
    resolved: ['已解决', 'Resolved'],
  }
  return labels[status][zh.value ? 0 : 1]
}

function ownerName(incident: Incident): string {
  if (!incident.assigned_to) return zh.value ? '未分配' : 'Unassigned'
  return users.value.find((user) => user.id === incident.assigned_to)?.email ?? (zh.value ? '已分配' : 'Assigned')
}

function title(incident: Incident): string {
  if (!zh.value) return incident.title
  const labels: Record<string, string> = {
    database_corruption: '数据库完整性事件',
    reverse_proxy_backend: '后端服务不可用',
    certificate_expiry: '证书即将到期',
    approval_audit: '审批审计事件',
  }
  if (labels[incident.fault_type]) return labels[incident.fault_type]
  return /[\u4e00-\u9fff]/u.test(incident.title) ? incident.title : '需要处理的运行事件'
}

function sourceLabel(incident: Incident): string {
  const labels: Record<string, [string, string]> = {
    database_corruption: ['数据库检查', 'Database check'],
    reverse_proxy_backend: ['服务检查', 'Service check'],
    certificate_expiry: ['证书检查', 'Certificate check'],
    approval_audit: ['审批审计', 'Approval audit'],
  }
  return labels[incident.fault_type]?.[zh.value ? 0 : 1] ?? (zh.value ? '自动检测' : 'Automatic detection')
}

function affected(incident: Incident): string {
  const values = [...incident.affected_hosts, ...incident.affected_services]
  return values.length ? values.slice(0, 2).join(' · ') : zh.value ? '未声明' : 'Not declared'
}

function age(incident: Incident): string {
  const end = incident.resolved_at ? new Date(incident.resolved_at).getTime() : Date.now()
  const seconds = Math.max(0, Math.round((end - new Date(incident.first_seen_at).getTime()) / 1000))
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))}${zh.value ? ' 分钟' : ' min'}`
  if (seconds < 86400) return `${Math.round(seconds / 3600)}${zh.value ? ' 小时' : ' hr'}`
  return `${Math.round(seconds / 86400)}${zh.value ? ' 天' : ' d'}`
}

function nextAction(incident: Incident): string {
  const recommendation = incident.recommendations[0]
  if (recommendation && (!zh.value || /[\u4e00-\u9fff]/u.test(recommendation))) return recommendation
  if (incident.status === 'open') return zh.value ? '确认并分配 Owner' : 'Acknowledge and assign'
  if (incident.status === 'acknowledged') return zh.value ? '开始调查' : 'Start investigation'
  if (incident.status === 'investigating') return zh.value ? '确认缓解方案' : 'Confirm mitigation'
  if (incident.status === 'mitigating') return zh.value ? '验证并解决' : 'Verify and resolve'
  return zh.value ? '查看复盘' : 'Review postmortem'
}

function isTestRecord(incident: Incident): boolean {
  return incident.severity === 5 && /test|演练|approval|审批/i.test(`${incident.title} ${incident.fault_type}`)
}

function timelineTitle(entry: Record<string, unknown>): string {
  for (const key of ['title', 'summary', 'event', 'action', 'status']) {
    if (typeof entry[key] === 'string' && entry[key]) {
      const value = String(entry[key])
      if (!zh.value || /[\u4e00-\u9fff]/u.test(value)) return value
      if (/investigation.*start/i.test(value)) return '已开始调查'
      if (/acknowledg/i.test(value)) return '事故已确认'
      if (/mitigat/i.test(value)) return '已进入缓解阶段'
      if (/resolv/i.test(value)) return '事故已解决'
      return '事故活动已更新'
    }
  }
  return zh.value ? '事故活动' : 'Incident activity'
}

function riskSummary(incident: Incident): string {
  if (!incident.risk || incident.risk === 'unknown') {
    return zh.value
      ? '影响范围正在确认；没有可靠数据时不显示伪造的置信度。'
      : 'Impact is being confirmed; no confidence is shown without meaningful data.'
  }
  if (!zh.value || /[\u4e00-\u9fff]/u.test(incident.risk)) return incident.risk
  return '存在运行影响；请结合受影响资源和证据确认范围。'
}

function timelineTime(entry: Record<string, unknown>): string | null {
  for (const key of ['at', 'created_at', 'timestamp', 'time']) {
    if (typeof entry[key] === 'string') return String(entry[key])
  }
  return null
}

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    incidents.value = await request<Incident[]>('/api/v1/incidents?limit=200')
    if (['admin', 'owner'].includes(session.user?.role ?? 'viewer')) {
      users.value = await request<User[]>('/api/v1/users')
    }
    const requested = typeof route.query.selected === 'string' ? route.query.selected : null
    if (requested) selected.value = incidents.value.find((incident) => incident.id === requested) ?? null
    else if (selected.value) selected.value = incidents.value.find((incident) => incident.id === selected.value?.id) ?? null
  } catch {
    error.value = zh.value ? '事故列表加载失败。' : 'Failed to load incidents.'
  } finally {
    loading.value = false
  }
}

async function advanceIncident(): Promise<void> {
  if (!selected.value || !canOperate.value) return
  const next: Partial<Record<Incident['status'], Incident['status']>> = {
    open: 'acknowledged',
    acknowledged: 'investigating',
    investigating: 'mitigating',
    mitigating: 'resolved',
  }
  const status = next[selected.value.status]
  if (!status) return
  if (status === 'resolved') return
  updating.value = true
  try {
    selected.value = await request<Incident>(`/api/v1/incidents/${selected.value.id}`, {
      method: 'PATCH',
      ...jsonBody({ status, assigned_to: selected.value.assigned_to }),
    })
    await load()
  } finally {
    updating.value = false
  }
}

function clearFilters(): void {
  query.value = ''
  filter.value = 'active'
  severityFilter.value = 'all'
  ownerFilter.value = 'all'
  sourceFilter.value = 'all'
  recordFilter.value = 'all'
  ageFilter.value = 'all'
}

onMounted(load)
</script>

<template>
  <PageHeader
    eyebrow="Staging / Incidents"
    :title="zh ? '事故' : 'Incidents'"
    :description="zh ? '按影响、Owner 和下一步决策组织处置。' : 'Prioritize active impact, ownership and the next decision.'"
    :updated="incidents[0] ? relativeTime(incidents[0].updated_at) : undefined"
  >
    <template #actions><button class="proto-button secondary" type="button" :disabled="loading" @click="load"><RefreshCw :size="15" />{{ zh ? '刷新' : 'Refresh' }}</button></template>
  </PageHeader>

  <section class="proto-inline-metrics incident-metrics" aria-label="事故摘要">
    <div><span>{{ zh ? '活动事故' : 'Active' }}</span><strong>{{ active.length }}</strong></div>
    <div><span>{{ zh ? '未分配' : 'Unassigned' }}</span><strong>{{ unassigned }}</strong></div>
    <div class="critical"><span>S1 / S2</span><strong>{{ highSeverity }}</strong></div>
    <div class="warning"><span>{{ zh ? '超过目标时间' : 'Over target' }}</span><strong>{{ overTarget }}</strong></div>
    <div class="healthy"><span>{{ zh ? '最近解决' : 'Recently resolved' }}</span><strong>{{ resolved.length }}</strong></div>
    <div><span>{{ zh ? '平均恢复时间' : 'Mean recovery' }}</span><strong class="small-value">{{ meanRecoveryMinutes === null ? '—' : `${meanRecoveryMinutes} ${zh ? '分钟' : 'min'}` }}</strong></div>
  </section>

  <section class="proto-section">
    <div class="proto-toolbar incident-toolbar">
      <label class="proto-field-search"><Search :size="16" /><input v-model="query" type="search" :placeholder="zh ? '搜索标题、资源或 Owner' : 'Search title, resource or owner'" /></label>
      <div class="proto-segmented">
        <button :class="{ active: filter === 'active' }" type="button" @click="filter = 'active'">{{ zh ? '活动' : 'Active' }} {{ active.length }}</button>
        <button :class="{ active: filter === 'resolved' }" type="button" @click="filter = 'resolved'">{{ zh ? '已解决' : 'Resolved' }} {{ resolved.length }}</button>
        <button :class="{ active: filter === 'all' }" type="button" @click="filter = 'all'">{{ zh ? '全部' : 'All' }}</button>
      </div>
      <label class="v3-compact-select"><Filter :size="15" /><span class="sr-only">{{ zh ? '严重等级' : 'Severity' }}</span><select v-model="severityFilter"><option value="all">{{ zh ? '全部等级' : 'All severities' }}</option><option v-for="level in [1, 2, 3, 4, 5]" :key="level" :value="String(level)">S{{ level }}</option></select></label>
      <label class="v3-compact-select"><span class="sr-only">Owner</span><select v-model="ownerFilter"><option value="all">{{ zh ? '全部 Owner' : 'All owners' }}</option><option value="unassigned">{{ zh ? '未分配' : 'Unassigned' }}</option><option v-for="user in users" :key="user.id" :value="user.id">{{ user.email }}</option></select></label>
      <label class="v3-compact-select"><span class="sr-only">{{ zh ? '来源' : 'Source' }}</span><select v-model="sourceFilter"><option value="all">{{ zh ? '全部来源' : 'All sources' }}</option><option v-for="source in availableSources" :key="source" :value="source">{{ source.replaceAll('_', ' ') }}</option></select></label>
      <label class="v3-compact-select"><span class="sr-only">{{ zh ? '记录类型' : 'Record type' }}</span><select v-model="recordFilter"><option value="all">{{ zh ? '全部记录' : 'All records' }}</option><option value="real">{{ zh ? '真实事故' : 'Operational only' }}</option><option value="test">{{ zh ? '测试记录' : 'Test records' }}</option></select></label>
      <label class="v3-compact-select"><span class="sr-only">{{ zh ? '创建时间' : 'Created' }}</span><select v-model="ageFilter"><option value="all">{{ zh ? '全部时间' : 'Any time' }}</option><option value="24h">{{ zh ? '最近 24 小时' : 'Last 24 hours' }}</option><option value="7d">{{ zh ? '最近 7 天' : 'Last 7 days' }}</option></select></label>
      <label class="v3-compact-select"><span class="sr-only">{{ zh ? '排序' : 'Sort' }}</span><select v-model="sortBy"><option value="updated">{{ zh ? '最后更新' : 'Updated' }}</option><option value="created">{{ zh ? '创建时间' : 'Created' }}</option></select><ChevronDown :size="14" /></label>
    </div>

    <DataTable :label="zh ? '事故' : 'Incidents'" table-class="incidents-table" :loading="loading" :error="error" :empty="!filtered.length" :total="filtered.length" @retry="load">
      <template #head><tr><th>{{ zh ? '等级' : 'Severity' }}</th><th>{{ zh ? '事故' : 'Incident' }}</th><th>{{ zh ? '影响资源' : 'Impact' }}</th><th>{{ zh ? '状态' : 'Status' }}</th><th>Owner</th><th>{{ zh ? '来源' : 'Source' }}</th><th>{{ zh ? '创建时间' : 'Created' }}</th><th>{{ zh ? '持续时间' : 'Duration' }}</th><th>{{ zh ? '最后更新' : 'Updated' }}</th><th>{{ zh ? '下一步' : 'Next action' }}</th></tr></template>
      <tr v-for="incident in filtered" :key="incident.id" :class="{ selected: selected?.id === incident.id, 'is-selected': selected?.id === incident.id }" :aria-selected="selected?.id === incident.id" tabindex="0" @click="selected = incident" @keydown.enter="selected = incident">
            <td><StatusBadge :tone="severityTone(incident.severity)" :label="`S${incident.severity}`" compact /></td>
            <td><strong>{{ title(incident) }}</strong><small>{{ sourceLabel(incident) }} <span v-if="isTestRecord(incident)" class="proto-test-label">{{ zh ? '测试记录' : 'Test record' }}</span></small></td>
            <td>{{ affected(incident) }}</td><td><StatusBadge :tone="statusTone(incident.status)" :label="statusLabel(incident.status)" compact /></td>
            <td>{{ ownerName(incident) }}</td><td>{{ sourceLabel(incident) }}</td><td><time :title="formatTime(incident.first_seen_at)">{{ formatTime(incident.first_seen_at) }}</time></td>
            <td>{{ age(incident) }}</td><td>{{ relativeTime(incident.updated_at) }}</td>
            <td><button class="proto-row-action" type="button">{{ nextAction(incident) }} <ChevronRight :size="13" /></button></td>
      </tr>
      <template #empty><span>{{ zh ? '当前筛选没有匹配事故。' : 'No incidents match the current filters.' }}</span><button class="proto-text-button" type="button" @click="clearFilters">{{ zh ? '清除筛选' : 'Clear filters' }}</button></template>
    </DataTable>
    <div v-if="!loading && incidents.some(isTestRecord)" class="proto-list-foot"><span>{{ zh ? '历史测试事故已明确标记；S5 信息事件不参与首屏严重健康判断。' : 'Historical test incidents are labelled; S5 informational items do not drive critical health.' }}</span><strong>{{ zh ? `显示 ${filtered.length} 项` : `${filtered.length} shown` }}</strong></div>
  </section>

  <DetailDrawer :open="Boolean(selected)" :eyebrow="zh ? '事故详情' : 'Incident details'" :title="selected ? title(selected) : ''" @close="selected = null">
    <template v-if="selected">
      <section class="proto-drawer-summary">
        <div class="proto-drawer-status-row"><StatusBadge :tone="severityTone(selected.severity)" :label="`S${selected.severity}`" /><StatusBadge :tone="statusTone(selected.status)" :label="statusLabel(selected.status)" /></div>
        <p>{{ riskSummary(selected) }}</p>
        <span>{{ affected(selected) }} · Owner {{ ownerName(selected) }}</span>
      </section>
      <section class="proto-definition-grid">
        <div><span>{{ zh ? '创建时间' : 'Created' }}</span><strong>{{ formatTime(selected.first_seen_at) }}</strong></div>
        <div><span>{{ zh ? '持续时间' : 'Duration' }}</span><strong>{{ age(selected) }}</strong></div>
        <div><span>{{ zh ? '最后更新' : 'Updated' }}</span><strong>{{ relativeTime(selected.updated_at) }}</strong></div>
        <div><span>{{ zh ? '来源' : 'Source' }}</span><strong>{{ sourceLabel(selected) }}</strong></div>
      </section>
      <section class="proto-drawer-section"><h3>{{ zh ? '下一步决策' : 'Next decision' }}</h3><div class="proto-next-action"><strong>{{ nextAction(selected) }}</strong><span>{{ zh ? '确认 Owner、影响范围和执行窗口后再采取修复操作。' : 'Confirm owner, impact and execution window before remediation.' }}</span><button v-if="canOperate && selected.status !== 'resolved' && selected.status !== 'mitigating'" class="proto-button primary" type="button" :disabled="updating" @click="advanceIncident">{{ updating ? (zh ? '更新中…' : 'Updating…') : nextAction(selected) }}</button></div></section>
      <section class="proto-drawer-section">
        <h3>{{ zh ? '时间线' : 'Timeline' }}</h3>
        <ol v-if="selected.timeline.length" class="proto-timeline"><li v-for="(entry, index) in selected.timeline" :key="index"><i></i><div><strong>{{ timelineTitle(entry) }}</strong><span>{{ relativeTime(timelineTime(entry)) }}</span></div></li></ol>
        <ol v-else class="proto-timeline"><li><i></i><div><strong>{{ zh ? '事故已创建' : 'Incident created' }}</strong><span>{{ relativeTime(selected.first_seen_at) }}</span><p>{{ sourceLabel(selected) }}</p></div></li></ol>
      </section>
      <section v-if="selected.evidence.length" class="proto-drawer-section"><h3>{{ zh ? '证据' : 'Evidence' }}</h3><p class="v3-muted-copy">{{ zh ? `${selected.evidence.length} 条证据已保留；原始内容只在受控证据查看器中按需显示。` : `${selected.evidence.length} evidence item(s) retained; raw content is available on demand.` }}</p></section>
    </template>
  </DetailDrawer>
</template>
