<script setup lang="ts">
import { ChevronDown, ChevronRight, Ellipsis, Filter, Plus, RefreshCw, Search, SlidersHorizontal, X } from '@lucide/vue'
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import DetailDrawer from '../components/v3/DetailDrawer.vue'
import PageHeader from '../components/v3/PageHeader.vue'
import StatusBadge, { type StatusTone } from '../components/v3/StatusBadge.vue'
import { session } from '../session'
import type { Agent, Host, ServiceCheck, ServiceCheckResult, ServiceSummary } from '../types'
import { formatTime, relativeTime } from '../utils'

const route = useRoute()
const router = useRouter()
const { locale } = useI18n()
const zh = computed(() => locale.value === 'zh-CN')
const checks = ref<ServiceCheck[]>([])
const observations = ref<ServiceSummary[]>([])
const hosts = ref<Host[]>([])
const agents = ref<Agent[]>([])
const results = ref<ServiceCheckResult[]>([])
const query = ref(typeof route.query.q === 'string' ? route.query.q : '')
const filter = ref<'all' | 'issues'>(route.query.status === 'issues' ? 'issues' : 'all')
const hostFilter = ref(typeof route.query.host === 'string' ? route.query.host : 'all')
const kindFilter = ref(typeof route.query.kind === 'string' ? route.query.kind : 'all')
const groupBy = ref<'none' | 'host' | 'type'>(
  route.query.group === 'host' || route.query.group === 'type' ? route.query.group : 'none',
)
const sortBy = ref<'updated' | 'name'>(route.query.sort === 'name' ? 'name' : 'updated')
const compact = ref(localStorage.getItem('guardian_service_density') === 'compact')
const selectedIds = ref(new Set<string>())
const page = ref(1)
const pageSize = 25
const batchInterval = ref(60)
const batchUpdating = ref(false)
const loading = ref(true)
const error = ref('')
const selectedCheck = ref<ServiceCheck | null>(null)
const selectedObservation = ref<ServiceSummary | null>(null)
const evidenceOpen = ref(false)
const evidenceWrap = ref(true)
const evidenceFullscreen = ref(false)
const creating = ref(false)
const dialog = ref<HTMLDialogElement | null>(null)
const canManage = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const newCheck = ref({
  name: '',
  kind: 'https' as ServiceCheck['kind'],
  target: '',
  port: 443,
  host_id: '',
  runner_agent_id: '',
  interval_seconds: 60,
  timeout_seconds: 5,
  failure_threshold: 3,
  recovery_threshold: 2,
  severity: 'warning' as ServiceCheck['severity'],
})

const latestResults = computed(() => {
  const output = new Map<string, ServiceCheckResult>()
  for (const result of results.value) {
    if (!output.has(result.check_id)) output.set(result.check_id, result)
  }
  return output
})

function checkTone(check: ServiceCheck): StatusTone {
  if (!check.enabled) return 'neutral'
  const result = latestResults.value.get(check.id)
  if (!result) return 'neutral'
  if (result.status === 'ok') return 'healthy'
  if (result.status === 'unsupported') return 'neutral'
  return check.severity === 'critical' ? 'critical' : 'warning'
}

function statusLabel(value: StatusTone | ServiceSummary['status']): string {
  const labels: Record<string, [string, string]> = {
    healthy: ['正常', 'Healthy'],
    warning: ['警告', 'Warning'],
    critical: ['严重', 'Critical'],
    neutral: ['无数据', 'No data'],
    execution_failed: ['执行失败', 'Execution failed'],
    no_data: ['无数据', 'No data'],
    unsupported: ['不支持', 'Unsupported'],
    parse_failed: ['解析失败', 'Parse failed'],
  }
  return labels[value]?.[zh.value ? 0 : 1] ?? value
}

function observationTone(value: ServiceSummary['status']): StatusTone {
  if (value === 'healthy') return 'healthy'
  if (value === 'warning') return 'warning'
  if (value === 'critical' || value === 'execution_failed') return 'critical'
  return 'neutral'
}

function displayName(check: ServiceCheck): string {
  const tokens = check.name
    .replace(/^phase\d+[a-z]?-?/i, '')
    .split(/[-_.]+/)
    .filter(Boolean)
  const known: Record<string, string> = {
    controller: 'Controller',
    docker: 'Docker',
    systemd: 'systemd',
    gateway: 'Gateway',
    http: 'HTTP',
    https: 'HTTPS',
    tcp: 'TCP',
    icmp: 'ICMP',
    postgres: 'Database',
    postgresql: 'Database',
    journal: 'Journal',
  }
  const output = tokens.map((token) => known[token.toLowerCase()] ?? `${token[0].toUpperCase()}${token.slice(1)}`)
  return output.length > 1 ? `${output[0]} · ${output.slice(1).join(' ')}` : output[0] || check.name
}

function targetName(check: ServiceCheck): string {
  if (check.host_id) return hosts.value.find((host) => host.id === check.host_id)?.name ?? (zh.value ? '已登记主机' : 'Registered host')
  const target = check.configuration.target
  return typeof target === 'string' ? target : zh.value ? 'Controller' : 'Controller'
}

function latestResult(check: ServiceCheck): string {
  const result = latestResults.value.get(check.id)
  if (!result) return zh.value ? '等待首次执行' : 'Waiting for first run'
  if (result.message) {
    if (!zh.value || /[\u4e00-\u9fff]/u.test(result.message)) return result.message
    if (/check passed|healthy|success/i.test(result.message)) return '检查通过'
    if (/timeout/i.test(result.message)) return '检查超时'
    return result.status === 'ok' ? '检查通过' : '检查未通过；请查看受控证据'
  }
  if (result.status === 'ok') return zh.value ? '检查通过' : 'Check passed'
  return statusLabel(result.status === 'failed' ? checkTone(check) : 'neutral')
}

function successRate(check: ServiceCheck): string {
  const sample = results.value.filter((result) => result.check_id === check.id)
  if (!sample.length) return '—'
  const successes = sample.filter((result) => result.status === 'ok').length
  return `${((successes / sample.length) * 100).toFixed(1)}%`
}

function consecutiveFailures(check: ServiceCheck): number {
  let count = 0
  for (const result of results.value.filter((item) => item.check_id === check.id)) {
    if (result.status === 'ok') break
    count += 1
  }
  return count
}

const filteredChecks = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const output = checks.value.filter((check) => {
    if (filter.value === 'issues' && checkTone(check) === 'healthy') return false
    if (hostFilter.value !== 'all' && check.host_id !== hostFilter.value) return false
    if (kindFilter.value !== 'all' && check.kind !== kindFilter.value) return false
    return !needle || `${displayName(check)} ${check.name} ${targetName(check)} ${check.kind}`.toLowerCase().includes(needle)
  })
  return output.sort((left, right) => {
    if (groupBy.value === 'host') {
      const grouped = targetName(left).localeCompare(targetName(right))
      if (grouped) return grouped
    }
    if (groupBy.value === 'type') {
      const grouped = left.kind.localeCompare(right.kind)
      if (grouped) return grouped
    }
    if (sortBy.value === 'name') return displayName(left).localeCompare(displayName(right))
    return (right.last_checked_at ?? '').localeCompare(left.last_checked_at ?? '')
  })
})
const pageCount = computed(() => Math.max(1, Math.ceil(filteredChecks.value.length / pageSize)))
const pagedChecks = computed(() =>
  filteredChecks.value.slice((page.value - 1) * pageSize, page.value * pageSize),
)
const allPageSelected = computed(() =>
  pagedChecks.value.length > 0 && pagedChecks.value.every((check) => selectedIds.value.has(check.id)),
)
const availableKinds = computed(() => [...new Set(checks.value.map((check) => check.kind))].sort())

const counts = computed(() => ({
  total: checks.value.length,
  healthy: checks.value.filter((check) => checkTone(check) === 'healthy').length,
  warning: checks.value.filter((check) => checkTone(check) === 'warning').length,
  critical: checks.value.filter((check) => checkTone(check) === 'critical').length,
  noData: checks.value.filter((check) => checkTone(check) === 'neutral').length,
}))

const observationCounts = computed(() => ({
  healthy: observations.value.filter((item) => item.status === 'healthy').length,
  issue: observations.value.filter((item) => ['warning', 'critical', 'execution_failed', 'parse_failed'].includes(item.status)).length,
}))
const formattedEvidence = computed(() => {
  const summary = selectedObservation.value?.summary ?? ''
  try {
    return JSON.stringify(JSON.parse(summary), null, 2)
  } catch {
    return summary
  }
})

watch([query, filter, hostFilter, kindFilter, groupBy, sortBy], () => {
  page.value = 1
  void router.replace({
    query: {
      ...route.query,
      q: query.value || undefined,
      status: filter.value === 'issues' ? 'issues' : undefined,
      host: hostFilter.value === 'all' ? undefined : hostFilter.value,
      kind: kindFilter.value === 'all' ? undefined : kindFilter.value,
      group: groupBy.value === 'none' ? undefined : groupBy.value,
      sort: sortBy.value === 'updated' ? undefined : sortBy.value,
    },
  })
})

watch(compact, (value) => localStorage.setItem('guardian_service_density', value ? 'compact' : 'comfortable'))

async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    ;[checks.value, observations.value, results.value, hosts.value] = await Promise.all([
      request<ServiceCheck[]>('/api/v1/service-checks'),
      request<ServiceSummary[]>('/api/v1/services'),
      request<ServiceCheckResult[]>('/api/v1/service-check-results?limit=100'),
      request<Host[]>('/api/v1/hosts'),
    ])
  } catch {
    error.value = zh.value ? '服务检查加载失败。' : 'Failed to load service checks.'
  } finally {
    loading.value = false
  }
}

async function openCreate(): Promise<void> {
  if (!agents.value.length) agents.value = await request<Agent[]>('/api/v1/agents')
  dialog.value?.showModal()
}

function configuration(): Record<string, unknown> {
  if (newCheck.value.kind === 'docker') return { container: newCheck.value.target }
  if (newCheck.value.kind === 'systemd') return { unit: newCheck.value.target }
  if (newCheck.value.kind === 'tcp') return { target: newCheck.value.target, port: newCheck.value.port }
  if (newCheck.value.kind === 'icmp') return { target: newCheck.value.target }
  return { target: newCheck.value.target, expected_statuses: [200], max_response_bytes: 65536 }
}

async function createCheck(): Promise<void> {
  creating.value = true
  try {
    await request<ServiceCheck>('/api/v1/service-checks', {
      method: 'POST',
      ...jsonBody({
        name: newCheck.value.name,
        kind: newCheck.value.kind,
        configuration: configuration(),
        host_id: newCheck.value.host_id || null,
        runner_agent_id: newCheck.value.runner_agent_id || null,
        interval_seconds: newCheck.value.interval_seconds,
        timeout_seconds: newCheck.value.timeout_seconds,
        failure_threshold: newCheck.value.failure_threshold,
        recovery_threshold: newCheck.value.recovery_threshold,
        severity: newCheck.value.severity,
      }),
    })
    dialog.value?.close()
    newCheck.value.name = ''
    newCheck.value.target = ''
    await load()
  } finally {
    creating.value = false
  }
}

async function deleteSelectedCheck(): Promise<void> {
  if (!selectedCheck.value) return
  const message = zh.value
    ? `删除“${displayName(selectedCheck.value)}”会同时移除关联告警规则。此操作不可撤销，是否继续？`
    : `Deleting “${displayName(selectedCheck.value)}” also removes linked alert rules. Continue?`
  if (!window.confirm(message)) return
  await request<void>(`/api/v1/service-checks/${selectedCheck.value.id}`, { method: 'DELETE' })
  selectedCheck.value = null
  await load()
}

function selectCheck(check: ServiceCheck): void {
  selectedObservation.value = null
  selectedCheck.value = check
  evidenceOpen.value = false
}

function selectObservation(observation: ServiceSummary): void {
  selectedCheck.value = null
  selectedObservation.value = observation
  evidenceOpen.value = false
}

function closeDrawer(): void {
  selectedCheck.value = null
  selectedObservation.value = null
  evidenceOpen.value = false
  evidenceFullscreen.value = false
}

function clearFilters(): void {
  query.value = ''
  filter.value = 'all'
  hostFilter.value = 'all'
  kindFilter.value = 'all'
}

function toggleSelection(checkId: string): void {
  const next = new Set(selectedIds.value)
  next.has(checkId) ? next.delete(checkId) : next.add(checkId)
  selectedIds.value = next
}

function togglePageSelection(): void {
  const next = new Set(selectedIds.value)
  for (const check of pagedChecks.value) {
    if (allPageSelected.value) next.delete(check.id)
    else next.add(check.id)
  }
  selectedIds.value = next
}

async function applyBatch(update: { enabled?: boolean; interval_seconds?: number }): Promise<void> {
  if (!selectedIds.value.size) return
  batchUpdating.value = true
  try {
    await Promise.all(
      [...selectedIds.value].map((checkId) =>
        request<ServiceCheck>(`/api/v1/service-checks/${checkId}`, {
          method: 'PATCH',
          ...jsonBody(update),
        }),
      ),
    )
    selectedIds.value = new Set()
    await load()
  } finally {
    batchUpdating.value = false
  }
}

async function copyEvidence(): Promise<void> {
  if (!selectedObservation.value || !navigator.clipboard) return
  await navigator.clipboard.writeText(formattedEvidence.value)
}

function downloadEvidence(): void {
  if (!selectedObservation.value) return
  const blob = new Blob([formattedEvidence.value], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `guardian-evidence-${selectedObservation.value.kind}.txt`
  anchor.click()
  URL.revokeObjectURL(url)
}

onMounted(load)
</script>

<template>
  <PageHeader
    eyebrow="Staging / Services"
    :title="zh ? '服务检查' : 'Service checks'"
    :description="zh ? '比较检查状态，在不丢失上下文的情况下查看证据。' : 'Compare check health and inspect evidence without losing context.'"
    :updated="checks.length ? `${relativeTime(checks.map((check) => check.last_checked_at).filter(Boolean).sort().at(-1))}` : undefined"
  >
    <template #actions>
      <button class="proto-button secondary" type="button" :disabled="loading" @click="load"><RefreshCw :size="15" />{{ zh ? '刷新' : 'Refresh' }}</button>
      <button v-if="canManage" class="proto-button primary" type="button" @click="openCreate"><Plus :size="15" />{{ zh ? '新建检查' : 'New check' }}</button>
    </template>
  </PageHeader>

  <section class="proto-inline-metrics" aria-label="检查摘要">
    <div><span>{{ zh ? '已配置' : 'Configured' }}</span><strong>{{ counts.total }}</strong></div>
    <div class="healthy"><span>{{ zh ? '正常' : 'Healthy' }}</span><strong>{{ counts.healthy }}</strong></div>
    <div class="warning"><span>{{ zh ? '警告' : 'Warning' }}</span><strong>{{ counts.warning }}</strong></div>
    <div class="critical"><span>{{ zh ? '严重' : 'Critical' }}</span><strong>{{ counts.critical }}</strong></div>
    <div><span>{{ zh ? '无数据' : 'No data' }}</span><strong>{{ counts.noData }}</strong></div>
    <div><span>{{ zh ? '最近执行' : 'Latest run' }}</span><strong class="small-value">{{ relativeTime(checks.map((check) => check.last_checked_at).filter(Boolean).sort().at(-1)) }}</strong></div>
  </section>

  <section class="proto-section">
    <div class="proto-toolbar">
      <label class="proto-field-search"><Search :size="16" /><input v-model="query" type="search" :placeholder="zh ? '搜索名称、目标或类型' : 'Search name, target or type'" /></label>
      <div class="proto-segmented" aria-label="状态筛选">
        <button :class="{ active: filter === 'all' }" type="button" @click="filter = 'all'">{{ zh ? '全部' : 'All' }} {{ counts.total }}</button>
        <button :class="{ active: filter === 'issues' }" type="button" @click="filter = 'issues'">{{ zh ? '只看异常' : 'Issues only' }} {{ counts.warning + counts.critical + counts.noData }}</button>
      </div>
      <label class="v3-compact-select"><Filter :size="15" /><span class="sr-only">{{ zh ? '主机' : 'Host' }}</span><select v-model="hostFilter"><option value="all">{{ zh ? '全部主机' : 'All hosts' }}</option><option v-for="host in hosts" :key="host.id" :value="host.id">{{ host.name }}</option></select></label>
      <label class="v3-compact-select"><span class="sr-only">{{ zh ? '类型' : 'Type' }}</span><select v-model="kindFilter"><option value="all">{{ zh ? '全部类型' : 'All types' }}</option><option v-for="kind in availableKinds" :key="kind" :value="kind">{{ kind.toUpperCase() }}</option></select></label>
      <label class="v3-compact-select"><SlidersHorizontal :size="15" /><span class="sr-only">{{ zh ? '分组' : 'Group' }}</span><select v-model="groupBy"><option value="none">{{ zh ? '不分组' : 'No grouping' }}</option><option value="host">{{ zh ? '按主机' : 'By host' }}</option><option value="type">{{ zh ? '按类型' : 'By type' }}</option></select></label>
      <label class="v3-compact-select"><span class="sr-only">{{ zh ? '排序' : 'Sort' }}</span><select v-model="sortBy"><option value="updated">{{ zh ? '最近更新' : 'Recently updated' }}</option><option value="name">{{ zh ? '名称' : 'Name' }}</option></select></label>
      <button class="proto-button secondary density-button" type="button" @click="compact = !compact">{{ compact ? (zh ? '舒适' : 'Comfortable') : (zh ? '紧凑' : 'Compact') }} <ChevronDown :size="14" /></button>
    </div>

    <div v-if="selectedIds.size" class="v3-batch-bar">
      <strong>{{ zh ? `已选 ${selectedIds.size} 项` : `${selectedIds.size} selected` }}</strong>
      <button class="proto-button secondary" type="button" :disabled="batchUpdating" @click="applyBatch({ enabled: true })">{{ zh ? '批量启用' : 'Enable' }}</button>
      <button class="proto-button secondary" type="button" :disabled="batchUpdating" @click="applyBatch({ enabled: false })">{{ zh ? '批量停用' : 'Disable' }}</button>
      <label><span>{{ zh ? '周期' : 'Interval' }}</span><select v-model.number="batchInterval"><option v-for="value in [30, 60, 300, 900]" :key="value" :value="value">{{ value }}s</option></select></label>
      <button class="proto-button secondary" type="button" :disabled="batchUpdating" @click="applyBatch({ interval_seconds: batchInterval })">{{ zh ? '应用周期' : 'Apply interval' }}</button>
      <button class="proto-text-button" type="button" @click="selectedIds = new Set()">{{ zh ? '清除选择' : 'Clear' }}</button>
    </div>

    <div v-if="error" class="v3-module-state error-state" role="alert"><strong>{{ error }}</strong><button class="proto-button secondary" type="button" @click="load">{{ zh ? '重试' : 'Retry' }}</button></div>
    <div v-else-if="loading" class="v3-table-skeleton" aria-label="正在加载检查"><span v-for="index in 7" :key="index"></span></div>
    <div v-else-if="filteredChecks.length" class="proto-table-shell">
      <table class="proto-table services-table" :class="{ 'is-compact': compact }">
        <thead><tr><th>{{ zh ? '状态' : 'Status' }}</th><th>{{ zh ? '检查' : 'Check' }}</th><th>{{ zh ? '目标' : 'Target' }}</th><th>{{ zh ? '类型' : 'Type' }}</th><th>{{ zh ? '周期' : 'Interval' }}</th><th>{{ zh ? '连续失败' : 'Failures' }}</th><th>{{ zh ? '最近结果' : 'Latest result' }}</th><th>{{ zh ? '延迟' : 'Latency' }}</th><th>{{ zh ? '更新时间' : 'Updated' }}</th><th>{{ zh ? '成功率' : 'Success rate' }}</th><th><label class="v3-row-check"><input type="checkbox" :checked="allPageSelected" :aria-label="zh ? '选择当前页' : 'Select current page'" @change="togglePageSelection" /></label></th></tr></thead>
        <tbody>
          <tr v-for="check in pagedChecks" :key="check.id" :class="{ selected: selectedCheck?.id === check.id, 'batch-selected': selectedIds.has(check.id) }" tabindex="0" @click="selectCheck(check)" @keydown.enter="selectCheck(check)">
            <td><StatusBadge :tone="checkTone(check)" :label="statusLabel(checkTone(check))" compact /></td>
            <td><strong>{{ displayName(check) }}</strong><small>{{ check.name }}</small></td>
            <td>{{ targetName(check) }}</td><td>{{ check.kind.toUpperCase() }}</td><td>{{ check.interval_seconds }}s</td>
            <td><span :class="{ 'warning-text': consecutiveFailures(check) }">{{ consecutiveFailures(check) }}</span></td>
            <td>{{ latestResult(check) }}</td>
            <td>{{ latestResults.get(check.id)?.latency_ms == null ? '—' : `${latestResults.get(check.id)?.latency_ms?.toFixed(0)} ms` }}</td>
            <td>{{ relativeTime(check.last_checked_at) }}</td><td>{{ successRate(check) }}</td>
            <td class="v3-row-actions"><label class="v3-row-check" @click.stop><input type="checkbox" :checked="selectedIds.has(check.id)" :aria-label="`${zh ? '选择' : 'Select'} ${displayName(check)}`" @change="toggleSelection(check.id)" /></label><button class="proto-icon-button small" type="button" :aria-label="`${displayName(check)} ${zh ? '操作' : 'actions'}`"><Ellipsis :size="17" /></button></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="v3-empty-inline"><span>{{ zh ? '当前筛选没有匹配检查。' : 'No checks match the current filters.' }}</span><button class="proto-text-button" type="button" @click="clearFilters">{{ zh ? '清除筛选' : 'Clear filters' }}</button></div>
    <div v-if="filteredChecks.length > pageSize" class="v3-pagination"><span>{{ page }} / {{ pageCount }}</span><button class="proto-button secondary" type="button" :disabled="page <= 1" @click="page -= 1">{{ zh ? '上一页' : 'Previous' }}</button><button class="proto-button secondary" type="button" :disabled="page >= pageCount" @click="page += 1">{{ zh ? '下一页' : 'Next' }}</button></div>
  </section>

  <section class="proto-section observation-section">
    <div class="proto-section-heading">
      <div><h2>{{ zh ? 'Agent 观察摘要' : 'Agent observation summary' }}</h2><p>{{ zh ? '结构化解析最近采集结果；原始证据默认关闭。' : 'Latest observations are parsed; raw evidence is collapsed by default.' }}</p></div>
      <div class="proto-observation-counts"><span><b>{{ observationCounts.healthy }}</b> {{ zh ? '正常' : 'healthy' }}</span><span><b>{{ observationCounts.issue }}</b> {{ zh ? '异常' : 'issues' }}</span></div>
    </div>
    <div v-if="observations.length" class="proto-observation-list">
      <button v-for="observation in observations" :key="`${observation.host_id}-${observation.kind}`" type="button" @click="selectObservation(observation)">
        <StatusBadge :tone="observationTone(observation.status)" :label="statusLabel(observation.status)" />
        <div><strong>{{ observation.kind.replace('_failed', '') }}</strong><span>{{ zh && observation.status === 'healthy' && observation.kind === 'systemd_failed' ? '未发现失败的 systemd unit' : observation.reason }}</span></div>
        <span>{{ observation.host_name }} · {{ relativeTime(observation.collected_at) }}</span><ChevronRight :size="16" />
      </button>
    </div>
    <div v-else-if="!loading" class="v3-empty-inline">{{ zh ? '尚无 Agent 观察结果。' : 'No agent observations yet.' }}</div>
  </section>

  <DetailDrawer
    :open="Boolean(selectedCheck || selectedObservation)"
    :eyebrow="selectedCheck ? (zh ? '检查详情' : 'Check details') : (zh ? '观察详情' : 'Observation details')"
    :title="selectedCheck ? displayName(selectedCheck) : selectedObservation?.kind.replace('_failed', '') ?? ''"
    @close="closeDrawer"
  >
    <template v-if="selectedCheck">
      <section class="proto-drawer-summary">
        <StatusBadge :tone="checkTone(selectedCheck)" :label="statusLabel(checkTone(selectedCheck))" />
        <p>{{ latestResult(selectedCheck) }}</p><span>{{ targetName(selectedCheck) }} · {{ relativeTime(selectedCheck.last_checked_at) }}</span>
      </section>
      <section class="proto-definition-grid">
        <div><span>{{ zh ? '24 小时成功率' : '24h success rate' }}</span><strong>{{ successRate(selectedCheck) }}</strong></div>
        <div><span>{{ zh ? '最近延迟' : 'Latest latency' }}</span><strong>{{ latestResults.get(selectedCheck.id)?.latency_ms == null ? '—' : `${latestResults.get(selectedCheck.id)?.latency_ms?.toFixed(0)} ms` }}</strong></div>
        <div><span>{{ zh ? '执行周期' : 'Interval' }}</span><strong>{{ selectedCheck.interval_seconds }}s</strong></div>
        <div><span>{{ zh ? '连续失败' : 'Consecutive failures' }}</span><strong>{{ consecutiveFailures(selectedCheck) }}</strong></div>
        <div><span>{{ zh ? '失败阈值' : 'Failure threshold' }}</span><strong>{{ selectedCheck.failure_threshold }}</strong></div>
        <div><span>{{ zh ? '恢复阈值' : 'Recovery threshold' }}</span><strong>{{ selectedCheck.recovery_threshold }}</strong></div>
      </section>
      <section class="proto-drawer-section"><h3>{{ zh ? '配置' : 'Configuration' }}</h3><dl class="v3-config-list"><div><dt>ID</dt><dd>{{ selectedCheck.name }}</dd></div><div><dt>{{ zh ? '类型' : 'Type' }}</dt><dd>{{ selectedCheck.kind }}</dd></div><div><dt>{{ zh ? '等级' : 'Severity' }}</dt><dd>{{ selectedCheck.severity }}</dd></div></dl></section>
      <section v-if="canManage" class="proto-drawer-section v3-danger-zone"><h3>{{ zh ? '危险操作' : 'Danger zone' }}</h3><p>{{ zh ? '删除会同时移除关联告警规则，并写入审计日志。' : 'Deletion also removes linked alert rules and is audited.' }}</p><button class="proto-button secondary" type="button" @click="deleteSelectedCheck">{{ zh ? '删除检查…' : 'Delete check…' }}</button></section>
    </template>
    <template v-else-if="selectedObservation">
      <section class="proto-drawer-summary">
        <StatusBadge :tone="observationTone(selectedObservation.status)" :label="statusLabel(selectedObservation.status)" />
        <p>{{ zh && selectedObservation.status === 'healthy' && selectedObservation.kind === 'systemd_failed' ? '未发现失败的 systemd unit' : selectedObservation.reason }}</p>
        <span>{{ selectedObservation.host_name }} · {{ relativeTime(selectedObservation.collected_at) }}</span>
      </section>
      <section class="proto-drawer-section"><h3>{{ zh ? '结构化摘要' : 'Structured summary' }}</h3><dl class="v3-config-list"><div v-for="(value, key) in selectedObservation.counts" :key="key"><dt>{{ key }}</dt><dd>{{ value }}</dd></div><div><dt>{{ zh ? '解析状态' : 'Parse status' }}</dt><dd>{{ selectedObservation.parsed ? (zh ? '成功' : 'Parsed') : (zh ? '未解析' : 'Not parsed') }}</dd></div></dl></section>
      <section class="proto-drawer-section">
        <button class="proto-evidence-toggle" type="button" :aria-expanded="evidenceOpen" @click="evidenceOpen = !evidenceOpen"><span><strong>{{ zh ? '查看原始证据' : 'View raw evidence' }}</strong><small>{{ formatTime(selectedObservation.collected_at) }} · {{ selectedObservation.parsed ? (zh ? '解析成功' : 'parsed') : (zh ? '解析失败' : 'parse failed') }}</small></span><ChevronDown :class="{ rotated: evidenceOpen }" :size="17" /></button>
        <div v-if="evidenceOpen" class="proto-evidence" :class="{ fullscreen: evidenceFullscreen }">
          <div>
            <span>{{ zh ? '脱敏文本' : 'Redacted text' }}</span>
            <button type="button" @click="evidenceWrap = !evidenceWrap">{{ evidenceWrap ? (zh ? '不换行' : 'No wrap') : (zh ? '自动换行' : 'Wrap') }}</button>
            <button type="button" @click="evidenceFullscreen = !evidenceFullscreen">{{ evidenceFullscreen ? (zh ? '退出全屏' : 'Exit full screen') : (zh ? '全屏' : 'Full screen') }}</button>
            <button type="button" @click="copyEvidence">{{ zh ? '复制' : 'Copy' }}</button>
            <button type="button" @click="downloadEvidence">{{ zh ? '下载脱敏内容' : 'Download redacted' }}</button>
          </div>
          <pre :class="{ nowrap: !evidenceWrap }"><code>{{ formattedEvidence }}</code></pre>
        </div>
      </section>
    </template>
  </DetailDrawer>

  <dialog ref="dialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ zh ? '新建检查' : 'New check' }}</h2><p>{{ zh ? '凭据必须使用受保护的外部引用。' : 'Credentials must use a protected external reference.' }}</p></div><button class="icon-button" :aria-label="zh ? '关闭' : 'Close'"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createCheck">
      <div class="form-grid"><label><span>{{ zh ? '名称' : 'Name' }}</span><input v-model="newCheck.name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{1,119}" /></label><label><span>{{ zh ? '类型' : 'Type' }}</span><select v-model="newCheck.kind"><option v-for="kind in ['http', 'https', 'tcp', 'icmp', 'docker', 'systemd']" :key="kind" :value="kind">{{ kind.toUpperCase() }}</option></select></label></div>
      <label><span>{{ zh ? '目标' : 'Target' }}</span><input v-model="newCheck.target" required /></label>
      <div class="form-grid"><label v-if="newCheck.kind === 'tcp'"><span>Port</span><input v-model.number="newCheck.port" type="number" min="1" max="65535" required /></label><label><span>Runner</span><select v-model="newCheck.runner_agent_id"><option value="">Controller</option><option v-for="agent in agents" :key="agent.id" :value="agent.id">{{ hosts.find((host) => host.id === agent.host_id)?.name || (zh ? '已登记 Agent' : 'Registered agent') }}</option></select></label><label v-if="['docker', 'systemd'].includes(newCheck.kind)"><span>{{ zh ? '主机' : 'Host' }}</span><select v-model="newCheck.host_id" required><option value="" disabled>{{ zh ? '选择主机' : 'Select host' }}</option><option v-for="host in hosts" :key="host.id" :value="host.id">{{ host.name }}</option></select></label></div>
      <div class="form-grid"><label><span>{{ zh ? '周期（秒）' : 'Interval (seconds)' }}</span><input v-model.number="newCheck.interval_seconds" type="number" min="15" max="86400" /></label><label><span>{{ zh ? '超时（秒）' : 'Timeout (seconds)' }}</span><input v-model.number="newCheck.timeout_seconds" type="number" min="1" max="30" /></label></div>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ zh ? '取消' : 'Cancel' }}</button><button class="primary-button" type="submit" :disabled="creating">{{ creating ? (zh ? '创建中…' : 'Creating…') : (zh ? '创建' : 'Create') }}</button></div>
    </form>
  </dialog>
</template>
