<script setup lang="ts">
import { Download, Filter, RefreshCw, Search } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import DataTable from '../components/v3/DataTable.vue'
import DetailDrawer from '../components/v3/DetailDrawer.vue'
import StatusBadge from '../components/v3/StatusBadge.vue'
import { auditActionLabel, auditActorLabel, auditSourceLabel, healthTone, productLabel, resourceTypeLabel, resultLabel } from '../presentationRegistry'
import type { AuditEvidence, AuditPresentation } from '../types'
import { formatTime } from '../utils'

const { locale } = useI18n()
const entries = ref<AuditPresentation[]>([])
const selected = ref<AuditPresentation | null>(null)
const evidence = ref<AuditEvidence | null>(null)
const query = ref('')
const outcome = ref('all')
const category = ref('all')
const severity = ref('all')
const source = ref('all')
const actorType = ref('all')
const resourceType = ref('all')
const timeRange = ref('all')
const loading = ref(true)
const loadError = ref('')
const page = ref(1)
const pageSize = 100
const totalHint = computed(() => (page.value - 1) * pageSize + entries.value.length + (entries.value.length === pageSize ? 1 : 0))

const filtered = computed(() => entries.value.filter((entry) => {
  const needle = query.value.toLocaleLowerCase().trim()
  const primaryText = `${entry.display_action} ${entry.resource_display} ${entry.actor_display} ${entry.source_display} ${entry.correlation_id ?? ''} ${entry.request_id ?? ''}`.toLocaleLowerCase()
  const age = Date.now() - new Date(entry.created_at).getTime()
  return (outcome.value === 'all' || entry.result === outcome.value) &&
    (category.value === 'all' || entry.category === category.value) &&
    (severity.value === 'all' || entry.severity === severity.value) &&
    (source.value === 'all' || entry.source_type === source.value) &&
    (actorType.value === 'all' || entry.actor_type === actorType.value) &&
    (resourceType.value === 'all' || entry.resource_type === resourceType.value) &&
    (timeRange.value === 'all' || age <= (timeRange.value === '24h' ? 86_400_000 : 604_800_000)) &&
    (!needle || primaryText.includes(needle))
}))
const categories = computed(() => [...new Set(entries.value.map((entry) => entry.category))])
const resourceTypes = computed(() => [...new Set(entries.value.map((entry) => entry.resource_type))])
const genericResourceDisplays = new Set(['User', 'Session', 'Host', 'Guardian Agent', 'Alert', 'Incident', 'Approval', 'Service check', 'Unknown resource'])

function resourceDisplay(entry: AuditPresentation): string {
  return genericResourceDisplays.has(entry.resource_display)
    ? resourceTypeLabel(entry.resource_type, locale.value)
    : entry.resource_display
}

async function load(): Promise<void> {
  loading.value = true
  loadError.value = ''
  try {
    entries.value = await request<AuditPresentation[]>(`/api/v1/audit/presentation?limit=${pageSize}&offset=${(page.value - 1) * pageSize}`)
  } catch {
    loadError.value = locale.value === 'zh-CN' ? '无法载入审计记录。' : 'Could not load audit records.'
  } finally {
    loading.value = false
  }
}

async function changePage(direction: -1 | 1): Promise<void> {
  page.value = Math.max(1, page.value + direction)
  selected.value = null
  await load()
}

function selectEntry(entry: AuditPresentation): void {
  selected.value = entry
  evidence.value = null
}

async function loadEvidence(event: Event): Promise<void> {
  const details = event.currentTarget as HTMLDetailsElement
  if (!details.open || evidence.value || !selected.value?.evidence_available) return
  const eventId = selected.value.event_id
  try {
    evidence.value = await request<AuditEvidence>(`/api/v1/audit/${eventId}/evidence`)
  } catch {
    evidence.value = null
  }
}

function exportHref(format: 'csv' | 'jsonl'): string {
  const params = new URLSearchParams({ format })
  if (outcome.value !== 'all') params.set('result', outcome.value)
  if (category.value !== 'all') params.set('category', category.value)
  if (severity.value !== 'all') params.set('severity', severity.value)
  if (source.value !== 'all') params.set('source_type', source.value)
  if (actorType.value !== 'all') params.set('actor_type', actorType.value)
  if (resourceType.value !== 'all') params.set('resource_type', resourceType.value)
  if (query.value.trim()) params.set('query', query.value.trim())
  return `/api/v1/audit/export?${params}`
}

onMounted(load)
</script>

<template>
  <PageHeader :title="$t('audit.title')" :description="$t('audit.description')">
    <template #actions><details class="rc5-export-menu"><summary><Download :size="15" />{{ locale === 'zh-CN' ? '导出' : 'Export' }}</summary><div><a :href="exportHref('csv')">{{ locale === 'zh-CN' ? '脱敏 CSV' : 'Redacted CSV' }}</a><a :href="exportHref('jsonl')">{{ locale === 'zh-CN' ? '脱敏 JSONL' : 'Redacted JSONL' }}</a></div></details><button class="icon-button bordered" type="button" :aria-label="$t('audit.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="toolbar-row rc5-filter-bar">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" :placeholder="$t('audit.searchPlaceholder')" /></label>
    <label class="rc5-filter-control"><span>{{ $t('audit.outcome') }}</span><span class="select-field"><Filter :size="15" /><select v-model="outcome" :aria-label="$t('audit.outcome')"><option value="all">{{ $t('audit.allOutcomes') }}</option><option value="success">{{ resultLabel('success', locale) }}</option><option value="denied">{{ resultLabel('denied', locale) }}</option><option value="failed">{{ resultLabel('failed', locale) }}</option><option value="detected">{{ resultLabel('detected', locale) }}</option></select></span></label>
    <details class="rc5-more-filters"><summary>{{ locale === 'zh-CN' ? '更多筛选' : 'More filters' }}</summary><div>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '类别' : 'Category' }}</span><select v-model="category"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option v-for="value in categories" :key="value" :value="value">{{ resourceTypeLabel(value, locale) }}</option></select></label>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '严重程度' : 'Severity' }}</span><select v-model="severity"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option value="neutral">{{ locale === 'zh-CN' ? '普通' : 'Neutral' }}</option><option value="warning">{{ locale === 'zh-CN' ? '警告' : 'Warning' }}</option><option value="critical">{{ locale === 'zh-CN' ? '严重' : 'Critical' }}</option></select></label>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '来源' : 'Source' }}</span><select v-model="source"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option value="internal_service">{{ locale === 'zh-CN' ? '内部服务' : 'Internal service' }}</option><option value="private_network">{{ locale === 'zh-CN' ? '私有网络' : 'Private network' }}</option><option value="external_client">{{ locale === 'zh-CN' ? '外部客户端' : 'External client' }}</option></select></label>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '时间范围' : 'Time range' }}</span><select v-model="timeRange"><option value="all">{{ locale === 'zh-CN' ? '全部时间' : 'Any time' }}</option><option value="24h">{{ locale === 'zh-CN' ? '最近 24 小时' : 'Last 24 hours' }}</option><option value="7d">{{ locale === 'zh-CN' ? '最近 7 天' : 'Last 7 days' }}</option></select></label>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '操作者' : 'Actor' }}</span><select v-model="actorType"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option value="user">{{ locale === 'zh-CN' ? '用户' : 'User' }}</option><option value="system">{{ locale === 'zh-CN' ? '系统' : 'System' }}</option><option value="agent">Guardian Agent</option><option value="unknown">{{ locale === 'zh-CN' ? '未知' : 'Unknown' }}</option></select></label>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '资源类型' : 'Resource type' }}</span><select v-model="resourceType"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option v-for="value in resourceTypes" :key="value" :value="value">{{ resourceTypeLabel(value, locale) }}</option></select></label>
    </div></details>
    <span class="rc5-result-count">{{ filtered.length }} / {{ entries.length }}</span>
  </div>
  <p v-if="loadError" class="inline-error" role="alert">{{ loadError }}</p>
  <div v-else-if="loading" class="row-skeletons" aria-label="Loading"><span v-for="item in 8" :key="item"></span></div>
  <DataTable v-else-if="filtered.length" :label="$t('audit.title')" :selected-key="selected?.event_id" :page="page" :page-size="pageSize" :total="totalHint" @previous="changePage(-1)" @next="changePage(1)">
    <template #head><tr><th aria-sort="descending">{{ $t('audit.time') }}</th><th>{{ locale === 'zh-CN' ? '严重程度' : 'Severity' }}</th><th>{{ $t('audit.action') }}</th><th>{{ $t('audit.resource') }}</th><th>{{ $t('audit.actor') }}</th><th>{{ $t('audit.source') }}</th><th>{{ $t('audit.outcome') }}</th></tr></template>
    <tr v-for="entry in filtered" :key="entry.event_id" :class="{ 'is-selected': selected?.event_id === entry.event_id }" :aria-selected="selected?.event_id === entry.event_id" tabindex="0" @click="selectEntry(entry)" @keydown.enter="selectEntry(entry)">
      <td :data-label="locale === 'zh-CN' ? '时间' : 'Time'"><span>{{ formatTime(entry.created_at) }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '严重程度' : 'Severity'"><StatusBadge :tone="entry.severity === 'neutral' ? 'neutral' : entry.severity" :label="entry.severity === 'neutral' ? (locale === 'zh-CN' ? '普通' : 'Neutral') : productLabel('severity', entry.severity, locale)" compact /></td>
      <td :data-label="locale === 'zh-CN' ? '动作' : 'Action'"><strong>{{ auditActionLabel(entry.action_code, entry.display_action, locale) }}</strong></td>
      <td :data-label="locale === 'zh-CN' ? '资源' : 'Resource'"><span>{{ resourceDisplay(entry) }}</span><small>{{ resourceTypeLabel(entry.resource_type, locale) }}</small></td>
      <td :data-label="locale === 'zh-CN' ? '操作者' : 'Actor'"><span>{{ auditActorLabel(entry.actor_type, entry.actor_display, locale) }}</span><small>{{ entry.actor_type === 'system' ? (locale === 'zh-CN' ? '系统' : 'System') : (locale === 'zh-CN' ? '用户' : 'User') }}</small></td>
      <td :data-label="locale === 'zh-CN' ? '来源' : 'Source'"><span>{{ auditSourceLabel(entry.source_type, locale) }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '结果' : 'Result'"><StatusBadge :tone="healthTone(entry.result)" :label="resultLabel(entry.result, locale)" compact /></td>
    </tr>
  </DataTable>
  <EmptyState v-else-if="!loading" :title="$t('audit.noMatch')" />

  <DetailDrawer :open="Boolean(selected)" :eyebrow="locale === 'zh-CN' ? '审计详情' : 'Audit detail'" :title="selected ? auditActionLabel(selected.action_code, selected.display_action, locale) : ''" @close="selected = null">
    <div v-if="selected" class="rc5-drawer-body">
      <section class="rc5-fact-grid">
        <div><span>{{ $t('audit.time') }}</span><strong>{{ formatTime(selected.created_at) }}</strong></div>
        <div><span>{{ $t('audit.outcome') }}</span><strong>{{ resultLabel(selected.result, locale) }}</strong></div>
        <div><span>{{ $t('audit.resource') }}</span><strong>{{ resourceDisplay(selected) }}</strong></div>
        <div><span>{{ $t('audit.actor') }}</span><strong>{{ auditActorLabel(selected.actor_type, selected.actor_display, locale) }}</strong></div>
      </section>
      <section class="rc5-drawer-section"><h3>{{ locale === 'zh-CN' ? '事件摘要' : 'Event summary' }}</h3><p>{{ auditActionLabel(selected.action_code, selected.display_action, locale) }} · {{ resourceDisplay(selected) }}</p></section>
      <section class="rc5-drawer-section"><h3>{{ locale === 'zh-CN' ? '来源说明' : 'Source' }}</h3><p>{{ auditSourceLabel(selected.source_type, locale) }}</p></section>
      <details class="rc5-technical" @toggle="loadEvidence">
        <summary>{{ locale === 'zh-CN' ? '技术证据' : 'Technical evidence' }}</summary>
        <dl v-if="evidence"><div><dt>Action code</dt><dd class="mono">{{ evidence.action_code }}</dd></div><div><dt>Resource ID</dt><dd class="mono">{{ evidence.resource_id || '—' }}</dd></div><div><dt>Actor ID</dt><dd class="mono">{{ evidence.actor_id || '—' }}</dd></div><div><dt>Source IP</dt><dd class="mono">{{ evidence.source_ip || '—' }}</dd></div><div><dt>Correlation ID</dt><dd class="mono">{{ selected.correlation_id || '—' }}</dd></div><div><dt>Request ID</dt><dd class="mono">{{ selected.request_id || '—' }}</dd></div><div><dt>{{ locale === 'zh-CN' ? '变更证据' : 'Change evidence' }}</dt><dd class="mono">{{ Object.keys(evidence.changes).length ? JSON.stringify(evidence.changes) : '—' }}</dd></div></dl>
        <p v-else>{{ locale === 'zh-CN' ? '没有可显示的技术证据。' : 'No technical evidence is available.' }}</p>
      </details>
    </div>
  </DetailDrawer>
</template>
