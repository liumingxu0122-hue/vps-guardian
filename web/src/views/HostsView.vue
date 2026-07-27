<script setup lang="ts">
import { Check, Copy, KeyRound, Plus, Power, RefreshCw, Search, Server, Trash2, X } from '@lucide/vue'
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import MetricBar from '../components/MetricBar.vue'
import PageHeader from '../components/PageHeader.vue'
import DataTable from '../components/v3/DataTable.vue'
import DetailDrawer from '../components/v3/DetailDrawer.vue'
import StatusBadge from '../components/v3/StatusBadge.vue'
import { agentLabel, dataReasonLabel, healthLabel, healthTone, managementLabel, regionLabel } from '../presentationRegistry'
import { session } from '../session'
import type { EnrollmentToken, Host, HostPresentation, LatestSnapshot } from '../types'
import { formatBytes, formatDuration, percentUsed, relativeTime } from '../utils'

const { locale, t } = useI18n()
const route = useRoute()
const hosts = ref<HostPresentation[]>([])
const selected = ref<HostPresentation | null>(null)
const snapshot = ref<LatestSnapshot | null>(null)
const query = ref('')
const stateFilter = ref('all')
const managementFilter = ref('all')
const agentFilter = ref('all')
const regionFilter = ref('all')
const groupFilter = ref('all')
const sortBy = ref<'name' | 'health' | 'heartbeat'>('name')
const sortDirection = ref<'asc' | 'desc'>('asc')
const page = ref(1)
const pageSize = 50
const loading = ref(true)
const loadError = ref('')
const dialog = ref<HTMLDialogElement | null>(null)
const tokenDialog = ref<HTMLDialogElement | null>(null)
const issuedToken = ref<EnrollmentToken | null>(null)
const copied = ref(false)
const creating = ref(false)
const formError = ref('')
const selectedIds = ref(new Set<string>())
const batchGroup = ref('')
const batchTag = ref('')
const newHost = ref({ name: '', address: '', location: '', group_name: '' })

const canManage = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const filtered = computed(() => {
  const needle = query.value.trim().toLocaleLowerCase()
  const values = hosts.value.filter((host) => {
    const searchable = [host.name, host.primary_address, host.region ?? '', host.group ?? '', ...host.display_tags]
    const state = host.enabled ? host.data_state : 'disabled'
    return (!needle || searchable.some((value) => value.toLocaleLowerCase().includes(needle))) &&
      (stateFilter.value === 'all' || state === stateFilter.value) &&
      (managementFilter.value === 'all' || host.management === managementFilter.value) &&
      (agentFilter.value === 'all' || host.agent_state === agentFilter.value) &&
      (regionFilter.value === 'all' || host.region === regionFilter.value) &&
      (groupFilter.value === 'all' || host.group === groupFilter.value)
  })
  values.sort((left, right) => {
    const leftValue = sortBy.value === 'heartbeat'
      ? left.last_heartbeat_at ?? ''
      : sortBy.value === 'health'
        ? left.data_state
        : left.name.toLocaleLowerCase()
    const rightValue = sortBy.value === 'heartbeat'
      ? right.last_heartbeat_at ?? ''
      : sortBy.value === 'health'
        ? right.data_state
        : right.name.toLocaleLowerCase()
    return leftValue.localeCompare(rightValue) * (sortDirection.value === 'asc' ? 1 : -1)
  })
  return values
})
const regions = computed(() => [...new Set(hosts.value.map((host) => host.region).filter(Boolean))] as string[])
const groups = computed(() => [...new Set(hosts.value.map((host) => host.group).filter(Boolean))] as string[])
const allFilteredSelected = computed(() => Boolean(filtered.value.length) && filtered.value.every((host) => selectedIds.value.has(host.id)))
const pagedHosts = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize))
const selectedEnrollmentHost = computed(() => {
  if (selectedIds.value.size !== 1) return null
  const hostId = [...selectedIds.value][0]
  const host = hosts.value.find((candidate) => candidate.id === hostId)
  return host?.management === 'pending_enrollment' ? host : null
})
watch([query, stateFilter, managementFilter, agentFilter, regionFilter, groupFilter, sortBy, sortDirection], () => {
  page.value = 1
})

async function load(): Promise<void> {
  loading.value = true
  loadError.value = ''
  try {
    hosts.value = await request<HostPresentation[]>('/api/v1/hosts/presentation')
    if (selected.value) selected.value = hosts.value.find((host) => host.id === selected.value?.id) ?? null
  } catch {
    loadError.value = t('hosts.fetchFailed')
  } finally {
    loading.value = false
  }
}

async function selectHost(host: HostPresentation): Promise<void> {
  selected.value = host
  snapshot.value = null
  try {
    snapshot.value = await request<LatestSnapshot>(`/api/v1/hosts/${host.id}/latest`)
  } catch {
    snapshot.value = null
  }
}

async function createHost(): Promise<void> {
  creating.value = true
  formError.value = ''
  try {
    const host = await request<Host>('/api/v1/hosts', {
      method: 'POST',
      ...jsonBody({ ...newHost.value, os_name: null, tags: [], labels: {} }),
    })
    dialog.value?.close()
    newHost.value = { name: '', address: '', location: '', group_name: '' }
    await load()
    await issueEnrollment(host.id)
  } catch {
    formError.value = t('hosts.createFailed')
  } finally {
    creating.value = false
  }
}

async function setEnabled(host: HostPresentation): Promise<void> {
  await request<Host>(`/api/v1/hosts/${host.id}`, {
    method: 'PATCH',
    ...jsonBody({ enabled: !host.enabled }),
  })
  await load()
}

function toggleSelected(hostId: string): void {
  const next = new Set(selectedIds.value)
  next.has(hostId) ? next.delete(hostId) : next.add(hostId)
  selectedIds.value = next
}

function toggleFiltered(): void {
  const next = new Set(selectedIds.value)
  if (allFilteredSelected.value) filtered.value.forEach((host) => next.delete(host.id))
  else filtered.value.forEach((host) => next.add(host.id))
  selectedIds.value = next
}

async function applyBatch(change: Record<string, unknown>): Promise<void> {
  await request<{ updated: number }>('/api/v1/hosts/batch', {
    method: 'PATCH',
    ...jsonBody({ host_ids: [...selectedIds.value], ...change }),
  })
  selectedIds.value = new Set()
  await load()
}

function exportSelected(): void {
  const selectedHosts = hosts.value.filter((host) => selectedIds.value.has(host.id))
  const rows = [
    ['name', 'address', 'region', 'group', 'management', 'health', 'agent_state'],
    ...selectedHosts.map((host) => [host.name, host.primary_address, host.region ?? '', host.group ?? '', host.management, host.health, host.agent_state]),
  ]
  const blob = new Blob([rows.map((row) => row.map((value) => JSON.stringify(value)).join(',')).join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'guardian-hosts.csv'
  link.click()
  URL.revokeObjectURL(url)
}

function resourceSummary(host: HostPresentation): string {
  const summary = host.resource_summary
  if (!summary) return dataReasonLabel(host.data_reason, locale.value)
  const parts = [
    summary.cpu_percent == null ? null : `CPU ${summary.cpu_percent.toFixed(0)}%`,
    summary.memory_percent == null ? null : `${locale.value === 'zh-CN' ? '内存' : 'RAM'} ${summary.memory_percent.toFixed(0)}%`,
    summary.disk_percent == null ? null : `${locale.value === 'zh-CN' ? '磁盘' : 'Disk'} ${summary.disk_percent.toFixed(0)}%`,
  ].filter(Boolean)
  return parts.join(' · ') || dataReasonLabel(host.data_reason, locale.value)
}

async function deleteHost(host: HostPresentation): Promise<void> {
  if (!window.confirm(t('hosts.deleteConfirm', { name: host.name }))) return
  await request<void>(`/api/v1/hosts/${host.id}`, { method: 'DELETE' })
  selected.value = null
  await load()
}

async function issueEnrollment(hostId: string): Promise<void> {
  issuedToken.value = await request<EnrollmentToken>(`/api/v1/hosts/${hostId}/enrollment-token`, {
    method: 'POST',
    ...jsonBody({ expires_in_minutes: 15 }),
  })
  copied.value = false
  tokenDialog.value?.showModal()
}

async function copyCommand(): Promise<void> {
  if (!issuedToken.value) return
  await navigator.clipboard.writeText(issuedToken.value.install_command)
  copied.value = true
}

onMounted(async () => {
  await load()
  if (typeof route.params.hostId === 'string') {
    const host = hosts.value.find((item) => item.id === route.params.hostId)
    if (host) await selectHost(host)
  }
})
</script>

<template>
  <PageHeader :title="t('hosts.title')" :description="t('hosts.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :aria-label="t('hosts.refresh')" @click="load"><RefreshCw :size="17" /></button>
      <button v-if="canManage" class="primary-button" type="button" @click="dialog?.showModal()"><Plus :size="16" />{{ t('hosts.add') }}</button>
    </template>
  </PageHeader>

  <section class="rc5-summary-strip" aria-label="Host summary">
    <div><strong>{{ hosts.length }}</strong><span>{{ locale === 'zh-CN' ? '主机总数' : 'Total hosts' }}</span></div>
    <div><strong>{{ hosts.filter((host) => host.agent_state === 'online').length }}</strong><span>{{ locale === 'zh-CN' ? 'Agent 在线' : 'Agents online' }}</span></div>
    <div><strong>{{ hosts.filter((host) => host.management === 'komari_only').length }}</strong><span>Komari-only</span></div>
    <div><strong>{{ hosts.filter((host) => host.management === 'pending_enrollment').length }}</strong><span>{{ locale === 'zh-CN' ? '等待接入' : 'Pending enrollment' }}</span></div>
    <div><strong>{{ hosts.filter((host) => host.agent_state === 'stale').length }}</strong><span>{{ locale === 'zh-CN' ? '心跳不新鲜' : 'Stale heartbeat' }}</span></div>
    <div><strong>{{ hosts.filter((host) => !host.enabled).length }}</strong><span>{{ locale === 'zh-CN' ? '已停用' : 'Disabled' }}</span></div>
  </section>

  <div class="toolbar-row rc5-filter-bar">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" :placeholder="t('hosts.searchPlaceholder')" /></label>
    <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '状态' : 'Status' }}</span><select v-model="stateFilter"><option value="all">{{ locale === 'zh-CN' ? '全部状态' : 'All states' }}</option><option value="normal">{{ healthLabel('normal', locale) }}</option><option value="stale">{{ healthLabel('stale', locale) }}</option><option value="offline">{{ healthLabel('offline', locale) }}</option><option value="disabled">{{ healthLabel('disabled', locale) }}</option></select></label>
    <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '管理方式' : 'Management' }}</span><select v-model="managementFilter"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option value="guardian_and_komari">Guardian + Komari</option><option value="guardian">{{ managementLabel('guardian', locale) }}</option><option value="komari_only">{{ managementLabel('komari_only', locale) }}</option><option value="pending_enrollment">{{ managementLabel('pending_enrollment', locale) }}</option></select></label>
    <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '排序' : 'Sort' }}</span><select v-model="sortBy"><option value="name">{{ locale === 'zh-CN' ? '名称' : 'Name' }}</option><option value="health">{{ locale === 'zh-CN' ? '健康状态' : 'Health' }}</option><option value="heartbeat">{{ locale === 'zh-CN' ? '最近心跳' : 'Last heartbeat' }}</option></select></label>
    <button class="secondary-button rc5-sort-direction" type="button" @click="sortDirection = sortDirection === 'asc' ? 'desc' : 'asc'">{{ sortDirection === 'asc' ? (locale === 'zh-CN' ? '升序' : 'Ascending') : (locale === 'zh-CN' ? '降序' : 'Descending') }}</button>
    <details class="rc5-more-filters"><summary>{{ locale === 'zh-CN' ? '更多筛选' : 'More filters' }}</summary><div>
      <label class="rc5-filter-control"><span>Agent</span><select v-model="agentFilter"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option value="online">{{ agentLabel('online', locale) }}</option><option value="stale">{{ agentLabel('stale', locale) }}</option><option value="never_seen">{{ agentLabel('never_seen', locale) }}</option><option value="not_installed">{{ agentLabel('not_installed', locale) }}</option></select></label>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '地区' : 'Region' }}</span><select v-model="regionFilter"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option v-for="region in regions" :key="region" :value="region">{{ regionLabel(region, locale) }}</option></select></label>
      <label class="rc5-filter-control"><span>{{ locale === 'zh-CN' ? '分组' : 'Group' }}</span><select v-model="groupFilter"><option value="all">{{ locale === 'zh-CN' ? '全部' : 'All' }}</option><option v-for="group in groups" :key="group" :value="group">{{ group }}</option></select></label>
    </div></details>
    <span class="rc5-result-count">{{ filtered.length }} / {{ hosts.length }}</span>
  </div>

  <p v-if="loadError" class="inline-error" role="alert">{{ loadError }}</p>
  <div v-else-if="loading" class="row-skeletons" :aria-label="t('hosts.loading')"><span v-for="item in 6" :key="item"></span></div>
  <div v-if="selectedIds.size" class="rc5-batch-bar">
    <strong>{{ locale === 'zh-CN' ? `已选 ${selectedIds.size} 台` : `${selectedIds.size} selected` }}</strong>
    <button class="secondary-button" type="button" @click="applyBatch({ enabled: true })">{{ locale === 'zh-CN' ? '启用' : 'Enable' }}</button>
    <button class="secondary-button" type="button" @click="applyBatch({ enabled: false })">{{ locale === 'zh-CN' ? '停用' : 'Disable' }}</button>
    <label><span>{{ locale === 'zh-CN' ? '分组' : 'Group' }}</span><input v-model="batchGroup" /><button type="button" @click="applyBatch({ group_name: batchGroup })">{{ locale === 'zh-CN' ? '应用' : 'Apply' }}</button></label>
    <label><span>{{ locale === 'zh-CN' ? '添加标签' : 'Add tag' }}</span><input v-model="batchTag" /><button type="button" @click="applyBatch({ add_tags: [batchTag] })">{{ locale === 'zh-CN' ? '添加' : 'Add' }}</button></label>
    <button v-if="selectedEnrollmentHost" class="secondary-button" type="button" @click="issueEnrollment(selectedEnrollmentHost.id)"><KeyRound :size="15" />{{ locale === 'zh-CN' ? '重新发送注册说明' : 'Resend enrollment instructions' }}</button>
    <button class="secondary-button" type="button" @click="exportSelected">{{ locale === 'zh-CN' ? '导出' : 'Export' }}</button>
  </div>
  <DataTable v-if="!loading && filtered.length" :label="t('hosts.title')" :selected-key="selected?.id" :page="page" :page-size="pageSize" :total="filtered.length" @previous="page -= 1" @next="page += 1">
    <template #head><tr><th><input type="checkbox" :checked="allFilteredSelected" :aria-label="locale === 'zh-CN' ? '选择全部主机' : 'Select all hosts'" @change="toggleFiltered" /></th><th :aria-sort="sortBy === 'name' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'">{{ t('hosts.name') }}</th><th :aria-sort="sortBy === 'health' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'">{{ locale === 'zh-CN' ? '健康状态' : 'Health' }}</th><th>{{ locale === 'zh-CN' ? '管理方式' : 'Management' }}</th><th>{{ locale === 'zh-CN' ? '区域 / 分组' : 'Region / group' }}</th><th>Agent</th><th>{{ locale === 'zh-CN' ? '资源摘要' : 'Resources' }}</th><th :aria-sort="sortBy === 'heartbeat' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'">{{ locale === 'zh-CN' ? '最近上报' : 'Last report' }}</th></tr></template>
    <tr v-for="host in pagedHosts" :key="host.id" :class="{ 'is-selected': selected?.id === host.id }" :aria-selected="selected?.id === host.id" tabindex="0" @click="selectHost(host)" @keydown.enter="selectHost(host)">
      <td :data-label="locale === 'zh-CN' ? '选择' : 'Select'" @click.stop><input type="checkbox" :checked="selectedIds.has(host.id)" :aria-label="`${locale === 'zh-CN' ? '选择' : 'Select'} ${host.name}`" @change="toggleSelected(host.id)" /></td>
      <td :data-label="locale === 'zh-CN' ? '主机' : 'Host'"><span class="rc5-resource"><span class="rc5-resource-icon"><Server :size="17" /></span><span><strong>{{ host.name }}</strong><small>{{ host.primary_address }}</small></span></span></td>
      <td :data-label="locale === 'zh-CN' ? '健康状态' : 'Health'"><StatusBadge :tone="healthTone(host.enabled ? host.data_state : 'disabled')" :label="healthLabel(host.enabled ? host.data_state : 'disabled', locale)" compact /></td>
      <td :data-label="locale === 'zh-CN' ? '管理方式' : 'Management'"><strong>{{ managementLabel(host.management, locale) }}</strong><small>{{ host.purpose || dataReasonLabel(host.data_reason, locale) }}</small></td>
      <td :data-label="locale === 'zh-CN' ? '地区' : 'Region'"><span>{{ regionLabel(host.region, locale) }}</span><small>{{ host.group || t('hosts.ungrouped') }}<template v-if="host.provider"> · {{ host.provider }}</template></small></td>
      <td data-label="Agent"><span>{{ agentLabel(host.agent_state, locale) }}</span><small>{{ host.agent_version ? `v${host.agent_version}` : dataReasonLabel(host.data_reason, locale) }}</small></td>
      <td :data-label="locale === 'zh-CN' ? '资源' : 'Resources'"><span>{{ resourceSummary(host) }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '最近上报' : 'Last report'"><span>{{ relativeTime(host.last_heartbeat_at || host.last_seen_at) }}</span></td>
    </tr>
  </DataTable>
  <EmptyState v-else-if="!loading" :title="t('hosts.noMatch')" />

  <DetailDrawer :open="Boolean(selected)" :eyebrow="locale === 'zh-CN' ? '主机详情' : 'Host details'" :title="selected?.name ?? ''" @close="selected = null">
    <div v-if="selected" class="rc5-drawer-body">
      <section class="rc5-fact-grid">
        <div><span>{{ locale === 'zh-CN' ? '管理方式' : 'Management' }}</span><strong>{{ managementLabel(selected.management, locale) }}</strong></div>
        <div><span>{{ locale === 'zh-CN' ? '健康状态' : 'Health' }}</span><strong>{{ healthLabel(selected.enabled ? selected.data_state : 'disabled', locale) }}</strong></div>
        <div><span>{{ locale === 'zh-CN' ? '区域' : 'Region' }}</span><strong>{{ regionLabel(selected.region, locale) }}</strong></div>
        <div><span>Agent</span><strong>{{ agentLabel(selected.agent_state, locale) }}</strong></div>
      </section>
      <section class="rc5-drawer-section">
        <h3>{{ locale === 'zh-CN' ? '资源概况' : 'Resource summary' }}</h3>
        <p class="muted">{{ dataReasonLabel(selected.data_reason, locale) }}</p>
        <template v-if="snapshot?.collected_at">
          <MetricBar :label="t('hosts.memory')" :value="percentUsed(snapshot.payload.memory_total_bytes, snapshot.payload.memory_available_bytes)" :detail="formatBytes(snapshot.payload.memory_total_bytes)" />
          <MetricBar :label="t('hosts.disk')" :value="percentUsed(snapshot.payload.disk_total_bytes, snapshot.payload.disk_free_bytes)" :detail="formatBytes(snapshot.payload.disk_total_bytes)" />
          <dl class="metric-facts"><div><dt>Load 1m</dt><dd>{{ snapshot.payload.load_1 ?? '—' }}</dd></div><div><dt>Uptime</dt><dd>{{ formatDuration(snapshot.payload.uptime_seconds) }}</dd></div></dl>
        </template>
        <EmptyState v-else :title="t('hosts.noMetrics')" />
      </section>
      <details class="rc5-technical"><summary>{{ locale === 'zh-CN' ? '技术信息' : 'Technical details' }}</summary><dl><div><dt>ID</dt><dd class="mono">{{ selected.id }}</dd></div><div><dt>{{ t('hosts.address') }}</dt><dd class="mono">{{ selected.primary_address }}</dd></div></dl></details>
      <div v-if="canManage" class="rc5-drawer-actions">
        <button class="secondary-button" type="button" @click="setEnabled(selected)"><Power :size="15" />{{ selected.enabled ? t('hosts.disable') : t('hosts.enable') }}</button>
        <button v-if="!selected.enrolled_at" class="secondary-button" type="button" @click="issueEnrollment(selected.id)"><KeyRound :size="15" />{{ t('hosts.issueToken') }}</button>
        <button v-if="!selected.enrolled_at" class="secondary-button danger" type="button" @click="deleteHost(selected)"><Trash2 :size="15" />{{ t('hosts.delete') }}</button>
      </div>
    </div>
  </DetailDrawer>

  <dialog ref="dialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('hosts.addTitle') }}</h2><p>{{ t('hosts.addDescription') }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createHost">
      <label><span>{{ t('hosts.name') }}</span><input v-model="newHost.name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{1,119}" /></label>
      <label><span>{{ t('hosts.address') }}</span><input v-model="newHost.address" required /></label>
      <div class="form-grid"><label><span>{{ t('hosts.region') }}</span><input v-model="newHost.location" /></label><label><span>{{ t('hosts.group') }}</span><input v-model="newHost.group_name" /></label></div>
      <p v-if="formError" class="form-error">{{ formError }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="creating">{{ creating ? t('hosts.creating') : t('hosts.create') }}</button></div>
    </form>
  </dialog>
  <dialog ref="tokenDialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('hosts.enrollmentReady') }}</h2><p>{{ t('hosts.enrollmentExpires', { time: relativeTime(issuedToken?.expires_at || null) }) }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <div v-if="issuedToken" class="dialog-form"><label><span>{{ t('hosts.oneTimeToken') }}</span><textarea class="mono" readonly :value="issuedToken.token"></textarea></label><label><span>{{ t('hosts.installCommand') }}</span><textarea class="mono command-output" readonly :value="issuedToken.install_command"></textarea></label><div class="dialog-actions"><button class="secondary-button" type="button" @click="copyCommand"><Check v-if="copied" :size="15" /><Copy v-else :size="15" />{{ copied ? t('common.copied') : t('common.copy') }}</button><button class="primary-button" type="button" @click="tokenDialog?.close()">{{ t('common.done') }}</button></div></div>
  </dialog>
</template>
