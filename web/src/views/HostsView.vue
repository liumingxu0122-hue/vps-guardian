<script setup lang="ts">
import { Activity, Check, Copy, KeyRound, Plus, Power, RefreshCw, RotateCcw, Search, Server, ShieldX, Trash2, Wrench, X } from '@lucide/vue'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import MetricBar from '../components/MetricBar.vue'
import PageHeader from '../components/PageHeader.vue'
import DataTable from '../components/v3/DataTable.vue'
import DetailDrawer from '../components/v3/DetailDrawer.vue'
import StatusBadge from '../components/v3/StatusBadge.vue'
import { enrollmentSecondsRemaining as secondsRemaining, isTerminalEnrollment } from '../enrollment'
import { canIssueMaintenance, canViewMaintenance, destroyMaintenanceDisclosure } from '../maintenance'
import { agentLabel, dataReasonLabel, healthLabel, healthTone, managementLabel, regionLabel } from '../presentationRegistry'
import { session } from '../session'
import type { AgentMaintenanceSession, AgentMaintenanceToken, EnrollmentSession, EnrollmentToken, Host, HostPresentation, LatestSnapshot } from '../types'
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
const maintenanceDialog = ref<HTMLDialogElement | null>(null)
const issuedToken = ref<EnrollmentToken | null>(null)
const enrollmentSession = ref<EnrollmentSession | null>(null)
const enrollmentError = ref('')
const copied = ref(false)
const creating = ref(false)
const formError = ref('')
const maintenanceKind = ref<AgentMaintenanceToken['kind']>('repair')
const maintenanceToken = ref<AgentMaintenanceToken | null>(null)
const maintenanceStatus = ref<AgentMaintenanceSession | null>(null)
const maintenanceError = ref('')
const maintenanceTypedConfirmation = ref('')
const maintenanceConfirmed = ref(false)
const maintenancePurge = ref(false)
const maintenanceApprovalId = ref('')
const selectedIds = ref(new Set<string>())
const batchGroup = ref('')
const batchTag = ref('')
const newHost = ref({
  name: '',
  location: '',
  group_name: '',
  tags: '',
  notes: '',
  os_family: 'auto',
  source_cidr: '',
})
const clock = ref(Date.now())
let enrollmentPoll: ReturnType<typeof setInterval> | null = null

const canAddHost = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const canIssueEnrollment = computed(() => ['operator', 'admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const canRepairAgent = computed(() => canIssueMaintenance(session.user?.role, 'repair'))
const canAdminAgent = computed(() => canIssueMaintenance(session.user?.role, 'reinstall'))
const canViewAgentMaintenance = computed(() => canViewMaintenance(session.user?.role))
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
const enrollmentSecondsRemaining = computed(() => {
  if (!issuedToken.value) return 0
  return secondsRemaining(issuedToken.value.expires_at, clock.value)
})
const enrollmentStatusLabel = computed(() => {
  const status = enrollmentSession.value?.status ?? issuedToken.value?.status ?? 'waiting'
  const key = `hosts.enrollmentStatus.${status}`
  return t(key)
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

function destroyMaintenanceCommand(): void {
  maintenanceToken.value = destroyMaintenanceDisclosure(maintenanceToken.value)
  maintenanceTypedConfirmation.value = ''
  maintenanceConfirmed.value = false
}

function openMaintenance(kind: AgentMaintenanceToken['kind']): void {
  maintenanceKind.value = kind
  maintenanceStatus.value = null
  maintenanceError.value = ''
  maintenancePurge.value = false
  maintenanceApprovalId.value = ''
  destroyMaintenanceCommand()
  maintenanceDialog.value?.showModal()
}

async function loadMaintenanceStatus(): Promise<void> {
  if (!selected.value) return
  maintenanceError.value = ''
  try {
    maintenanceStatus.value = await request<AgentMaintenanceSession>(
      `/api/v1/hosts/${selected.value.id}/maintenance-sessions/latest`,
    )
    maintenanceKind.value = maintenanceStatus.value.kind
    maintenanceDialog.value?.showModal()
  } catch {
    maintenanceError.value = t('hosts.maintenanceStatusFailed')
    maintenanceDialog.value?.showModal()
  }
}

async function issueMaintenance(): Promise<void> {
  if (!selected.value) return
  maintenanceError.value = ''
  if (maintenanceKind.value === 'decommission' && (
    !maintenanceConfirmed.value ||
    maintenanceTypedConfirmation.value !== selected.value.name ||
    !maintenanceApprovalId.value
  )) {
    maintenanceError.value = t('hosts.decommissionConfirmationRequired')
    return
  }
  try {
    maintenanceToken.value = await request<AgentMaintenanceToken>(
      `/api/v1/hosts/${selected.value.id}/maintenance-sessions`,
      {
        method: 'POST',
        ...jsonBody({
          kind: maintenanceKind.value,
          purge_local_state: maintenancePurge.value,
          approval_id: maintenanceApprovalId.value || null,
          confirmation: maintenanceKind.value === 'decommission'
            ? `DECOMMISSION ${selected.value.name}`
            : null,
        }),
      },
    )
  } catch {
    maintenanceError.value = t('hosts.maintenanceIssueFailed')
  }
}

async function copyMaintenanceCommand(): Promise<void> {
  if (maintenanceToken.value?.command) await navigator.clipboard.writeText(maintenanceToken.value.command)
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
      ...jsonBody({
        name: newHost.value.name,
        address: 'pending-enrollment',
        location: newHost.value.location || null,
        group_name: newHost.value.group_name || null,
        notes: newHost.value.notes || null,
        desired_os_family: newHost.value.os_family,
        os_name: null,
        tags: newHost.value.tags.split(',').map((value) => value.trim()).filter(Boolean),
        labels: {},
      }),
    })
    dialog.value?.close()
    await load()
    await issueEnrollment(host.id, {
      os_family: newHost.value.os_family,
      source_cidr: newHost.value.source_cidr || null,
    })
    newHost.value = {
      name: '',
      location: '',
      group_name: '',
      tags: '',
      notes: '',
      os_family: 'auto',
      source_cidr: '',
    }
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

function hostSubtitle(host: HostPresentation): string {
  const productContext = [host.purpose, host.provider, host.os_name].filter(
    (value): value is string => Boolean(value?.trim()),
  )
  if (productContext.length) return [...new Set(productContext)].join(' · ')
  if (host.management === 'komari_only') {
    return locale.value === 'zh-CN' ? 'Komari 资产记录' : 'Komari inventory record'
  }
  return locale.value === 'zh-CN' ? 'Guardian 托管主机' : 'Guardian managed host'
}

async function deleteHost(host: HostPresentation): Promise<void> {
  if (!window.confirm(t('hosts.deleteConfirm', { name: host.name }))) return
  await request<void>(`/api/v1/hosts/${host.id}`, { method: 'DELETE' })
  selected.value = null
  await load()
}

function stopEnrollmentPoll(): void {
  if (enrollmentPoll) clearInterval(enrollmentPoll)
  enrollmentPoll = null
}

function destroyEnrollmentCommand(): void {
  stopEnrollmentPoll()
  issuedToken.value = null
  copied.value = false
}

async function loadEnrollmentStatus(hostId: string): Promise<void> {
  try {
    enrollmentSession.value = await request<EnrollmentSession>(
      `/api/v1/hosts/${hostId}/enrollment-sessions/latest`,
      { dedupe: false },
    )
    if (isTerminalEnrollment(enrollmentSession.value.status)) stopEnrollmentPoll()
  } catch {
    enrollmentError.value = t('hosts.enrollmentStatusFailed')
  }
}

function startEnrollmentPoll(hostId: string): void {
  stopEnrollmentPoll()
  void loadEnrollmentStatus(hostId)
  enrollmentPoll = setInterval(() => void loadEnrollmentStatus(hostId), 2_000)
}

async function issueEnrollment(
  hostId: string,
  options: { os_family?: string; source_cidr?: string | null } = {},
): Promise<void> {
  enrollmentError.value = ''
  enrollmentSession.value = null
  try {
    issuedToken.value = await request<EnrollmentToken>(
      `/api/v1/hosts/${hostId}/enrollment-token`,
      {
        method: 'POST',
        ...jsonBody({
          expires_in_minutes: 10,
          os_family: options.os_family ?? 'auto',
          source_cidr: options.source_cidr ?? null,
        }),
      },
    )
    copied.value = false
    tokenDialog.value?.showModal()
    startEnrollmentPoll(hostId)
  } catch {
    enrollmentError.value = t('hosts.enrollmentIssueFailed')
  }
}

async function revokeEnrollment(): Promise<void> {
  if (!issuedToken.value) return
  enrollmentError.value = ''
  try {
    await request<void>(
      `/api/v1/hosts/${issuedToken.value.host_id}/enrollment-tokens/${issuedToken.value.id}/revoke`,
      { method: 'POST' },
    )
    await loadEnrollmentStatus(issuedToken.value.host_id)
    issuedToken.value = null
  } catch {
    enrollmentError.value = t('hosts.enrollmentRevokeFailed')
  }
}

async function regenerateEnrollment(): Promise<void> {
  const hostId = issuedToken.value?.host_id ?? enrollmentSession.value?.host_id
  if (!hostId) return
  await issueEnrollment(hostId, {
    os_family: enrollmentSession.value?.os_family ?? 'auto',
    source_cidr: enrollmentSession.value?.source_cidr ?? null,
  })
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
const clockInterval = setInterval(() => {
  clock.value = Date.now()
}, 1_000)
onUnmounted(() => {
  clearInterval(clockInterval)
  stopEnrollmentPoll()
})
</script>

<template>
  <PageHeader :title="t('hosts.title')" :description="t('hosts.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :aria-label="t('hosts.refresh')" @click="load"><RefreshCw :size="17" /></button>
      <button v-if="canAddHost" class="primary-button" type="button" @click="dialog?.showModal()"><Plus :size="16" />{{ t('hosts.add') }}</button>
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
  <p v-if="enrollmentError" class="inline-error" role="alert">{{ enrollmentError }}</p>
  <div v-else-if="loading" class="row-skeletons" :aria-label="t('hosts.loading')"><span v-for="item in 6" :key="item"></span></div>
  <div v-if="selectedIds.size" class="rc5-batch-bar">
    <strong>{{ locale === 'zh-CN' ? `已选 ${selectedIds.size} 台` : `${selectedIds.size} selected` }}</strong>
    <button class="secondary-button" type="button" @click="applyBatch({ enabled: true })">{{ locale === 'zh-CN' ? '启用' : 'Enable' }}</button>
    <button class="secondary-button" type="button" @click="applyBatch({ enabled: false })">{{ locale === 'zh-CN' ? '停用' : 'Disable' }}</button>
    <label><span>{{ locale === 'zh-CN' ? '分组' : 'Group' }}</span><input v-model="batchGroup" /><button type="button" @click="applyBatch({ group_name: batchGroup })">{{ locale === 'zh-CN' ? '应用' : 'Apply' }}</button></label>
    <label><span>{{ locale === 'zh-CN' ? '添加标签' : 'Add tag' }}</span><input v-model="batchTag" /><button type="button" @click="applyBatch({ add_tags: [batchTag] })">{{ locale === 'zh-CN' ? '添加' : 'Add' }}</button></label>
    <button v-if="canIssueEnrollment && selectedEnrollmentHost" class="secondary-button" type="button" @click="issueEnrollment(selectedEnrollmentHost.id)"><KeyRound :size="15" />{{ locale === 'zh-CN' ? '重新发送注册说明' : 'Resend enrollment instructions' }}</button>
    <button class="secondary-button" type="button" @click="exportSelected">{{ locale === 'zh-CN' ? '导出' : 'Export' }}</button>
  </div>
  <DataTable v-if="!loading && filtered.length" :label="t('hosts.title')" :selected-key="selected?.id" :page="page" :page-size="pageSize" :total="filtered.length" @previous="page -= 1" @next="page += 1">
    <template #head><tr><th><input type="checkbox" :checked="allFilteredSelected" :aria-label="locale === 'zh-CN' ? '选择全部主机' : 'Select all hosts'" @change="toggleFiltered" /></th><th :aria-sort="sortBy === 'name' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'">{{ t('hosts.name') }}</th><th :aria-sort="sortBy === 'health' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'">{{ locale === 'zh-CN' ? '健康状态' : 'Health' }}</th><th>{{ locale === 'zh-CN' ? '管理方式' : 'Management' }}</th><th>{{ locale === 'zh-CN' ? '区域 / 分组' : 'Region / group' }}</th><th>Agent</th><th>{{ locale === 'zh-CN' ? '资源摘要' : 'Resources' }}</th><th :aria-sort="sortBy === 'heartbeat' ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'">{{ locale === 'zh-CN' ? '最近上报' : 'Last report' }}</th></tr></template>
    <tr v-for="host in pagedHosts" :key="host.id" :class="{ 'is-selected': selected?.id === host.id }" :aria-selected="selected?.id === host.id" tabindex="0" @click="selectHost(host)" @keydown.enter="selectHost(host)">
      <td :data-label="locale === 'zh-CN' ? '选择' : 'Select'" @click.stop><input type="checkbox" :checked="selectedIds.has(host.id)" :aria-label="`${locale === 'zh-CN' ? '选择' : 'Select'} ${host.name}`" @change="toggleSelected(host.id)" /></td>
      <td :data-label="locale === 'zh-CN' ? '主机' : 'Host'"><span class="rc5-resource"><span class="rc5-resource-icon"><Server :size="17" /></span><span><strong>{{ host.name }}</strong><small>{{ hostSubtitle(host) }}</small></span></span></td>
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
      <div v-if="canAddHost || canIssueEnrollment || canViewAgentMaintenance" class="rc5-drawer-actions">
        <button v-if="canAddHost" class="secondary-button" type="button" @click="setEnabled(selected)"><Power :size="15" />{{ selected.enabled ? t('hosts.disable') : t('hosts.enable') }}</button>
        <button v-if="canIssueEnrollment && !selected.enrolled_at" class="secondary-button" type="button" @click="issueEnrollment(selected.id)"><KeyRound :size="15" />{{ t('hosts.issueToken') }}</button>
        <button v-if="canAddHost && !selected.enrolled_at" class="secondary-button danger" type="button" @click="deleteHost(selected)"><Trash2 :size="15" />{{ t('hosts.delete') }}</button>
        <button v-if="canViewAgentMaintenance && selected.enrolled_at" class="secondary-button" type="button" @click="loadMaintenanceStatus"><Activity :size="15" />{{ t('hosts.agentStatus') }}</button>
        <button v-if="canRepairAgent && selected.enrolled_at" class="secondary-button" type="button" @click="openMaintenance('repair')"><Wrench :size="15" />{{ t('hosts.repairAgent') }}</button>
        <button v-if="canAdminAgent && selected.enrolled_at" class="secondary-button" type="button" @click="openMaintenance('reinstall')"><RefreshCw :size="15" />{{ t('hosts.reinstallAgent') }}</button>
        <button v-if="canAdminAgent && selected.enrolled_at" class="secondary-button" type="button" @click="openMaintenance('rotate_identity')"><RotateCcw :size="15" />{{ t('hosts.rotateIdentity') }}</button>
        <button v-if="canAdminAgent && selected.enrolled_at" class="secondary-button danger" type="button" @click="openMaintenance('decommission')"><ShieldX :size="15" />{{ t('hosts.decommissionAgent') }}</button>
      </div>
    </div>
  </DetailDrawer>

  <dialog ref="dialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('hosts.addTitle') }}</h2><p>{{ t('hosts.addDescription') }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createHost">
      <label><span>{{ t('hosts.name') }}</span><input v-model="newHost.name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{1,119}" /></label>
      <div class="form-grid"><label><span>{{ t('hosts.region') }}</span><input v-model="newHost.location" /></label><label><span>{{ t('hosts.group') }}</span><input v-model="newHost.group_name" /></label></div>
      <label><span>{{ t('hosts.tags') }}</span><input v-model="newHost.tags" :placeholder="t('hosts.tagsPlaceholder')" /></label>
      <label><span>{{ t('hosts.osFamily') }}</span><select v-model="newHost.os_family"><option value="auto">{{ t('hosts.osAuto') }}</option><option value="debian">Debian / Ubuntu</option><option value="rhel">RHEL / Rocky / AlmaLinux</option><option value="fedora">Fedora</option><option value="alpine">Alpine Linux</option><option value="generic">{{ t('hosts.osGeneric') }}</option></select></label>
      <label><span>{{ t('hosts.sourceCidr') }}</span><input v-model="newHost.source_cidr" inputmode="decimal" placeholder="203.0.113.10/32" /><small>{{ t('hosts.sourceCidrHelp') }}</small></label>
      <label><span>{{ t('hosts.notes') }}</span><textarea v-model="newHost.notes" maxlength="500"></textarea></label>
      <p class="muted">{{ t('hosts.installBoundary') }}</p>
      <p v-if="formError" class="form-error">{{ formError }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="creating">{{ creating ? t('hosts.creating') : t('hosts.createAndEnroll') }}</button></div>
    </form>
  </dialog>
  <dialog ref="tokenDialog" class="modal-dialog" @close="destroyEnrollmentCommand">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('hosts.enrollmentReady') }}</h2><p v-if="issuedToken">{{ t('hosts.enrollmentCountdown', { seconds: enrollmentSecondsRemaining }) }}</p><p v-else>{{ enrollmentStatusLabel }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <div class="dialog-form">
      <div class="rc5-fact-grid" aria-live="polite"><div><span>{{ t('hosts.enrollmentCurrentStatus') }}</span><strong>{{ enrollmentStatusLabel }}</strong></div><div v-if="enrollmentSession"><span>{{ t('hosts.enrollmentOs') }}</span><strong>{{ enrollmentSession.os_family }}</strong></div></div>
      <template v-if="issuedToken">
        <p class="muted">{{ t('hosts.commandDisclosure') }}</p>
        <label><span>{{ t('hosts.installCommand') }}</span><textarea class="mono command-output" readonly :value="issuedToken.install_command"></textarea></label>
      </template>
      <p v-else-if="enrollmentSession?.status === 'revoked'" class="muted">{{ t('hosts.commandDestroyed') }}</p>
      <ol v-if="enrollmentSession?.events.length" class="enrollment-timeline">
        <li v-for="event in enrollmentSession.events" :key="`${event.sequence}-${event.status}`"><strong>{{ t(`hosts.enrollmentStatus.${event.status}`) }}</strong><small>{{ relativeTime(event.occurred_at) }}</small><span v-if="event.error_summary">{{ event.error_summary }}</span></li>
      </ol>
      <dl v-if="enrollmentSession?.error_code" class="metric-facts"><div><dt>{{ t('hosts.errorCategory') }}</dt><dd>{{ enrollmentSession.error_code }}</dd></div><div><dt>{{ t('hosts.errorStep') }}</dt><dd>{{ enrollmentSession.error_step || '—' }}</dd></div><div><dt>{{ t('hosts.rollbackStatus') }}</dt><dd>{{ enrollmentSession.rolled_back ? t('hosts.rollbackCompleted') : t('hosts.rollbackNotCompleted') }}</dd></div></dl>
      <p v-if="enrollmentSession?.error_summary" class="form-error" role="alert">{{ enrollmentSession.error_summary }}<template v-if="enrollmentSession.rolled_back"> · {{ t('hosts.rollbackCompleted') }}</template></p>
      <p v-if="enrollmentError" class="form-error" role="alert">{{ enrollmentError }}</p>
      <div class="dialog-actions">
        <button v-if="issuedToken" class="secondary-button" type="button" @click="copyCommand"><Check v-if="copied" :size="15" /><Copy v-else :size="15" />{{ copied ? t('common.copied') : t('common.copy') }}</button>
        <button v-if="issuedToken && !isTerminalEnrollment(enrollmentSession?.status)" class="secondary-button danger" type="button" @click="revokeEnrollment">{{ t('hosts.revokeEnrollment') }}</button>
        <button v-if="enrollmentSession && ['failed', 'expired', 'revoked'].includes(enrollmentSession.status)" class="secondary-button" type="button" @click="regenerateEnrollment">{{ t('hosts.regenerateEnrollment') }}</button>
        <button class="primary-button" type="button" @click="tokenDialog?.close()">{{ t('common.done') }}</button>
      </div>
    </div>
  </dialog>
  <dialog ref="maintenanceDialog" class="modal-dialog" @close="destroyMaintenanceCommand">
    <form method="dialog" class="dialog-header"><div><h2>{{ t(`hosts.maintenance.${maintenanceKind}`) }}</h2><p>{{ t('hosts.maintenanceBoundary') }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <div class="dialog-form">
      <template v-if="maintenanceStatus">
        <dl class="metric-facts"><div><dt>{{ t('hosts.maintenanceState') }}</dt><dd>{{ maintenanceStatus.status }}</dd></div><div><dt>{{ t('hosts.maintenanceMode') }}</dt><dd>{{ maintenanceStatus.kind }}</dd></div></dl>
        <ol class="enrollment-timeline"><li v-for="event in maintenanceStatus.events" :key="`${event.status_sequence}-${event.status}`"><strong>{{ event.status }}</strong><small>{{ relativeTime(event.occurred_at) }}</small><span v-if="event.error_summary">{{ event.error_summary }}</span></li></ol>
      </template>
      <template v-else-if="maintenanceToken">
        <p class="muted">{{ t('hosts.maintenanceOneTime') }}</p>
        <label><span>{{ t('hosts.maintenanceCommand') }}</span><textarea class="mono command-output" readonly :value="maintenanceToken.command"></textarea></label>
      </template>
      <template v-else>
        <template v-if="maintenanceKind === 'decommission'">
          <p class="form-error">{{ t('hosts.decommissionWarning') }}</p>
          <label><span>{{ t('hosts.approvalId') }}</span><input v-model="maintenanceApprovalId" autocomplete="off" /></label>
          <label><input v-model="maintenanceConfirmed" type="checkbox" /> {{ t('hosts.decommissionCheck') }}</label>
          <label><span>{{ t('hosts.typeHostName') }}</span><input v-model="maintenanceTypedConfirmation" autocomplete="off" /></label>
          <label><input v-model="maintenancePurge" type="checkbox" /> {{ t('hosts.purgeLocalState') }}</label>
        </template>
        <button class="primary-button" type="button" @click="issueMaintenance">{{ t('hosts.generateMaintenanceCommand') }}</button>
      </template>
      <p v-if="maintenanceError" class="form-error" role="alert">{{ maintenanceError }}</p>
      <div class="dialog-actions"><button v-if="maintenanceToken" class="secondary-button" type="button" @click="copyMaintenanceCommand"><Copy :size="15" />{{ t('common.copy') }}</button><button class="primary-button" type="button" @click="maintenanceDialog?.close()">{{ t('common.done') }}</button></div>
    </div>
  </dialog>
</template>
