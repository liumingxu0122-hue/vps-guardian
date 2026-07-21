<script setup lang="ts">
import { Check, Copy, KeyRound, MapPin, Plus, Power, RefreshCw, Search, Server, Trash2, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import MetricBar from '../components/MetricBar.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type { EnrollmentToken, Host, LatestSnapshot } from '../types'
import { formatBytes, formatDuration, percentUsed, relativeTime } from '../utils'

const hosts = ref<Host[]>([])
const { t } = useI18n()
const route = useRoute()
const snapshots = ref<Record<string, LatestSnapshot>>({})
const expanded = ref<string | null>(null)
const query = ref('')
const onlineFilter = ref('all')
const enabledFilter = ref('all')
const groupFilter = ref('all')
const sortBy = ref('name')
const loading = ref(true)
const loadError = ref('')
const dialog = ref<HTMLDialogElement | null>(null)
const tokenDialog = ref<HTMLDialogElement | null>(null)
const issuedToken = ref<EnrollmentToken | null>(null)
const copied = ref(false)
const formError = ref('')
const creating = ref(false)
const newHost = ref({ name: '', address: '', os_name: '', location: '', group_name: '', tags: '' })
const canCreate = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const filtered = computed(() => {
  const needle = query.value.trim().toLowerCase()
  const values = hosts.value.filter((host) => {
    const matchesQuery = !needle || [host.name, host.address, host.location ?? '', host.os_name ?? '', ...host.tags].some((value) => value.toLowerCase().includes(needle))
    const matchesOnline = onlineFilter.value === 'all' || (onlineFilter.value === 'online' ? host.status !== 'offline' : host.status === 'offline')
    const matchesEnabled = enabledFilter.value === 'all' || host.enabled === (enabledFilter.value === 'enabled')
    const matchesGroup = groupFilter.value === 'all' || host.group_name === groupFilter.value
    return matchesQuery && matchesOnline && matchesEnabled && matchesGroup
  })
  return values
})
const groups = computed(() => [...new Set(hosts.value.map((host) => host.group_name).filter(Boolean))] as string[])

async function load(): Promise<void> {
  loading.value = true
  loadError.value = ''
  try {
    const order = ['cpu', 'memory', 'disk'].includes(sortBy.value) ? 'desc' : 'asc'
    hosts.value = await request<Host[]>(`/api/v1/hosts?sort_by=${sortBy.value}&order=${order}`)
  } catch {
    loadError.value = t('hosts.fetchFailed')
  } finally {
    loading.value = false
  }
}

async function toggle(host: Host): Promise<void> {
  expanded.value = expanded.value === host.id ? null : host.id
  if (expanded.value && !snapshots.value[host.id]) {
    snapshots.value[host.id] = await request<LatestSnapshot>(`/api/v1/hosts/${host.id}/latest`)
  }
}

async function createHost(): Promise<void> {
  formError.value = ''
  creating.value = true
  try {
    const host = await request<Host>('/api/v1/hosts', {
      method: 'POST',
      ...jsonBody({
        ...newHost.value,
        os_name: newHost.value.os_name || null,
        location: newHost.value.location || null,
        group_name: newHost.value.group_name || null,
        tags: newHost.value.tags.split(',').map((tag) => tag.trim()).filter(Boolean),
        labels: {},
      }),
    })
    dialog.value?.close()
    newHost.value = { name: '', address: '', os_name: '', location: '', group_name: '', tags: '' }
    await load()
    await issueEnrollment(host)
  } catch (error) {
    formError.value = t('hosts.createFailed')
  } finally {
    creating.value = false
  }
}

async function setEnabled(host: Host): Promise<void> {
  await request<Host>(`/api/v1/hosts/${host.id}`, {
    method: 'PATCH',
    ...jsonBody({ enabled: !host.enabled }),
  })
  await load()
}

async function deleteHost(host: Host): Promise<void> {
  if (!window.confirm(t('hosts.deleteConfirm', { name: host.name }))) return
  await request<void>(`/api/v1/hosts/${host.id}`, { method: 'DELETE' })
  await load()
}

async function issueEnrollment(host: Host): Promise<void> {
  issuedToken.value = await request<EnrollmentToken>(`/api/v1/hosts/${host.id}/enrollment-token`, {
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
  const requested = route.params.hostId
  if (typeof requested === 'string') {
    const host = hosts.value.find((item) => item.id === requested)
    if (host) await toggle(host)
  }
})
</script>

<template>
  <PageHeader :title="t('hosts.title')" :description="t('hosts.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :title="t('common.refresh')" :aria-label="t('hosts.refresh')" @click="load"><RefreshCw :size="17" /></button>
      <button v-if="canCreate" class="primary-button" type="button" @click="dialog?.showModal()"><Plus :size="16" />{{ t('hosts.add') }}</button>
    </template>
  </PageHeader>
  <div class="toolbar-row">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" :placeholder="t('hosts.searchPlaceholder')" /></label>
    <label><span class="sr-only">{{ t('hosts.onlineFilter') }}</span><select v-model="onlineFilter" :aria-label="t('hosts.onlineFilter')"><option value="all">{{ t('hosts.allConnectivity') }}</option><option value="online">{{ t('hosts.online') }}</option><option value="offline">{{ t('hosts.offline') }}</option></select></label>
    <label><span class="sr-only">{{ t('hosts.enabledFilter') }}</span><select v-model="enabledFilter" :aria-label="t('hosts.enabledFilter')"><option value="all">{{ t('hosts.allEnabledStates') }}</option><option value="enabled">{{ t('common.enabled') }}</option><option value="disabled">{{ t('common.disabled') }}</option></select></label>
    <label><span class="sr-only">{{ t('hosts.groupFilter') }}</span><select v-model="groupFilter" :aria-label="t('hosts.groupFilter')"><option value="all">{{ t('hosts.allGroups') }}</option><option v-for="group in groups" :key="group" :value="group">{{ group }}</option></select></label>
    <label><span class="sr-only">{{ t('hosts.sort') }}</span><select v-model="sortBy" :aria-label="t('hosts.sort')" @change="load"><option value="name">{{ t('hosts.sortName') }}</option><option value="status">{{ t('hosts.sortStatus') }}</option><option value="cpu">CPU</option><option value="memory">{{ t('hosts.memory') }}</option><option value="disk">{{ t('hosts.disk') }}</option></select></label>
    <span>{{ filtered.length }} / {{ hosts.length }}</span>
  </div>
  <p v-if="loadError" class="inline-error" role="alert">{{ loadError }}</p>
  <div v-else-if="loading" class="row-skeletons" :aria-label="t('hosts.loading')"><span v-for="item in 6" :key="item"></span></div>
  <section class="host-list">
    <article v-for="host in filtered" :key="host.id" class="host-item" :class="{ expanded: expanded === host.id }">
      <button class="host-summary" type="button" @click="toggle(host)">
        <span class="host-icon"><Server :size="19" /></span>
        <span class="host-identity"><strong>{{ host.name }}</strong><small class="mono">{{ host.address }}</small><small>{{ host.group_name || t('hosts.ungrouped') }} · {{ host.tags.join(', ') || t('hosts.noTags') }}</small></span>
        <span class="host-location"><MapPin :size="14" />{{ host.location || t('hosts.notSet') }}</span>
        <span class="host-os">{{ host.os_name || t('hosts.awaitingDiscovery') }}</span>
        <StatusBadge :status="host.enabled ? host.data_state : 'disabled'" />
        <span class="last-seen">{{ relativeTime(host.last_seen_at) }}</span>
      </button>
      <div v-if="expanded === host.id" class="host-detail">
        <template v-if="snapshots[host.id]?.collected_at">
          <MetricBar :label="t('hosts.memory')" :value="percentUsed(snapshots[host.id].payload.memory_total_bytes, snapshots[host.id].payload.memory_available_bytes)" :detail="formatBytes(snapshots[host.id].payload.memory_total_bytes)" />
          <MetricBar :label="t('hosts.disk')" :value="percentUsed(snapshots[host.id].payload.disk_total_bytes, snapshots[host.id].payload.disk_free_bytes)" :detail="formatBytes(snapshots[host.id].payload.disk_total_bytes)" />
          <MetricBar label="Inode" :value="percentUsed(snapshots[host.id].payload.inode_total, snapshots[host.id].payload.inode_free)" />
          <dl class="metric-facts"><div><dt>Load 1m</dt><dd>{{ snapshots[host.id].payload.load_1 ?? '—' }}</dd></div><div><dt>Uptime</dt><dd>{{ formatDuration(snapshots[host.id].payload.uptime_seconds) }}</dd></div><div><dt>{{ t('hosts.collected') }}</dt><dd>{{ relativeTime(snapshots[host.id].collected_at) }}</dd></div></dl>
        </template>
        <EmptyState v-else :title="t('hosts.noMetrics')" />
        <div v-if="canCreate" class="host-actions">
          <button class="secondary-button" type="button" @click="setEnabled(host)"><Power :size="15" />{{ host.enabled ? t('hosts.disable') : t('hosts.enable') }}</button>
          <button v-if="!host.enrolled_at" class="secondary-button" type="button" @click="issueEnrollment(host)"><KeyRound :size="15" />{{ t('hosts.issueToken') }}</button>
          <button v-if="!host.enrolled_at" class="secondary-button danger" type="button" @click="deleteHost(host)"><Trash2 :size="15" />{{ t('hosts.delete') }}</button>
        </div>
      </div>
    </article>
    <EmptyState v-if="!loading && !filtered.length" :title="t('hosts.noMatch')" />
  </section>
  <dialog ref="dialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('hosts.addTitle') }}</h2><p>{{ t('hosts.addDescription') }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createHost">
      <label><span>{{ t('hosts.name') }}</span><input v-model="newHost.name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{1,119}" /></label>
      <label><span>{{ t('hosts.address') }}</span><input v-model="newHost.address" required /></label>
      <div class="form-grid"><label><span>{{ t('hosts.operatingSystem') }}</span><input v-model="newHost.os_name" placeholder="Ubuntu 24.04" /></label><label><span>{{ t('hosts.region') }}</span><input v-model="newHost.location" placeholder="Hong Kong" /></label></div>
      <div class="form-grid"><label><span>{{ t('hosts.group') }}</span><input v-model="newHost.group_name" maxlength="120" /></label><label><span>{{ t('hosts.tags') }}</span><input v-model="newHost.tags" :placeholder="t('hosts.tagsPlaceholder')" /></label></div>
      <p v-if="formError" class="form-error">{{ formError }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="creating">{{ creating ? t('hosts.creating') : t('hosts.create') }}</button></div>
    </form>
  </dialog>
  <dialog ref="tokenDialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ t('hosts.enrollmentReady') }}</h2><p>{{ t('hosts.enrollmentExpires', { time: relativeTime(issuedToken?.expires_at || null) }) }}</p></div><button class="icon-button" :aria-label="t('common.close')"><X :size="18" /></button></form>
    <div v-if="issuedToken" class="dialog-form">
      <label><span>{{ t('hosts.oneTimeToken') }}</span><textarea class="mono" readonly :value="issuedToken.token"></textarea></label>
      <label><span>{{ t('hosts.installCommand') }}</span><textarea class="mono command-output" readonly :value="issuedToken.install_command"></textarea></label>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="copyCommand"><Check v-if="copied" :size="15" /><Copy v-else :size="15" />{{ copied ? t('common.copied') : t('common.copy') }}</button><button class="primary-button" type="button" @click="tokenDialog?.close()">{{ t('common.done') }}</button></div>
    </div>
  </dialog>
</template>
