<script setup lang="ts">
import { MapPin, Plus, RefreshCw, Search, Server, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import MetricBar from '../components/MetricBar.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type { Host, LatestSnapshot } from '../types'
import { formatBytes, formatDuration, percentUsed, relativeTime } from '../utils'

const hosts = ref<Host[]>([])
const { t } = useI18n()
const route = useRoute()
const snapshots = ref<Record<string, LatestSnapshot>>({})
const expanded = ref<string | null>(null)
const query = ref('')
const loading = ref(true)
const dialog = ref<HTMLDialogElement | null>(null)
const formError = ref('')
const creating = ref(false)
const newHost = ref({ name: '', address: '', os_name: '', location: '' })
const canCreate = computed(() => ['admin', 'owner'].includes(session.user?.role ?? 'viewer'))
const filtered = computed(() => {
  const needle = query.value.trim().toLowerCase()
  if (!needle) return hosts.value
  return hosts.value.filter((host) =>
    [host.name, host.address, host.location ?? '', host.os_name ?? ''].some((value) =>
      value.toLowerCase().includes(needle),
    ),
  )
})

async function load(): Promise<void> {
  loading.value = true
  try {
    hosts.value = await request<Host[]>('/api/v1/hosts')
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
    await request<Host>('/api/v1/hosts', {
      method: 'POST',
      ...jsonBody({
        ...newHost.value,
        os_name: newHost.value.os_name || null,
        location: newHost.value.location || null,
        labels: {},
      }),
    })
    dialog.value?.close()
    newHost.value = { name: '', address: '', os_name: '', location: '' }
    await load()
  } catch (error) {
    formError.value = t('hosts.createFailed')
  } finally {
    creating.value = false
  }
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
    <span>{{ filtered.length }} / {{ hosts.length }}</span>
  </div>
  <section class="host-list">
    <article v-for="host in filtered" :key="host.id" class="host-item" :class="{ expanded: expanded === host.id }">
      <button class="host-summary" type="button" @click="toggle(host)">
        <span class="host-icon"><Server :size="19" /></span>
        <span class="host-identity"><strong>{{ host.name }}</strong><small class="mono">{{ host.address }}</small></span>
        <span class="host-location"><MapPin :size="14" />{{ host.location || t('hosts.notSet') }}</span>
        <span class="host-os">{{ host.os_name || t('hosts.awaitingDiscovery') }}</span>
        <StatusBadge :status="host.status" />
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
      <p v-if="formError" class="form-error">{{ formError }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="creating">{{ creating ? t('hosts.creating') : t('hosts.create') }}</button></div>
    </form>
  </dialog>
</template>
