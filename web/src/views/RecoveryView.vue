<script setup lang="ts">
import { CheckCircle2, Clipboard, DatabaseBackup, RefreshCw, ShieldX } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import DataTable from '../components/v3/DataTable.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { Host, RecoveryPoint } from '../types'
import { formatTime } from '../utils'

const points = ref<RecoveryPoint[]>([])
const hosts = ref<Host[]>([])
const verifiedOnly = ref(true)
const copied = ref('')
const filtered = computed(() => points.value.filter((point) => !verifiedOnly.value || point.verified))
const hostName = (id: string): string => hosts.value.find((host) => host.id === id)?.name ?? '—'

async function load(): Promise<void> {
  ;[points.value, hosts.value] = await Promise.all([
    request<RecoveryPoint[]>('/api/v1/recovery-points'),
    request<Host[]>('/api/v1/hosts'),
  ])
}

async function copyCommand(point: RecoveryPoint): Promise<void> {
  await navigator.clipboard.writeText(
    `guardian-recovery restore-service ${point.snapshot_id} --target /srv/guardian-restore/${point.service_name}`,
  )
  copied.value = point.id
  window.setTimeout(() => { copied.value = '' }, 1500)
}

onMounted(load)
</script>

<template>
  <PageHeader :title="$t('recovery.title')" :description="$t('recovery.description')">
    <template #actions><button class="icon-button bordered" type="button" :title="$t('common.refresh')" :aria-label="$t('recovery.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="recovery-summary">
    <div><DatabaseBackup :size="19" /><span>{{ $t('recovery.points') }}</span><strong>{{ points.length }}</strong></div>
    <div><CheckCircle2 :size="19" /><span>{{ $t('recovery.verified') }}</span><strong>{{ points.filter((point) => point.verified).length }}</strong></div>
    <div><ShieldX :size="19" /><span>{{ $t('recovery.unverified') }}</span><strong>{{ points.filter((point) => !point.verified).length }}</strong></div>
    <label class="toggle-control"><input v-model="verifiedOnly" type="checkbox" /><span></span>{{ $t('recovery.verifiedOnly') }}</label>
  </div>
  <DataTable :label="$t('recovery.title')" :empty="!filtered.length" :total="filtered.length">
    <template #head><tr><th>{{ $t('recovery.service') }}</th><th>{{ $t('recovery.host') }}</th><th>{{ $t('recovery.status') }}</th><th>{{ $t('recovery.created') }}</th><th>{{ $t('recovery.restore') }}</th></tr></template>
    <tr v-for="point in filtered" :key="point.id">
      <td><span class="rc5-resource"><span class="rc5-resource-icon"><DatabaseBackup :size="18" /></span><strong>{{ point.service_name }}</strong></span></td>
      <td>{{ hostName(point.host_id) }}</td>
      <td><StatusBadge :status="point.verified ? 'verified' : 'unknown'" :label="point.verified ? $t('recovery.testRestored') : $t('recovery.unverified')" /></td>
      <td>{{ formatTime(point.created_at) }}</td>
      <td><button class="icon-button bordered" type="button" :title="copied === point.id ? $t('recovery.copied') : $t('recovery.copy')" :aria-label="$t('recovery.copy')" @click="copyCommand(point)"><CheckCircle2 v-if="copied === point.id" :size="16" /><Clipboard v-else :size="16" /></button></td>
    </tr>
    <template #empty><EmptyState :title="$t('recovery.noItems')" /></template>
  </DataTable>
</template>
