<script setup lang="ts">
import { CheckCircle2, Clipboard, DatabaseBackup, RefreshCw, ShieldX } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { Host, RecoveryPoint } from '../types'
import { formatTime } from '../utils'

const points = ref<RecoveryPoint[]>([])
const hosts = ref<Host[]>([])
const verifiedOnly = ref(true)
const copied = ref('')
const filtered = computed(() => points.value.filter((point) => !verifiedOnly.value || point.verified))
const hostName = (id: string): string => hosts.value.find((host) => host.id === id)?.name ?? id.slice(0, 8)

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
  <PageHeader title="备份恢复" description="Restic 快照、完整性校验与试恢复状态">
    <template #actions><button class="icon-button bordered" type="button" title="刷新" aria-label="刷新恢复点" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="recovery-summary">
    <div><DatabaseBackup :size="19" /><span>恢复点</span><strong>{{ points.length }}</strong></div>
    <div><CheckCircle2 :size="19" /><span>已验证</span><strong>{{ points.filter((point) => point.verified).length }}</strong></div>
    <div><ShieldX :size="19" /><span>未验证</span><strong>{{ points.filter((point) => !point.verified).length }}</strong></div>
    <label class="toggle-control"><input v-model="verifiedOnly" type="checkbox" /><span></span>只看已验证</label>
  </div>
  <section v-if="filtered.length" class="recovery-list">
    <article v-for="point in filtered" :key="point.id" class="recovery-item">
      <span class="snapshot-icon"><DatabaseBackup :size="18" /></span>
      <div class="snapshot-main"><strong>{{ point.service_name }}</strong><span>{{ hostName(point.host_id) }}</span></div>
      <div><small>快照</small><code>{{ point.snapshot_id.slice(0, 12) }}</code></div>
      <div><small>校验和</small><code>{{ point.checksum.slice(0, 12) }}</code></div>
      <div><small>创建时间</small><span>{{ formatTime(point.created_at) }}</span></div>
      <StatusBadge :status="point.verified ? 'verified' : 'unknown'" :label="point.verified ? '已试恢复' : '未验证'" />
      <button class="icon-button bordered" type="button" :title="copied === point.id ? '已复制' : '复制 Dry-run 命令'" aria-label="复制恢复命令" @click="copyCommand(point)"><CheckCircle2 v-if="copied === point.id" :size="16" /><Clipboard v-else :size="16" /></button>
    </article>
  </section>
  <EmptyState v-else title="没有符合条件的恢复点" />
</template>
