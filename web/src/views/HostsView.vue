<script setup lang="ts">
import { MapPin, Plus, RefreshCw, Search, Server, X } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { jsonBody, request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import MetricBar from '../components/MetricBar.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { session } from '../session'
import type { Host, LatestSnapshot } from '../types'
import { formatBytes, formatDuration, percentUsed, relativeTime } from '../utils'

const hosts = ref<Host[]>([])
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
    formError.value = error instanceof Error ? error.message : '添加失败'
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
  <PageHeader title="主机" description="节点身份、Agent 在线状态与最新资源指标">
    <template #actions>
      <button class="icon-button bordered" type="button" title="刷新" aria-label="刷新主机" @click="load"><RefreshCw :size="17" /></button>
      <button v-if="canCreate" class="primary-button" type="button" @click="dialog?.showModal()"><Plus :size="16" />添加主机</button>
    </template>
  </PageHeader>
  <div class="toolbar-row">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" placeholder="搜索主机、地址或地区" /></label>
    <span>{{ filtered.length }} / {{ hosts.length }}</span>
  </div>
  <section class="host-list">
    <article v-for="host in filtered" :key="host.id" class="host-item" :class="{ expanded: expanded === host.id }">
      <button class="host-summary" type="button" @click="toggle(host)">
        <span class="host-icon"><Server :size="19" /></span>
        <span class="host-identity"><strong>{{ host.name }}</strong><small class="mono">{{ host.address }}</small></span>
        <span class="host-location"><MapPin :size="14" />{{ host.location || '未设置' }}</span>
        <span class="host-os">{{ host.os_name || '待发现' }}</span>
        <StatusBadge :status="host.status" />
        <span class="last-seen">{{ relativeTime(host.last_seen_at) }}</span>
      </button>
      <div v-if="expanded === host.id" class="host-detail">
        <template v-if="snapshots[host.id]?.collected_at">
          <MetricBar label="内存" :value="percentUsed(snapshots[host.id].payload.memory_total_bytes, snapshots[host.id].payload.memory_available_bytes)" :detail="formatBytes(snapshots[host.id].payload.memory_total_bytes)" />
          <MetricBar label="磁盘" :value="percentUsed(snapshots[host.id].payload.disk_total_bytes, snapshots[host.id].payload.disk_free_bytes)" :detail="formatBytes(snapshots[host.id].payload.disk_total_bytes)" />
          <MetricBar label="Inode" :value="percentUsed(snapshots[host.id].payload.inode_total, snapshots[host.id].payload.inode_free)" />
          <dl class="metric-facts"><div><dt>Load 1m</dt><dd>{{ snapshots[host.id].payload.load_1 ?? '—' }}</dd></div><div><dt>Uptime</dt><dd>{{ formatDuration(snapshots[host.id].payload.uptime_seconds) }}</dd></div><div><dt>采集时间</dt><dd>{{ relativeTime(snapshots[host.id].collected_at) }}</dd></div></dl>
        </template>
        <EmptyState v-else title="尚无 Agent 指标" />
      </div>
    </article>
    <EmptyState v-if="!loading && !filtered.length" title="没有匹配的主机" />
  </section>
  <dialog ref="dialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>添加受管主机</h2><p>创建清单后再通过安装脚本绑定 Agent</p></div><button class="icon-button" aria-label="关闭"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createHost">
      <label><span>名称</span><input v-model="newHost.name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{1,119}" /></label>
      <label><span>地址</span><input v-model="newHost.address" required /></label>
      <div class="form-grid"><label><span>操作系统</span><input v-model="newHost.os_name" placeholder="Ubuntu 24.04" /></label><label><span>地区</span><input v-model="newHost.location" placeholder="Hong Kong" /></label></div>
      <p v-if="formError" class="form-error">{{ formError }}</p>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">取消</button><button class="primary-button" type="submit" :disabled="creating">{{ creating ? '正在创建' : '创建主机' }}</button></div>
    </form>
  </dialog>
</template>
