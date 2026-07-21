<script setup lang="ts">
import { Filter, RefreshCw, Search } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { AuditEntry } from '../types'
import { formatTime, titleize } from '../utils'

const entries = ref<AuditEntry[]>([])
const query = ref('')
const outcome = ref('all')
const filtered = computed(() => entries.value.filter((entry) => {
  const needle = query.value.toLowerCase().trim()
  return (outcome.value === 'all' || entry.outcome === outcome.value) &&
    (!needle || `${entry.action} ${entry.resource_type} ${entry.resource_id ?? ''} ${entry.source_ip ?? ''}`.toLowerCase().includes(needle))
}))

async function load(): Promise<void> { entries.value = await request<AuditEntry[]>('/api/v1/audit') }
onMounted(load)
</script>

<template>
  <PageHeader title="审计日志" description="身份、动作、资源与结果的追加式记录">
    <template #actions><button class="icon-button bordered" type="button" title="刷新" aria-label="刷新审计" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="toolbar-row">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" placeholder="搜索动作、资源或来源地址" /></label>
    <label class="select-field"><Filter :size="15" /><select v-model="outcome"><option value="all">全部结果</option><option value="success">成功</option><option value="denied">拒绝</option><option value="failed">失败</option></select></label>
  </div>
  <div v-if="filtered.length" class="data-table audit-table">
    <div class="table-head"><span>时间</span><span>动作</span><span>资源</span><span>操作者</span><span>来源</span><span>结果</span></div>
    <div v-for="entry in filtered" :key="entry.id" class="table-row">
      <span class="muted">{{ formatTime(entry.created_at) }}</span>
      <strong class="mono">{{ titleize(entry.action) }}</strong>
      <span>{{ entry.resource_type }}<small class="mono">{{ entry.resource_id?.slice(0, 12) || '—' }}</small></span>
      <span class="mono muted">{{ entry.actor_id?.slice(0, 8) || 'system' }}</span>
      <span class="mono muted">{{ entry.source_ip || 'internal' }}</span>
      <StatusBadge :status="entry.outcome" />
    </div>
  </div>
  <EmptyState v-else title="没有匹配的审计记录" />
</template>
