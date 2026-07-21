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
  <PageHeader :title="$t('audit.title')" :description="$t('audit.description')">
    <template #actions><button class="icon-button bordered" type="button" :title="$t('common.refresh')" :aria-label="$t('audit.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="toolbar-row">
    <label class="search-field"><Search :size="16" /><input v-model="query" type="search" :placeholder="$t('audit.searchPlaceholder')" /></label>
    <label class="select-field"><Filter :size="15" /><select v-model="outcome"><option value="all">{{ $t('audit.allOutcomes') }}</option><option value="success">{{ $t('status.success') }}</option><option value="denied">{{ $t('status.denied') }}</option><option value="failed">{{ $t('status.failed') }}</option></select></label>
  </div>
  <div v-if="filtered.length" class="data-table audit-table">
    <div class="table-head"><span>{{ $t('audit.time') }}</span><span>{{ $t('audit.action') }}</span><span>{{ $t('audit.resource') }}</span><span>{{ $t('audit.actor') }}</span><span>{{ $t('audit.source') }}</span><span>{{ $t('audit.outcome') }}</span></div>
    <div v-for="entry in filtered" :key="entry.id" class="table-row">
      <span class="muted">{{ formatTime(entry.created_at) }}</span>
      <strong class="mono">{{ titleize(entry.action) }}</strong>
      <span>{{ entry.resource_type }}<small class="mono">{{ entry.resource_id?.slice(0, 12) || '—' }}</small></span>
      <span class="mono muted">{{ entry.actor_id?.slice(0, 8) || $t('common.system') }}</span>
      <span class="mono muted">{{ entry.source_ip || $t('common.internal') }}</span>
      <StatusBadge :status="entry.outcome" />
    </div>
  </div>
  <EmptyState v-else :title="$t('audit.noMatch')" />
</template>
