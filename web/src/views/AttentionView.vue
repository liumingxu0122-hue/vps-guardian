<script setup lang="ts">
import { ArrowUpRight, Clock3, RefreshCw, TriangleAlert } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { AttentionResponse } from '../types'
import { relativeTime, titleize } from '../utils'

const data = ref<AttentionResponse | null>(null)
const loading = ref(true)
const error = ref(false)
const severity = ref('all')
const kind = ref('all')
const kinds = computed(() => [...new Set((data.value?.items ?? []).map((item) => item.type))])
const items = computed(() =>
  (data.value?.items ?? []).filter(
    (item) =>
      (severity.value === 'all' || item.severity === severity.value) &&
      (kind.value === 'all' || item.type === kind.value),
  ),
)

async function load(): Promise<void> {
  loading.value = true
  error.value = false
  try {
    data.value = await request<AttentionResponse>('/api/v1/attention')
  } catch {
    error.value = true
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <PageHeader :title="$t('attention.title')" :description="$t('attention.description')">
    <template #actions>
      <button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="load">
        <RefreshCw :size="17" />
      </button>
    </template>
  </PageHeader>
  <div class="toolbar-row">
    <select v-model="severity" :aria-label="$t('attention.severity')">
      <option value="all">{{ $t('common.all') }}</option>
      <option value="critical">{{ $t('status.critical') }}</option>
      <option value="warning">Warning</option>
      <option value="info">Info</option>
    </select>
    <select v-model="kind" :aria-label="$t('attention.type')">
      <option value="all">{{ $t('attention.allTypes') }}</option>
      <option v-for="value in kinds" :key="value" :value="value">{{ titleize(value) }}</option>
    </select>
    <span>{{ $t('attention.count', { count: items.length }) }}</span>
  </div>
  <div v-if="error" class="overview-error" role="alert">
    <TriangleAlert :size="20" /><span>{{ $t('attention.fetchFailed') }}</span>
  </div>
  <div v-else-if="loading" class="row-skeletons"><span v-for="item in 6" :key="item"></span></div>
  <section v-else-if="items.length" class="attention-list">
    <article v-for="item in items" :key="item.id" class="attention-row">
      <StatusBadge :status="item.severity" />
      <div>
        <strong>{{ item.object }}</strong>
        <p>{{ item.reason }}</p>
        <small><Clock3 :size="13" />{{ relativeTime(item.observed_at) }} · {{ titleize(item.type) }}</small>
      </div>
      <p class="attention-action">{{ item.suggested_action }}</p>
      <RouterLink :to="item.href" class="secondary-button">
        {{ $t('attention.open') }} <ArrowUpRight :size="14" />
      </RouterLink>
    </article>
  </section>
  <EmptyState v-else :title="$t('attention.empty')" :detail="$t('attention.emptyDetail')" />
</template>
