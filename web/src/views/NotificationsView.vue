<script setup lang="ts">
import { BellRing, RefreshCw, RotateCcw } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { NotificationChannel, NotificationDelivery } from '../types'
import { formatTime } from '../utils'

const channels = ref<NotificationChannel[]>([])
const deliveries = ref<NotificationDelivery[]>([])
const channelMap = computed(() => Object.fromEntries(channels.value.map((channel) => [channel.id, channel])))
async function load(): Promise<void> {
  ;[channels.value, deliveries.value] = await Promise.all([
    request<NotificationChannel[]>('/api/v1/notification-channels'),
    request<NotificationDelivery[]>('/api/v1/notification-deliveries'),
  ])
}
async function retry(delivery: NotificationDelivery): Promise<void> {
  await request<NotificationDelivery>(`/api/v1/notification-deliveries/${delivery.id}/retry`, { method: 'POST' })
  await load()
}
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('notifications.title')" :description="$t('notifications.description')">
    <template #actions><button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <section class="notification-summary">
    <article v-for="channel in channels" :key="channel.id"><BellRing :size="17" /><div><strong>{{ channel.name }}</strong><small>{{ channel.kind }} · {{ channel.event_scope.join(', ') || $t('notifications.allEvents') }}</small></div><StatusBadge :status="channel.enabled ? 'enabled' : 'disabled'" /></article>
  </section>
  <section class="data-table delivery-table">
    <div class="data-table-head"><span>{{ $t('notifications.channel') }}</span><span>{{ $t('notifications.event') }}</span><span>{{ $t('common.status') }}</span><span>{{ $t('notifications.attempts') }}</span><span>{{ $t('notifications.detail') }}</span><span>{{ $t('common.actions') }}</span></div>
    <div v-for="delivery in deliveries" :key="delivery.id" class="data-table-row">
      <span>{{ channelMap[delivery.channel_id]?.name ?? delivery.channel_id.slice(0, 8) }}</span>
      <span>{{ delivery.event_type }}</span>
      <StatusBadge :status="delivery.status" />
      <span>{{ delivery.attempt_count }}</span>
      <span><strong>{{ delivery.error_summary ?? delivery.response_code ?? '—' }}</strong><small>{{ formatTime(delivery.created_at) }}</small></span>
      <button v-if="['failed', 'dead_letter'].includes(delivery.status)" class="secondary-button" type="button" @click="retry(delivery)"><RotateCcw :size="14" />{{ $t('common.retry') }}</button>
      <span v-else>—</span>
    </div>
  </section>
  <EmptyState v-if="!deliveries.length" :title="$t('notifications.empty')" />
</template>
