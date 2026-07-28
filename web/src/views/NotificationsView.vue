<script setup lang="ts">
import { BellRing, RefreshCw, RotateCcw } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import DataTable from '../components/v3/DataTable.vue'
import { productLabel } from '../presentationRegistry'
import type { NotificationChannel, NotificationDelivery } from '../types'
import { formatTime } from '../utils'

const channels = ref<NotificationChannel[]>([])
const { locale } = useI18n()
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
    <article v-for="channel in channels" :key="channel.id"><BellRing :size="17" /><div><strong>{{ channel.name }}</strong><small>{{ productLabel('notification', channel.kind, locale) }} · {{ channel.event_scope.length ? (locale === 'zh-CN' ? `${channel.event_scope.length} 类事件` : `${channel.event_scope.length} event types`) : $t('notifications.allEvents') }}</small></div><StatusBadge :status="channel.enabled ? 'enabled' : 'disabled'" /></article>
  </section>
  <DataTable :label="$t('notifications.title')" :empty="!deliveries.length">
    <template #head><tr><th>{{ $t('notifications.channel') }}</th><th>{{ $t('notifications.event') }}</th><th>{{ $t('common.status') }}</th><th>{{ $t('notifications.attempts') }}</th><th>{{ $t('notifications.detail') }}</th><th>{{ $t('common.actions') }}</th></tr></template>
    <tr v-for="delivery in deliveries" :key="delivery.id">
      <td :data-label="locale === 'zh-CN' ? '通道' : 'Channel'"><span>{{ channelMap[delivery.channel_id]?.name ?? (locale === 'zh-CN' ? '已移除通道' : 'Removed channel') }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '事件' : 'Event'"><span>{{ locale === 'zh-CN' ? '通知事件' : 'Notification event' }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '状态' : 'Status'"><StatusBadge :status="delivery.status" /></td>
      <td :data-label="locale === 'zh-CN' ? '尝试次数' : 'Attempts'"><span>{{ delivery.attempt_count }}</span></td>
      <td :data-label="locale === 'zh-CN' ? '详情' : 'Detail'"><span><strong>{{ delivery.error_summary ?? delivery.response_code ?? '—' }}</strong><small>{{ formatTime(delivery.created_at) }}</small></span></td>
      <td :data-label="locale === 'zh-CN' ? '操作' : 'Actions'"><button v-if="['failed', 'dead_letter'].includes(delivery.status)" class="secondary-button" type="button" @click="retry(delivery)"><RotateCcw :size="14" />{{ $t('common.retry') }}</button><span v-else>—</span></td>
    </tr>
    <template #empty><EmptyState :title="$t('notifications.empty')" /></template>
  </DataTable>
</template>
