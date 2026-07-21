<script setup lang="ts">
import { BellRing, Check, LockKeyhole, Plus, RefreshCw, Send, ShieldCheck, X } from '@lucide/vue'
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { jsonBody, request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import type { NotificationChannel, PublicSettings } from '../types'
import { formatBytes, titleize } from '../utils'

const settings = ref<PublicSettings | null>(null)
const { t } = useI18n()
const channels = ref<NotificationChannel[]>([])
const dialog = ref<HTMLDialogElement | null>(null)
const creating = ref(false)
const testResult = ref('')
const newChannel = ref({ name: '', kind: 'webhook' as NotificationChannel['kind'], endpointRef: '', tokenFile: '', chatRef: '', hostRef: '', portRef: '', fromRef: '', toRef: '', usernameRef: '', passwordFile: '' })
async function load(): Promise<void> {
  ;[settings.value, channels.value] = await Promise.all([
    request<PublicSettings>('/api/v1/settings/public'),
    request<NotificationChannel[]>('/api/v1/notification-channels'),
  ])
}

function channelConfiguration(): Record<string, string> {
  const channel = newChannel.value
  if (channel.kind === 'webhook') return { endpoint_env: channel.endpointRef }
  if (channel.kind === 'telegram') return { token_file: channel.tokenFile, chat_id_env: channel.chatRef, api_base_env: channel.endpointRef }
  const configuration: Record<string, string> = {
    host_env: channel.hostRef, port_env: channel.portRef, from_env: channel.fromRef, to_env: channel.toRef,
  }
  if (channel.usernameRef) configuration.username_env = channel.usernameRef
  if (channel.passwordFile) configuration.password_file = channel.passwordFile
  return configuration
}

async function createChannel(): Promise<void> {
  creating.value = true
  try {
    await request<NotificationChannel>('/api/v1/notification-channels', {
      method: 'POST',
      ...jsonBody({ name: newChannel.value.name, kind: newChannel.value.kind, configuration: channelConfiguration() }),
    })
    dialog.value?.close()
    await load()
  } finally {
    creating.value = false
  }
}

async function testChannel(channel: NotificationChannel): Promise<void> {
  testResult.value = ''
  try {
    await request(`/api/v1/notification-channels/${channel.id}/test`, { method: 'POST' })
    testResult.value = t('settings.testPassed')
  } catch {
    testResult.value = t('settings.testLocalOnly')
  }
}
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('settings.title')" :description="$t('settings.description')">
    <template #actions><button class="icon-button bordered" type="button" :title="$t('common.refresh')" :aria-label="$t('settings.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div v-if="settings" class="settings-layout">
    <section class="settings-section">
      <div class="section-heading"><div><h2>{{ $t('settings.runtime') }}</h2><span>{{ $t('settings.readOnly') }}</span></div><span class="environment-badge">{{ settings.environment }}</span></div>
      <dl class="settings-list">
        <div><dt>{{ $t('settings.secureCookies') }}</dt><dd><Check v-if="settings.secure_cookies" :size="16" /><X v-else :size="16" />{{ settings.secure_cookies ? $t('common.enabled') : $t('common.disabled') }}</dd></div>
        <div><dt>{{ $t('settings.autoSchema') }}</dt><dd>{{ settings.auto_create_schema ? $t('common.enabled') : $t('common.disabled') }}</dd></div>
        <div><dt>{{ $t('settings.logLimit') }}</dt><dd>{{ formatBytes(settings.max_incident_log_bytes) }}</dd></div>
        <div><dt>{{ $t('settings.loginAttempts') }}</dt><dd>{{ $t('settings.attempts', { count: settings.login_attempts_per_10m }) }}</dd></div>
        <div><dt>{{ $t('settings.nonceTtl') }}</dt><dd>{{ settings.nonce_ttl_seconds }} {{ $t('common.seconds') }}</dd></div>
        <div><dt>{{ $t('settings.metricRetention') }}</dt><dd>{{ settings.metric_retention_days }} {{ $t('common.days') }} / {{ settings.max_metric_rows_per_host }}</dd></div>
        <div><dt>{{ $t('settings.checkRetention') }}</dt><dd>{{ settings.service_result_retention_days }} {{ $t('common.days') }} / {{ settings.max_results_per_check }}</dd></div>
        <div><dt>{{ $t('settings.externalNotifications') }}</dt><dd>{{ settings.external_notifications_enabled ? $t('common.enabled') : $t('common.disabled') }}</dd></div>
        <div><dt>{{ $t('settings.allowedOrigins') }}</dt><dd class="mono wrap">{{ settings.allowed_origins.join(', ') }}</dd></div>
      </dl>
    </section>
    <section class="settings-section">
      <div class="section-heading"><div><h2>{{ $t('settings.securityBoundary') }}</h2><span>{{ $t('settings.serverEnforced') }}</span></div><ShieldCheck :size="19" /></div>
      <div class="feature-grid">
        <div v-for="(enabled, name) in settings.features" :key="name" :class="{ disabled: !enabled }"><span><LockKeyhole :size="16" />{{ titleize(String(name)) }}</span><strong>{{ enabled ? $t('common.enabled') : $t('common.disabled') }}</strong></div>
      </div>
    </section>
    <section class="settings-section notification-settings">
      <div class="section-heading"><div><h2>{{ $t('settings.notifications') }}</h2><span>{{ $t('settings.notificationReferences') }}</span></div><button class="primary-button" type="button" @click="dialog?.showModal()"><Plus :size="15" />{{ $t('settings.addChannel') }}</button></div>
      <div v-if="channels.length" class="channel-list">
        <div v-for="channel in channels" :key="channel.id" class="channel-row"><BellRing :size="17" /><div><strong>{{ channel.name }}</strong><span>{{ channel.kind }} · {{ channel.enabled ? $t('common.enabled') : $t('common.disabled') }}</span></div><button class="secondary-button" type="button" @click="testChannel(channel)"><Send :size="14" />{{ $t('settings.testChannel') }}</button></div>
      </div>
      <p v-else>{{ $t('settings.noChannels') }}</p>
      <p v-if="testResult" role="status">{{ testResult }}</p>
    </section>
  </div>
  <dialog ref="dialog" class="modal-dialog">
    <form method="dialog" class="dialog-header"><div><h2>{{ $t('settings.addChannel') }}</h2><p>{{ $t('settings.notificationReferences') }}</p></div><button class="icon-button" :aria-label="$t('common.close')"><X :size="18" /></button></form>
    <form class="dialog-form" @submit.prevent="createChannel">
      <div class="form-grid"><label><span>{{ $t('settings.channelName') }}</span><input v-model="newChannel.name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{1,119}" /></label><label><span>{{ $t('settings.channelKind') }}</span><select v-model="newChannel.kind"><option value="webhook">Webhook</option><option value="telegram">Telegram</option><option value="smtp">SMTP</option></select></label></div>
      <template v-if="newChannel.kind === 'webhook'"><label><span>{{ $t('settings.endpointEnv') }}</span><input v-model="newChannel.endpointRef" required /></label></template>
      <template v-else-if="newChannel.kind === 'telegram'"><label><span>{{ $t('settings.tokenFile') }}</span><input v-model="newChannel.tokenFile" required /></label><label><span>{{ $t('settings.chatEnv') }}</span><input v-model="newChannel.chatRef" required /></label><label><span>{{ $t('settings.apiBaseEnv') }}</span><input v-model="newChannel.endpointRef" required /></label></template>
      <template v-else><div class="form-grid"><label><span>{{ $t('settings.hostEnv') }}</span><input v-model="newChannel.hostRef" required /></label><label><span>{{ $t('settings.portEnv') }}</span><input v-model="newChannel.portRef" required /></label></div><div class="form-grid"><label><span>{{ $t('settings.fromEnv') }}</span><input v-model="newChannel.fromRef" required /></label><label><span>{{ $t('settings.toEnv') }}</span><input v-model="newChannel.toRef" required /></label></div><div class="form-grid"><label><span>{{ $t('settings.usernameEnv') }}</span><input v-model="newChannel.usernameRef" /></label><label><span>{{ $t('settings.passwordFile') }}</span><input v-model="newChannel.passwordFile" /></label></div></template>
      <div class="dialog-actions"><button class="secondary-button" type="button" @click="dialog?.close()">{{ $t('common.cancel') }}</button><button class="primary-button" type="submit" :disabled="creating">{{ $t('settings.createChannel') }}</button></div>
    </form>
  </dialog>
</template>
