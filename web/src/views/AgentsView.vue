<script setup lang="ts">
import { KeyRound, RefreshCw, Server } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { Agent, AgentIdentity, Host } from '../types'
import { formatTime, relativeTime } from '../utils'

const agents = ref<Agent[]>([])
const hosts = ref<Host[]>([])
const selected = ref<string | null>(null)
const identities = ref<AgentIdentity[]>([])
const hostMap = computed(() => Object.fromEntries(hosts.value.map((host) => [host.id, host])))
async function load(): Promise<void> {
  ;[agents.value, hosts.value] = await Promise.all([
    request<Agent[]>('/api/v1/agents'),
    request<Host[]>('/api/v1/hosts'),
  ])
}
async function inspect(agent: Agent): Promise<void> {
  selected.value = agent.id
  identities.value = await request<AgentIdentity[]>(`/api/v1/agents/${agent.id}/identities`)
}
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('agents.title')" :description="$t('agents.description')">
    <template #actions><button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div class="split-view" :class="{ 'detail-open': selected }">
    <section class="agent-list">
      <button v-for="agent in agents" :key="agent.id" type="button" class="agent-row" @click="inspect(agent)">
        <Server :size="18" />
        <span><strong>{{ hostMap[agent.host_id]?.name ?? agent.host_id }}</strong><small>{{ agent.version ?? $t('common.unknown') }}</small></span>
        <StatusBadge :status="agent.revoked_at ? 'revoked' : 'active'" />
        <span>{{ relativeTime(agent.last_heartbeat_at) }}</span>
        <code>v{{ agent.identity_version }}</code>
      </button>
      <EmptyState v-if="!agents.length" :title="$t('agents.empty')" />
    </section>
    <aside v-if="selected" class="detail-panel">
      <header><div><span class="mono">{{ selected.slice(0, 8) }}</span><h2>{{ $t('agents.identities') }}</h2></div></header>
      <article v-for="identity in identities" :key="identity.id" class="identity-card">
        <KeyRound :size="16" /><div><strong>Generation {{ identity.generation }}</strong><small>{{ formatTime(identity.created_at) }}</small></div>
        <StatusBadge :status="identity.state" />
        <dl><div><dt>Serial</dt><dd class="mono">{{ identity.certificate_serial ?? '—' }}</dd></div><div><dt>Expires</dt><dd>{{ formatTime(identity.expires_at) }}</dd></div><div><dt>Verified</dt><dd>{{ formatTime(identity.verified_at) }}</dd></div></dl>
      </article>
    </aside>
  </div>
</template>
