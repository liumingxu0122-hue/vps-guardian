<script setup lang="ts">
import { Database, Network, RefreshCw, Server, ShieldCheck } from '@lucide/vue'
import { onMounted, ref } from 'vue'

import { request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import { resourceTypeLabel } from '../presentationRegistry'
import type { DashboardTopology } from '../dashboard'
import { useI18n } from 'vue-i18n'

const { locale, t } = useI18n()
const data = ref<DashboardTopology | null>(null)
const error = ref('')
async function load(): Promise<void> {
  error.value = ''
  try {
    data.value = await request<DashboardTopology>('/api/v1/dashboard/topology')
  } catch {
    error.value = t('topology.unavailable')
  }
}
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('topology.title')" :description="$t('topology.description')">
    <template #actions><button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <div v-if="error" class="v3-module-state error-state" role="alert"><strong>{{ error }}</strong><button class="proto-button secondary" type="button" @click="load">{{ $t('common.retry') }}</button></div>
  <section v-if="data" class="topology-map overview-section">
    <div class="topology-stage">
      <article v-for="node in data.nodes" :key="node.id" class="topology-card">
        <component :is="node.kind === 'database' ? Database : node.kind === 'gateway' ? ShieldCheck : node.kind === 'agent' ? Server : Network" :size="19" />
        <div><strong>{{ node.label }}</strong><small>{{ resourceTypeLabel(node.kind, locale) }}</small></div>
        <StatusBadge :status="node.status" />
      </article>
    </div>
    <aside class="topology-legend">
      <h2>{{ $t('topology.boundary') }}</h2>
      <p>{{ $t('topology.boundaryDetail') }}</p>
      <dl>
        <div><dt>Controller → Agent</dt><dd>{{ $t('topology.agentBoundary') }}</dd></div>
        <div><dt>Browser → Controller</dt><dd>{{ $t('topology.browserBoundary') }}</dd></div>
        <div><dt>Controller → PostgreSQL</dt><dd>{{ $t('topology.databaseBoundary') }}</dd></div>
      </dl>
    </aside>
  </section>
</template>
