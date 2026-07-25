<script setup lang="ts">
import { Database, Network, RefreshCw, Server, ShieldCheck } from '@lucide/vue'
import { onMounted, ref } from 'vue'

import { request } from '../api'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { Overview } from '../types'

const data = ref<Overview | null>(null)
async function load(): Promise<void> {
  data.value = await request<Overview>('/api/v1/overview?window=24h')
}
onMounted(load)
</script>

<template>
  <PageHeader :title="$t('topology.title')" :description="$t('topology.description')">
    <template #actions><button class="icon-button bordered" type="button" :aria-label="$t('common.refresh')" @click="load"><RefreshCw :size="17" /></button></template>
  </PageHeader>
  <section v-if="data" class="topology-map overview-section">
    <div class="topology-stage">
      <article v-for="node in data.topology" :key="node.id" class="topology-card">
        <component :is="node.kind === 'database' ? Database : node.kind === 'gateway' ? ShieldCheck : node.kind === 'agent' ? Server : Network" :size="19" />
        <div><strong>{{ node.label }}</strong><small>{{ node.kind }}</small></div>
        <StatusBadge :status="node.status" />
      </article>
    </div>
    <aside class="topology-legend">
      <h2>{{ $t('topology.boundary') }}</h2>
      <p>{{ $t('topology.boundaryDetail') }}</p>
      <dl>
        <div><dt>Controller → Agent</dt><dd>mTLS + signed requests + nonce</dd></div>
        <div><dt>Browser → Controller</dt><dd>Login + RBAC + CSRF</dd></div>
        <div><dt>Controller → PostgreSQL</dt><dd>Private container network</dd></div>
      </dl>
    </aside>
  </section>
</template>
