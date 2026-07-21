<script setup lang="ts">
import { ArrowRight, CheckCircle2, ShieldAlert, Wrench } from '@lucide/vue'
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { request } from '../api'
import EmptyState from '../components/EmptyState.vue'
import PageHeader from '../components/PageHeader.vue'
import StatusBadge from '../components/StatusBadge.vue'
import type { Incident } from '../types'

const incidents = ref<Incident[]>([])
const repairable = computed(() => incidents.value.filter((item) => item.status !== 'resolved' && item.recommendations.length))
onMounted(async () => { incidents.value = await request<Incident[]>('/api/v1/incidents') })
</script>

<template>
  <PageHeader :title="$t('repairs.title')" :description="$t('repairs.description')" />
  <section v-if="repairable.length" class="repair-list">
    <article v-for="incident in repairable" :key="incident.id" class="repair-item">
      <div class="repair-status" :class="{ allowed: incident.auto_repair_allowed }"><CheckCircle2 v-if="incident.auto_repair_allowed" :size="19" /><ShieldAlert v-else :size="19" /></div>
      <div class="repair-content">
        <div class="repair-heading"><div><h2>{{ incident.title }}</h2><span>{{ incident.risk }}</span></div><StatusBadge :status="incident.auto_repair_allowed ? 'approved' : 'pending'" :label="incident.auto_repair_allowed ? $t('repairs.automatic') : $t('repairs.approval')" /></div>
        <ul><li v-for="recommendation in incident.recommendations" :key="recommendation"><Wrench :size="15" />{{ recommendation }}</li></ul>
        <div class="verification-line"><strong>{{ $t('repairs.verification') }}</strong><span>{{ incident.verification_plan.join(' · ') || $t('repairs.defaultVerification') }}</span></div>
      </div>
      <RouterLink v-if="!incident.auto_repair_allowed" to="/approvals" class="icon-button bordered" :title="$t('repairs.openApproval')" :aria-label="$t('repairs.openApproval')"><ArrowRight :size="17" /></RouterLink>
    </article>
  </section>
  <EmptyState v-else :title="$t('repairs.noItems')" />
</template>
