<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{
  label: string
  values: Array<number | null>
  unit: '%' | 'B/s'
  tone: 'green' | 'blue' | 'amber' | 'cyan'
}>()

const present = computed(() => props.values.filter((value): value is number => value !== null))
const ceiling = computed(() => {
  if (props.unit === '%') return 100
  const maximum = Math.max(1, ...present.value)
  const magnitude = 10 ** Math.floor(Math.log10(maximum))
  return Math.ceil(maximum / magnitude) * magnitude
})
const points = computed(() => {
  const width = 248
  const count = Math.max(1, props.values.length - 1)
  return props.values
    .map((value, index) => {
      if (value === null) return null
      const x = 58 + (index / count) * width
      const y = 12 + (1 - Math.min(ceiling.value, Math.max(0, value)) / ceiling.value) * 64
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .filter(Boolean)
    .join(' ')
})
const latest = computed(() => [...props.values].reverse().find((value) => value !== null) ?? null)

function compact(value: number): string {
  if (props.unit === '%') return `${Math.round(value)}%`
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)}M`
  if (value >= 1024) return `${(value / 1024).toFixed(1)}K`
  return `${Math.round(value)}`
}
</script>

<template>
  <figure class="trend-chart" :class="`trend-${tone}`">
    <figcaption>
      <span>{{ label }}</span>
      <strong>{{ latest === null ? t('common.none') : `${compact(latest)}${unit === 'B/s' ? '/s' : ''}` }}</strong>
    </figcaption>
    <svg viewBox="0 0 320 92" role="img" :aria-label="t('chart.trend', { label })">
      <g class="trend-grid">
        <line x1="58" y1="12" x2="306" y2="12" />
        <line x1="58" y1="44" x2="306" y2="44" />
        <line x1="58" y1="76" x2="306" y2="76" />
      </g>
      <g class="trend-axis">
        <text x="2" y="16">{{ compact(ceiling) }}</text>
        <text x="2" y="48">{{ compact(ceiling / 2) }}</text>
        <text x="2" y="80">0</text>
      </g>
      <polyline v-if="present.length" class="trend-line" :points="points" />
      <text v-else class="trend-empty" x="182" y="49" text-anchor="middle">{{ t('chart.noData') }}</text>
    </svg>
  </figure>
</template>
