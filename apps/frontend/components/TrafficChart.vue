<script setup lang="ts">
interface Point {
  ts: string
  requests: number
  cache_hits: number
  cache_misses: number
  bytes_sent: number
  hit_ratio: number
}

const props = withDefaults(
  defineProps<{
    current: Point[]
    previous?: Point[]
    metric?: 'requests' | 'bytes_sent' | 'hit_ratio'
    height?: number
    color?: string
  }>(),
  { previous: () => [], metric: 'requests', height: 240, color: '#1677ff' },
)

const W = ref(920)
const H = computed(() => (W.value < 520 ? Math.min(props.height, 210) : props.height))
const viewBox = computed(() => `0 0 ${W.value} ${H.value}`)
const chartStyle = computed(() => ({ height: `${H.value}px` }))
const chartRight = computed(() => W.value - PAD.right)
const xLabelY = computed(() => H.value - 8)
const PAD = { left: 48, right: 16, top: 16, bottom: 28 }
const chartEl = ref<HTMLElement | null>(null)
let resizeObserver: ResizeObserver | null = null

onMounted(() => {
  if (!import.meta.client || !chartEl.value) return
  const updateWidth = () => {
    const next = Math.round(chartEl.value?.clientWidth || 920)
    // SVG user units must track CSS pixels; otherwise an ultrawide card
    // stretches the 920-unit viewBox and makes axis labels enormous.
    W.value = Math.max(280, Math.min(next, 2400))
  }
  updateWidth()
  resizeObserver = new ResizeObserver(updateWidth)
  resizeObserver.observe(chartEl.value)
})

onBeforeUnmount(() => {
  resizeObserver?.disconnect()
  resizeObserver = null
})

const maxValue = computed(() => {
  const values = [
    ...props.current.map((p) => p[props.metric]),
    ...props.previous.map((p) => p[props.metric]),
  ]
  return Math.max(1, ...values)
})

function x(index: number, total: number) {
  if (total <= 1) return PAD.left
  return PAD.left + (index / (total - 1)) * (W.value - PAD.left - PAD.right)
}

function y(value: number) {
  const h = H.value - PAD.top - PAD.bottom
  return PAD.top + (1 - value / maxValue.value) * h
}

function path(points: Point[]) {
  if (!points.length) return ''
  return points
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i, points.length).toFixed(1)},${y(p[props.metric]).toFixed(1)}`)
    .join(' ')
}

function area(points: Point[]) {
  if (!points.length) return ''
  const base = H.value - PAD.bottom
  return `${path(points)} L${x(points.length - 1, points.length).toFixed(1)},${base} L${PAD.left},${base} Z`
}

const labels = computed(() => {
  const out: { x: number; text: string }[] = []
  const data = props.current
  if (!data.length) return out
  const maxLabels = Math.max(3, Math.min(8, Math.floor(W.value / 120)))
  const step = Math.max(1, Math.ceil(data.length / maxLabels))
  for (let i = 0; i < data.length; i += step) {
    const d = new Date(data[i].ts)
    out.push({
      x: x(i, data.length),
      text: d.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }),
    })
  }
  return out
})

function fmt(v: number) {
  if (props.metric === 'hit_ratio') return `${(v * 100).toFixed(0)}%`
  if (props.metric === 'bytes_sent') {
    if (v >= 1024 * 1024 * 1024) return `${(v / 1024 / 1024 / 1024).toFixed(1)}G`
    if (v >= 1024 * 1024) return `${(v / 1024 / 1024).toFixed(1)}M`
    if (v >= 1024) return `${(v / 1024).toFixed(1)}K`
    return String(v)
  }
  return v >= 1000 ? `${(v / 1000).toFixed(1)}K` : String(v)
}

const gridLines = computed(() => [0, 0.25, 0.5, 0.75, 1].map((r) => ({
  y: PAD.top + r * (H.value - PAD.top - PAD.bottom),
  value: maxValue.value * (1 - r),
})))
</script>

<template>
  <div ref="chartEl" class="traffic-chart" :style="chartStyle">
    <svg
      :viewBox="viewBox"
      :style="chartStyle"
      preserveAspectRatio="none"
      role="img"
      aria-label="traffic chart"
    >
      <defs>
        <linearGradient :id="`fill-${metric}`" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" :stop-color="color" stop-opacity="0.28" />
          <stop offset="1" :stop-color="color" stop-opacity="0.02" />
        </linearGradient>
      </defs>
      <g v-for="(line, i) in gridLines" :key="i">
        <line
          :x1="PAD.left"
          :x2="chartRight"
          :y1="line.y"
          :y2="line.y"
          stroke="var(--border)"
          stroke-width="1"
          stroke-dasharray="3 4"
        />
        <text :x="PAD.left - 8" :y="line.y + 4" text-anchor="end" class="axis">
          {{ fmt(line.value) }}
        </text>
      </g>
      <path v-if="previous.length" :d="path(previous)" fill="none" stroke="var(--text-4)" stroke-width="1.5" stroke-dasharray="5 4" opacity="0.8" />
      <path :d="area(current)" :fill="`url(#fill-${metric})`" />
      <path :d="path(current)" fill="none" :stroke="color" stroke-width="2" stroke-linejoin="round" />
      <text v-for="label in labels" :key="label.x" :x="label.x" :y="xLabelY" text-anchor="middle" class="axis">
        {{ label.text }}
      </text>
    </svg>
    <div v-if="!current.length" class="chart-empty">暂无流量数据</div>
  </div>
</template>

<style scoped>
.traffic-chart {
  position: relative;
  width: 100%;
  min-height: 0;
}

svg {
  display: block;
  width: 100%;
  overflow: visible;
}

.axis {
  fill: var(--text-3);
  font-size: 10px;
  font-family: var(--font);
  font-variant-numeric: tabular-nums;
}

.chart-empty {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-3);
  font-size: 13px;
}
</style>
