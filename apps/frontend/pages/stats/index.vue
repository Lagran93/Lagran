<template>
  <div class="page stats-page analytics-page">
    <div class="page-head">
      <div>
        <div class="page-title">统计分析</div>
        <div class="page-desc">近 {{ rangeLabel }}的请求、命中率与流量分布</div>
      </div>
      <div class="page-actions">
        <select v-model.number="rangeHours" class="select" style="min-width: 100px" @change="load">
          <option :value="1">近 1 小时</option>
          <option :value="24">近 24 小时</option>
          <option :value="168">近 7 天</option>
        </select>
        <button class="btn btn-default" type="button" @click="exportRows">
          <AppIcon name="upload" :size="15" />
          导出 CSV
        </button>
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <span v-if="updatedAt" class="text-muted" style="font-size: 12px; min-width: 100px;">更新于 {{ updatedAt }}</span>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">流量趋势</div>
          <div class="card-desc">近 {{ rangeLabel }} · 每 15 秒自动刷新 · 可对比上一时间段</div>
        </div>
        <div class="card-extra flex-center gap-8">
          <div class="segmented">
            <button type="button" :class="{ active: chartMetric === 'requests' }" @click="chartMetric = 'requests'">
              请求数
            </button>
            <button type="button" :class="{ active: chartMetric === 'bytes_sent' }" @click="chartMetric = 'bytes_sent'">
              流量
            </button>
            <button type="button" :class="{ active: chartMetric === 'hit_ratio' }" @click="chartMetric = 'hit_ratio'">
              命中率
            </button>
          </div>
          <label class="check" style="font-size: 12px">
            <input v-model="compare" type="checkbox" @change="load" />
            对比上一时段
          </label>
        </div>
      </div>
      <div class="card-body">
        <TrafficChart :current="series" :previous="compare ? previousSeries : []" :metric="chartMetric" :height="260" />
        <div class="range-summary">
          <div class="range-metric">
            <span>请求数</span>
            <b>{{ formatNumber(currentTotal.requests) }}</b>
            <small>
              <template v-if="compare">
                环比
                <StatusTag :tone="delta >= 0 ? 'success' : 'danger'">
                  {{ delta >= 0 ? '+' : '' }}{{ delta.toFixed(1) }}%
                </StatusTag>
              </template>
              <span v-else>未启用对比</span>
            </small>
          </div>
          <div class="range-metric">
            <span>缓存命中率</span>
            <b>{{ percent(currentTotal.hit_ratio) }}</b>
            <small>命中 {{ formatNumber(currentTotal.hits) }}</small>
          </div>
          <div class="range-metric">
            <span>出流量</span>
            <b>{{ formatBytes(currentTotal.bytes) }}</b>
            <small>未命中 {{ formatNumber(currentTotal.misses) }}</small>
          </div>
          <div class="range-metric">
            <span>活跃域名</span>
            <b>{{ formatNumber(byDomain.length) }}</b>
            <small>近 {{ rangeLabel }}</small>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">分域名流量</div>
          <div class="card-desc">近 {{ rangeLabel }}，按请求数排序</div>
        </div>
      </div>
      <div v-if="byDomain.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>域名</th>
              <th class="num">请求数</th>
              <th class="num">缓存命中</th>
              <th class="num">未命中</th>
              <th style="min-width: 180px">命中率</th>
              <th class="num">流量</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in pagedByDomain" :key="d.domain">
              <td class="cell-main">{{ d.domain }}</td>
              <td class="num">{{ formatNumber(d.requests) }}</td>
              <td class="num text-success">{{ formatNumber(d.cache_hits) }}</td>
              <td class="num text-muted">{{ formatNumber(d.cache_misses) }}</td>
              <td>
                <div class="flex-center gap-8">
                  <div class="progress flex-1">
                    <div class="progress-bar" :style="{ width: `${Math.min(100, (d.hit_ratio || 0) * 100)}%` }" />
                  </div>
                  <span class="num" style="width: 48px">{{ percent(d.hit_ratio) }}</span>
                </div>
              </td>
              <td class="num">{{ formatBytes(d.bytes_sent) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="byDomain.length > pageSize" class="table-footer">
        <AppPagination v-model:page="domainPage" :total="byDomain.length" :page-size="pageSize" />
      </div>
      <EmptyState v-if="!byDomain.length" icon="stats" title="暂无统计数据" text="边缘节点上报指标后（约 15 秒一次），这里会显示各域名的流量与命中率。" />
    </div>

  </div>
</template>

<script setup lang="ts">
const api = useApi()

const loading = ref(false)
const updatedAt = ref('')
const rangeHours = ref(24)
const rangeLabel = computed(() =>
  rangeHours.value === 1 ? '1 小时' : rangeHours.value === 24 ? '24 小时' : '7 天',
)
const chartMetric = ref<'requests' | 'bytes_sent' | 'hit_ratio'>('requests')
const compare = ref(true)
const series = ref<any[]>([])
const previousSeries = ref<any[]>([])
const byDomain = ref<any[]>([])
let timer: ReturnType<typeof setInterval> | null = null

const currentTotal = computed(() => totals(series.value))
const previousTotal = computed(() => totals(previousSeries.value))
const delta = computed(() => {
  if (!compare.value) return 0
  const prev = previousTotal.value.requests
  if (!prev) return currentTotal.value.requests ? 100 : 0
  return ((currentTotal.value.requests - prev) / prev) * 100
})

function totals(points: any[]) {
  const requests = points.reduce((sum, p) => sum + (p.requests || 0), 0)
  const hits = points.reduce((sum, p) => sum + (p.cache_hits || 0), 0)
  const misses = points.reduce((sum, p) => sum + (p.cache_misses || 0), 0)
  const bytes = points.reduce((sum, p) => sum + (p.bytes_sent || 0), 0)
  return {
    requests,
    hits,
    misses,
    bytes,
    hit_ratio: hits + misses ? hits / (hits + misses) : 0,
  }
}

function exportRows() {
  exportCsv(
    `lagran-stats-${new Date().toISOString().slice(0, 10)}`,
    byDomain.value,
    [
      { key: 'domain', label: '域名' },
      { key: 'requests', label: '请求数' },
      { key: 'cache_hits', label: '缓存命中' },
      { key: 'cache_misses', label: '未命中' },
      { key: 'hit_ratio', label: '命中率', value: (row: any) => `${((row.hit_ratio || 0) * 100).toFixed(2)}%` },
      { key: 'bytes_sent', label: '流量(bytes)' },
    ],
  )
}

const pageSize = 10
const domainPage = ref(1)
const pagedByDomain = computed(() => {
  const start = (domainPage.value - 1) * pageSize
  return byDomain.value.slice(start, start + pageSize)
})
watch(
  () => byDomain.value.length,
  (total) => {
    domainPage.value = Math.min(domainPage.value, Math.max(1, Math.ceil(total / pageSize)))
  },
)

async function loadSeries() {
  const bucket = rangeHours.value <= 1 ? 60 : rangeHours.value <= 24 ? 1800 : 3600
  const res = await api
    .get<any>(
      `/api/v1/stats/timeseries?hours=${rangeHours.value}&bucket=${bucket}&compare=${compare.value ? 'true' : 'false'}`,
    )
    .catch(() => null)
  series.value = res?.current || []
  previousSeries.value = res?.previous || []
}

async function loadByDomain() {
  const data = await api
    .get<any[]>(`/api/v1/stats/by-domain?hours=${rangeHours.value}`)
    .catch(() => [])
  byDomain.value = data || []
}

async function load() {
  loading.value = true
  try {
    await Promise.all([loadSeries(), loadByDomain()])
    updatedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = setInterval(() => {
    loadSeries()
    loadByDomain()
  }, 15_000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.range-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px solid var(--divider);
}

.range-metric {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.range-metric>span {
  color: var(--text-3);
  font-size: 12px;
}

.range-metric>b {
  color: var(--text);
  font-size: 24px;
  font-weight: 600;
  line-height: 1.2;
  font-variant-numeric: tabular-nums;
}

.range-metric>small {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-3);
  font-size: 11px;
  min-height: 18px;
}

@media (max-width: 860px) {
  .range-summary {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 640px) {
  .table {
    min-width: 760px;
  }

  .range-metric>b {
    font-size: 21px;
  }
}
</style>
