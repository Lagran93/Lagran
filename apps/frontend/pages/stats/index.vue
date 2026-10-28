<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">统计分析</div>
        <div class="page-desc">近 24 小时的请求、命中率与流量分布</div>
      </div>
      <div class="page-actions">
        <select v-model.number="rangeHours" class="select" style="min-width: 120px" @change="load">
          <option :value="1">近 1 小时</option>
          <option :value="24">近 24 小时</option>
          <option :value="168">近 7 天</option>
        </select>
        <span v-if="updatedAt" class="text-muted" style="font-size: 12px">更新于 {{ updatedAt }}</span>
        <button class="btn btn-default" type="button" @click="exportRows">
          <AppIcon name="upload" :size="15" />
          导出 CSV
        </button>
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">实时流量</div>
          <div class="card-desc">每 15 秒自动刷新，可对比上一时间段</div>
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
        <TrafficChart
          :current="series"
          :previous="compare ? previousSeries : []"
          :metric="chartMetric"
          :height="260"
        />
        <div class="compare-strip">
          <span>当前请求 <b>{{ formatNumber(currentTotal.requests) }}</b></span>
          <span class="text-2">上一时段 {{ formatNumber(previousTotal.requests) }}</span>
          <StatusTag :tone="delta >= 0 ? 'success' : 'danger'">
            {{ delta >= 0 ? '+' : '' }}{{ delta.toFixed(1) }}%
          </StatusTag>
          <span class="text-2">命中率 {{ percent(currentTotal.hit_ratio) }}</span>
        </div>
      </div>
    </div>

    <div class="stat-grid">
      <StatCard
        label="请求数"
        :value="formatNumber(stats.total_requests)"
        :hint="`命中 ${formatNumber(stats.cache_hits)} · 未命中 ${formatNumber(stats.cache_misses)}`"
        icon="activity"
      />
      <StatCard
        label="缓存命中率"
        :value="percent(stats.hit_ratio)"
        hint="命中 /（命中 + 未命中）"
        icon="zap"
        tone="green"
      />
      <StatCard
        label="出流量"
        :value="formatBytes(stats.bytes_sent)"
        hint="边缘节点回传给访客的字节数"
        icon="upload"
        tone="orange"
      />
      <StatCard
        label="加速域名"
        :value="formatNumber(stats.domain_count)"
        :hint="auth.isAdmin ? `在线节点 ${formatNumber(stats.online_nodes)}` : '当前账号可见域名'"
        icon="domain"
      />
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">分域名流量</div>
          <div class="card-desc">按请求数排序</div>
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
      <EmptyState
        v-if="!byDomain.length"
        icon="stats"
        title="暂无统计数据"
        text="边缘节点上报指标后（约 15 秒一次），这里会显示各域名的流量与命中率。"
      />
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">源站健康</div>
          <div class="card-desc">由边缘节点每 30 秒探测并上报</div>
        </div>
      </div>
      <div v-if="health.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>域名</th>
              <th>源站地址</th>
              <th>状态</th>
              <th class="num">延迟</th>
              <th class="num">连续失败</th>
              <th>最近检查</th>
              <th>错误信息</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="h in pagedHealth" :key="h.domain_name + h.origin_url">
              <td class="cell-main">{{ h.domain_name }}</td>
              <td class="mono text-2">{{ h.origin_url }}</td>
              <td>
                <StatusTag :tone="h.healthy ? 'success' : 'danger'" dot>
                  {{ h.healthy ? '健康' : '异常' }}
                </StatusTag>
              </td>
              <td class="num">{{ h.latency_ms }} ms</td>
              <td class="num">{{ h.consecutive_fails }}</td>
              <td class="text-muted">{{ fromNow(h.last_check_at) }}</td>
              <td class="text-muted truncate" style="max-width: 220px">{{ h.last_error || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="health.length > pageSize" class="table-footer">
        <AppPagination v-model:page="healthPage" :total="health.length" :page-size="pageSize" />
      </div>
      <EmptyState
        v-if="!health.length"
        icon="shield"
        title="暂无探测数据"
        text="边缘节点启动并同步域名后，大约 30 秒内会上报第一次源站健康结果。"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()

const loading = ref(false)
const updatedAt = ref('')
const rangeHours = ref(24)
const chartMetric = ref<'requests' | 'bytes_sent' | 'hit_ratio'>('requests')
const compare = ref(true)
const series = ref<any[]>([])
const previousSeries = ref<any[]>([])
let timer: ReturnType<typeof setInterval> | null = null
const stats = ref<any>({
  total_requests: 0,
  cache_hits: 0,
  cache_misses: 0,
  bytes_sent: 0,
  hit_ratio: 0,
  domain_count: 0,
  online_nodes: 0,
})
const byDomain = ref<any[]>([])
const health = ref<any[]>([])
const currentTotal = computed(() => totals(series.value))
const previousTotal = computed(() => totals(previousSeries.value))
const delta = computed(() => {
  const prev = previousTotal.value.requests
  if (!prev) return currentTotal.value.requests ? 100 : 0
  return ((currentTotal.value.requests - prev) / prev) * 100
})

function totals(points: any[]) {
  const requests = points.reduce((sum, p) => sum + (p.requests || 0), 0)
  const hits = points.reduce((sum, p) => sum + (p.cache_hits || 0), 0)
  const misses = points.reduce((sum, p) => sum + (p.cache_misses || 0), 0)
  return { requests, hit_ratio: hits + misses ? hits / (hits + misses) : 0 }
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
const healthPage = ref(1)
const pagedByDomain = computed(() => {
  const start = (domainPage.value - 1) * pageSize
  return byDomain.value.slice(start, start + pageSize)
})
const pagedHealth = computed(() => {
  const start = (healthPage.value - 1) * pageSize
  return health.value.slice(start, start + pageSize)
})
watch(
  () => byDomain.value.length,
  (total) => {
    domainPage.value = Math.min(domainPage.value, Math.max(1, Math.ceil(total / pageSize)))
  },
)
watch(
  () => health.value.length,
  (total) => {
    healthPage.value = Math.min(healthPage.value, Math.max(1, Math.ceil(total / pageSize)))
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

async function load() {
  loading.value = true
  try {
    const [s, bd, h] = await Promise.all([
      api.get<any>('/api/v1/stats/summary').catch(() => null),
      api.get<any[]>('/api/v1/stats/by-domain').catch(() => []),
      api.get<any[]>('/api/v1/origin-health').catch(() => []),
      loadSeries(),
    ])
    if (s) stats.value = s
    byDomain.value = bd || []
    health.value = h || []
    updatedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = setInterval(loadSeries, 15_000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.compare-strip {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 20px;
  margin-top: 10px;
  font-size: 12px;
  color: var(--text-2);
}

.compare-strip b {
  color: var(--text);
}

@media (max-width: 640px) {
  .table {
    min-width: 760px;
  }
}
</style>
