<template>
  <div class="monitor-page analytics-page">
    <div class="monitor-actions">
      <div>
        <div class="monitor-title">实时监控</div>
        <div class="monitor-sub">
          实时 5 分钟 · 近 1 小时趋势 · 每 10 秒刷新 · 最后更新 {{ updatedAt }}
        </div>
      </div>
      <div class="flex-center gap-8">
        <span class="live-badge"><i /> LIVE</span>
        <button class="btn btn-default btn-sm" type="button" @click="fullscreen">
          {{ isFull ? '退出全屏' : '全屏' }}
        </button>
      </div>
    </div>

    <div class="wall-stats">
      <div class="wall-card">
        <div class="wall-label">{{ realtime.enabled ? '实时请求' : '请求 · 近 1 小时' }}</div>
        <div class="wall-value">{{ formatNumber(live.requests) }}</div>
        <div class="wall-hint">{{ realtime.enabled ? '近 5 分钟' : '近 1 小时' }} · 1 小时 {{ formatNumber(hourStats.requests) }}</div>
      </div>
      <div class="wall-card">
        <div class="wall-label">缓存命中率</div>
        <div class="wall-value accent">{{ percent(live.hit_ratio) }}</div>
        <div class="wall-hint">1 小时 {{ percent(hourStats.hit_ratio) }}</div>
      </div>
      <div class="wall-card">
        <div class="wall-label">出流量</div>
        <div class="wall-value">{{ formatBytes(live.bytes) }}</div>
        <div class="wall-hint">1 小时 {{ formatBytes(hourStats.bytes) }}</div>
      </div>
      <div class="wall-card">
        <div class="wall-label">在线节点</div>
        <div class="wall-value accent2">{{ onlineNodes }}</div>
        <div class="wall-hint">活跃域名 {{ live.domain_count }}</div>
      </div>
    </div>

    <div class="wall-grid">
      <div class="wall-card chart-card">
        <div class="wall-card-head">
          <span>近 1 小时请求趋势</span>
          <span class="wall-legend"><i /> 当前 <i class="prev" /> 上一时段</span>
        </div>
        <TrafficChart :current="series" :previous="previousSeries" metric="requests" :height="300" color="#4b9bff" />
      </div>

      <div class="wall-card">
        <div class="wall-card-head">
          <span>{{ topIsLive ? '实时域名 TOP · 5 分钟' : '域名流量 TOP · 1 小时' }}</span>
        </div>
        <div class="top-list">
          <div v-for="(d, i) in topDomains.slice(0, 8)" :key="d.domain" class="top-row">
            <span class="rank" :class="{ hot: i < 3 }">{{ i + 1 }}</span>
            <span class="top-domain">{{ d.domain }}</span>
            <span class="top-bar">
              <i :style="{ width: `${Math.min(100, (d.requests / maxDomain) * 100)}%` }" />
            </span>
            <span class="top-num">{{ formatNumber(d.requests) }}</span>
          </div>
          <div v-if="!topDomains.length" class="wall-empty">暂无数据</div>
        </div>
      </div>
    </div>

    <div class="wall-grid lower">
      <div class="wall-card">
        <div class="wall-card-head"><span>节点状态</span></div>
        <div class="node-grid-monitor">
          <div v-for="n in nodes.slice(0, 12)" :key="n.id" class="node-pill">
            <span class="status-dot" :class="n.status === 'online' ? 'ok' : 'off'" />
            <span class="truncate">{{ n.name }}</span>
            <span class="node-region">{{ n.region || '—' }}</span>
            <span class="node-load">{{ n.cpu_usage != null ? `${n.cpu_usage.toFixed(0)}%` : '—' }}</span>
          </div>
          <div v-if="!nodes.length" class="wall-empty">暂无节点</div>
        </div>
      </div>
      <div class="wall-card">
        <div class="wall-card-head"><span>源站健康</span></div>
        <div class="health-list">
          <div v-for="h in health.slice(0, 8)" :key="h.domain_name + h.origin_url" class="health-row">
            <span class="status-dot" :class="h.healthy ? 'ok' : 'off'" />
            <span class="truncate">{{ h.domain_name }}</span>
            <span class="health-latency">{{ h.latency_ms }} ms</span>
          </div>
          <div v-if="!health.length" class="wall-empty">暂无数据</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
definePageMeta({ layout: 'monitor' })

const api = useApi()

const series = ref<any[]>([])
const previousSeries = ref<any[]>([])
const byDomain = ref<any[]>([])
const realtime = ref<any>({
  enabled: false,
  minutes: 5,
  requests: 0,
  cache_hits: 0,
  cache_misses: 0,
  bytes_sent: 0,
  hit_ratio: 0,
  domain_count: 0,
  domains: [],
})
const nodes = ref<any[]>([])
const health = ref<any[]>([])
const updatedAt = ref('')
const isFull = ref(false)
let timer: ReturnType<typeof setInterval> | null = null

const hourStats = computed(() => totals(series.value))
const onlineNodes = computed(() => nodes.value.filter((n) => n.status === 'online').length)
const topIsLive = computed(() => realtime.value.enabled && realtime.value.domains.length > 0)
const topDomains = computed(() =>
  topIsLive.value ? realtime.value.domains : byDomain.value,
)
const live = computed(() =>
  realtime.value.enabled
    ? {
        requests: realtime.value.requests,
        hit_ratio: realtime.value.hit_ratio,
        bytes: realtime.value.bytes_sent,
        domain_count: realtime.value.domain_count ?? realtime.value.domains.length,
      }
    : {
        requests: hourStats.value.requests,
        hit_ratio: hourStats.value.hit_ratio,
        bytes: hourStats.value.bytes,
        domain_count: byDomain.value.length,
      },
)
const maxDomain = computed(() => Math.max(1, ...topDomains.value.map((d) => d.requests || 0)))

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

async function load() {
  const [rt, ts, bd, endpoints, hs] = await Promise.all([
    api.get<any>('/api/v1/stats/realtime?minutes=5').catch(() => null),
    api.get<any>('/api/v1/stats/timeseries?hours=1&bucket=60&compare=true').catch(() => null),
    api.get<any[]>('/api/v1/stats/by-domain?hours=1').catch(() => []),
    api.get<any>('/api/v1/edge-endpoints').catch(() => null),
    api.get<any[]>('/api/v1/origin-health').catch(() => []),
  ])
  if (rt) realtime.value = rt
  series.value = ts?.current || []
  previousSeries.value = ts?.previous || []
  byDomain.value = bd || []
  nodes.value = endpoints?.nodes || []
  health.value = hs || []
  updatedAt.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
}

function fullscreen() {
  if (!import.meta.client) return
  if (!document.fullscreenElement) {
    document.documentElement.requestFullscreen?.().then(() => {
      isFull.value = true
    })
  } else {
    document.exitFullscreen?.().then(() => {
      isFull.value = false
    })
  }
}

onMounted(() => {
  load()
  timer = setInterval(load, 10_000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.monitor-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.monitor-actions {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
}

.monitor-title {
  font-size: 26px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.monitor-sub {
  margin-top: 4px;
  font-size: 12px;
  color: #7f92ad;
}

.live-badge {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 6px 10px;
  border: 1px solid rgba(61, 220, 132, 0.28);
  border-radius: 999px;
  background: rgba(61, 220, 132, 0.08);
  color: #7ef0b0;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.08em;
}

.live-badge i {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #3ddc84;
  box-shadow: 0 0 8px rgba(61, 220, 132, 0.7);
  animation: live-pulse 1.8s ease-in-out infinite;
}

@keyframes live-pulse {
  50% {
    opacity: 0.35;
  }
}

.monitor-select {
  background: #101722;
  border-color: #243044;
  color: #dbe6f5;
}

.wall-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}

.wall-card {
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  background: linear-gradient(180deg, rgba(20, 29, 42, 0.92), rgba(12, 17, 25, 0.9));
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  padding: 16px;
  min-width: 0;
}

.wall-label {
  font-size: 12px;
  color: #7f92ad;
  letter-spacing: 0.08em;
}

.wall-value {
  margin-top: 8px;
  font-size: 34px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  color: #f0f5ff;
}

.wall-value.accent {
  color: #3ddc84;
}

.wall-value.accent2 {
  color: #4b9bff;
}

.wall-hint {
  margin-top: 4px;
  font-size: 12px;
  color: #6f819c;
}

.wall-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.8fr) minmax(280px, 1fr);
  gap: 14px;
}

.wall-grid.lower {
  grid-template-columns: 1.4fr 1fr;
}

.wall-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
  font-size: 13px;
  font-weight: 500;
  color: #b8c7dd;
}

.wall-legend {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  color: #6f819c;
  font-weight: 400;
}

.wall-legend i {
  width: 14px;
  height: 2px;
  background: #4b9bff;
  display: inline-block;
}

.wall-legend i.prev {
  background: #55657a;
}

.chart-card {
  min-height: 380px;
}

.top-list,
.health-list,
.node-grid-monitor {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.top-row,
.health-row,
.node-pill {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
  font-size: 12px;
  color: #a9bad2;
}

.rank {
  width: 18px;
  height: 18px;
  border-radius: 4px;
  background: #182233;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  color: #7588a3;
  flex: none;
}

.rank.hot {
  background: rgba(75, 155, 255, 0.18);
  color: #6fb0ff;
}

.top-domain {
  width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: #dbe6f5;
}

.top-bar {
  flex: 1;
  height: 5px;
  border-radius: 3px;
  background: #172131;
  overflow: hidden;
}

.top-bar i {
  display: block;
  height: 100%;
  background: linear-gradient(90deg, #1677ff, #52c4ff);
  border-radius: 3px;
}

.top-num {
  width: 60px;
  text-align: right;
  font-variant-numeric: tabular-nums;
  color: #9fb2cc;
}

.node-grid-monitor {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
}

.node-pill {
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 7px;
  padding: 8px 10px;
  background: rgba(255, 255, 255, 0.02);
}

.node-region {
  margin-left: auto;
  color: #64778f;
  font-size: 11px;
}

.node-load {
  width: 34px;
  text-align: right;
  color: #7f92ad;
  font-size: 11px;
}

.health-latency {
  margin-left: auto;
  font-family: var(--mono);
  color: #7f92ad;
}

.status-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex: none;
}

.status-dot.ok {
  background: #3ddc84;
  box-shadow: 0 0 8px rgba(61, 220, 132, 0.5);
}

.status-dot.off {
  background: #ff6b6b;
  box-shadow: 0 0 8px rgba(255, 107, 107, 0.4);
}

.wall-empty {
  color: #5d7089;
  font-size: 12px;
  padding: 20px 0;
}

@media (max-width: 1100px) {
  .wall-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .wall-grid,
  .wall-grid.lower {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 600px) {
  .monitor-actions {
    flex-direction: column;
    align-items: flex-start;
  }
  .wall-value {
    font-size: 26px;
  }
  .top-domain {
    width: 120px;
  }
}
</style>
