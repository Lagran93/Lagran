<template>
  <div>
    <div class="grid grid-4" style="margin-bottom:1.5rem;">
      <div class="card">
        <div class="stat-value">{{ stats.total_requests?.toLocaleString?.() ?? stats.total_requests }}</div>
        <div class="stat-label">请求数（24h）</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ ((stats.hit_ratio || 0) * 100).toFixed(1) }}%</div>
        <div class="stat-label">命中率</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ stats.online_nodes }}</div>
        <div class="stat-label">在线节点</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ stats.domain_count }}</div>
        <div class="stat-label">域名数</div>
      </div>
    </div>

    <div class="card" style="margin-bottom:1.25rem;">
      <h3 style="margin-top:0;">分域名流量（24h）</h3>
      <table>
        <thead>
          <tr><th>域名</th><th>请求</th><th>命中</th><th>未命中</th><th>命中率</th><th>流量</th></tr>
        </thead>
        <tbody>
          <tr v-for="d in byDomain" :key="d.domain">
            <td>{{ d.domain }}</td>
            <td>{{ d.requests }}</td>
            <td>{{ d.cache_hits }}</td>
            <td>{{ d.cache_misses }}</td>
            <td>{{ ((d.hit_ratio||0)*100).toFixed(1) }}%</td>
            <td>{{ d.bytes_sent }}</td>
          </tr>
          <tr v-if="!byDomain.length">
            <td colspan="6" class="empty">暂无数据</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin-top:0;">源站健康</h3>
      <table>
        <thead>
          <tr>
            <th>域名</th>
            <th>源站</th>
            <th>状态</th>
            <th>延迟</th>
            <th>连续失败</th>
            <th>最近检查</th>
            <th>错误</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="h in health" :key="h.domain_name">
            <td>{{ h.domain_name }}</td>
            <td class="muted">{{ h.origin_url }}</td>
            <td>
              <span :class="['badge', h.healthy ? 'ok' : 'bad']">
                {{ h.healthy ? '健康' : '异常' }}
              </span>
            </td>
            <td>{{ h.latency_ms }} ms</td>
            <td>{{ h.consecutive_fails }}</td>
            <td class="muted">{{ h.last_check_at?.slice(0, 19).replace('T', ' ') || '—' }}</td>
            <td class="muted">{{ h.last_error || '—' }}</td>
          </tr>
          <tr v-if="!health.length">
            <td colspan="7" class="empty">暂无探测数据（边缘节点启动后约 30s 上报）</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const stats = ref<any>({
  total_requests: 0,
  hit_ratio: 0,
  online_nodes: 0,
  domain_count: 0,
})
const health = ref<any[]>([])
const byDomain = ref<any[]>([])

onMounted(async () => {
  try {
    const [s, h, bd] = await Promise.all([
      api.get('/api/v1/stats/summary').catch(() => null),
      api.get('/api/v1/origin-health').catch(() => []),
      api.get('/api/v1/stats/by-domain').catch(() => []),
    ])
    if (s) stats.value = s
    health.value = h || []
    byDomain.value = bd || []
  } catch {}
})
</script>

<style scoped>
.badge { padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.8rem; }
.badge.ok { background: rgba(34,197,94,.2); color: #4ade80; }
.badge.bad { background: rgba(248,113,113,.2); color: #f87171; }
.stat-value { font-size: 1.5rem; font-weight: 650; }
.stat-label { color: #94a3b8; font-size: 0.85rem; margin-top: 0.25rem; }
</style>
