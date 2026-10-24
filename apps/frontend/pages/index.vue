<template>
  <div>
    <div class="grid grid-4" style="margin-bottom: 1.5rem;">
      <div class="card">
        <div class="stat-value">{{ stats.domain_count ?? domains.length }}</div>
        <div class="stat-label">域名数量</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ stats.online_nodes ?? nodes.length }}</div>
        <div class="stat-label">在线节点</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ stats.total_requests.toLocaleString() }}</div>
        <div class="stat-label">总请求数</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ (stats.hit_ratio * 100).toFixed(1) }}%</div>
        <div class="stat-label">缓存命中率</div>
      </div>
    </div>

    <div class="card">
      <h3 style="margin: 0 0 1rem;">最近域名</h3>
      <table>
        <thead>
          <tr>
            <th>域名</th>
            <th>源站</th>
            <th>状态</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in domains" :key="d.id">
            <td>{{ d.name }}</td>
            <td class="muted">{{ d.origin_proto }}://{{ d.origin_host }}:{{ d.origin_port }}</td>
            <td><span class="badge">{{ d.status }}</span></td>
          </tr>
          <tr v-if="!domains.length">
            <td colspan="3" class="empty">暂无数据</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()

const stats = ref({
  total_requests: 0,
  cache_hits: 0,
  cache_misses: 0,
  bytes_sent: 0,
  hit_ratio: 0,
  domain_count: 0,
  online_nodes: 0,
})
const domains = ref<any[]>([])
const nodes = ref<any[]>([])

onMounted(async () => {
  try {
    const [s, d, n] = await Promise.all([
      api.get<any>('/api/v1/stats/summary').catch(() => null),
      api.get<any[]>('/api/v1/domains').catch(() => []),
      api.get<any[]>('/api/v1/nodes').catch(() => []),
    ])
    if (s) stats.value = { ...stats.value, ...s }
    domains.value = d || []
    nodes.value = n || []
  } catch (e) {
    console.warn('API error', e)
  }
})
</script>

<style scoped>
.badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  background: rgba(56, 189, 248, 0.15);
  color: #38bdf8;
  font-size: 0.8rem;
}
</style>
