<template>
  <div>
    <p class="muted" style="margin:0 0 1.25rem;">请求量、带宽与缓存命中统计</p>
    <div class="grid grid-4" style="margin-bottom:1.5rem;">
      <div class="card">
        <div class="stat-value">{{ stats.total_requests }}</div>
        <div class="stat-label">总请求</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ stats.cache_hits }}</div>
        <div class="stat-label">缓存命中</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ stats.cache_misses }}</div>
        <div class="stat-label">缓存未命中</div>
      </div>
      <div class="card">
        <div class="stat-value">{{ formatBytes(stats.bytes_sent) }}</div>
        <div class="stat-label">出站流量</div>
      </div>
    </div>
    <div class="card">
      <p class="muted">图表与按域名/节点下钻将在后续版本提供。</p>
    </div>
  </div>
</template>

<script setup lang="ts">
const config = useRuntimeConfig()
const apiBase = config.public.apiBase as string

const stats = ref({
  total_requests: 0,
  cache_hits: 0,
  cache_misses: 0,
  bytes_sent: 0,
  hit_ratio: 0,
})

function formatBytes(n: number) {
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1024 / 1024).toFixed(1) + ' MB'
}

onMounted(async () => {
  try {
    stats.value = (await $fetch(`${apiBase}/api/v1/stats/summary`)) as any
  } catch {}
})
</script>
