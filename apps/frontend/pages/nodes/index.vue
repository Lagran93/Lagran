<template>
  <div>
    <p class="muted" style="margin:0 0 1.25rem;">边缘节点状态与心跳（由边缘端自动上报）</p>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>区域</th>
            <th>状态</th>
            <th>Agent URL</th>
            <th>最后心跳</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="n in nodes" :key="n.id">
            <td>{{ n.name }}</td>
            <td>{{ n.region }}</td>
            <td>
              <span :class="['badge', n.status === 'online' ? 'ok' : '']">{{ n.status }}</span>
            </td>
            <td class="muted">{{ n.agent_url || '—' }}</td>
            <td class="muted">{{ n.last_heartbeat || '—' }}</td>
          </tr>
          <tr v-if="!nodes.length">
            <td colspan="5" class="empty">暂无节点。启动边缘端后将自动出现。</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const nodes = ref<any[]>([])

async function load() {
  try {
    nodes.value = await api.get('/api/v1/nodes')
  } catch {
    nodes.value = []
  }
}

onMounted(() => {
  load()
  const t = setInterval(load, 10000)
  onUnmounted(() => clearInterval(t))
})
</script>

<style scoped>
.badge {
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  background: #334155;
  font-size: 0.8rem;
}
.badge.ok {
  background: rgba(34, 197, 94, 0.2);
  color: #4ade80;
}
</style>
