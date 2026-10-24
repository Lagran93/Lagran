<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;gap:1rem;flex-wrap:wrap;">
      <p class="muted" style="margin:0;">访客访问日志（边缘上报汇总）</p>
      <div style="display:flex;gap:0.5rem;align-items:center;">
        <input v-model="host" placeholder="按域名筛选" style="width:180px;" />
        <button class="btn" @click="load">刷新</button>
      </div>
    </div>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>节点</th>
            <th>客户端 IP</th>
            <th>方法</th>
            <th>域名</th>
            <th>路径</th>
            <th>状态</th>
            <th>缓存</th>
            <th>字节</th>
            <th>耗时</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rows" :key="r.id">
            <td class="muted">{{ r.ts?.slice(0, 19).replace('T', ' ') }}</td>
            <td>{{ r.node_id }}</td>
            <td>{{ r.client_ip }}</td>
            <td>{{ r.method }}</td>
            <td>{{ r.host }}</td>
            <td class="path">{{ r.path }}</td>
            <td><span :class="['badge', statusClass(r.status)]">{{ r.status }}</span></td>
            <td>{{ r.cache_status }}</td>
            <td>{{ r.bytes }}</td>
            <td>{{ r.latency_ms }}ms</td>
          </tr>
          <tr v-if="!rows.length">
            <td colspan="10" class="empty">暂无日志（边缘 ACCESS_LOG_REPORT=true 时约 30s 上报一次）</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const rows = ref<any[]>([])
const host = ref('')

async function load() {
  try {
    const q = host.value.trim()
      ? `?host=${encodeURIComponent(host.value.trim())}&limit=200`
      : '?limit=200'
    rows.value = await api.get(`/api/v1/access-logs${q}`)
  } catch {
    rows.value = []
  }
}

function statusClass(s: number) {
  if (s >= 500) return 'err'
  if (s >= 400) return 'warn'
  if (s >= 300) return 'redir'
  return 'ok'
}

onMounted(load)
</script>

<style scoped>
input {
  padding: 0.4rem 0.6rem; border: 1px solid #334155; border-radius: 6px;
  background: #0f172a; color: #e2e8f0;
}
.path { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.badge { padding: 0.1rem 0.4rem; border-radius: 999px; font-size: 0.75rem; }
.badge.ok { background: rgba(34,197,94,.2); color: #4ade80; }
.badge.warn { background: rgba(251,191,36,.2); color: #fbbf24; }
.badge.err { background: rgba(248,113,113,.2); color: #f87171; }
.badge.redir { background: rgba(56,189,248,.2); color: #38bdf8; }
</style>
