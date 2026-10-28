<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">访问日志</div>
        <div class="page-desc">边缘节点批量上报的访客请求明细，默认展示最近 200 条</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" @click="exportLogs">
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
      <div class="filter-bar">
        <input
          v-model="host"
          class="input"
          placeholder="按域名筛选，如 cdn.example.com"
          style="min-width: 240px"
          @keyup.enter="load"
        />
        <select v-model="statusClass" class="select">
          <option value="">全部状态码</option>
          <option value="2xx">2xx 成功</option>
          <option value="3xx">3xx 跳转</option>
          <option value="4xx">4xx 客户端错误</option>
          <option value="5xx">5xx 服务端错误</option>
        </select>
        <select v-model.number="limit" class="select">
          <option :value="100">最近 100 条</option>
          <option :value="200">最近 200 条</option>
          <option :value="500">最近 500 条</option>
        </select>
        <button class="btn btn-default" type="button" @click="load">查询</button>
        <span class="spacer" />
        <span class="text-muted" style="font-size: 13px">{{ filtered.length }} 条记录</span>
      </div>

      <div v-if="filtered.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>时间</th>
              <th>节点</th>
              <th>客户端 IP</th>
              <th>方法</th>
              <th>域名</th>
              <th style="min-width: 220px">路径</th>
              <th>状态</th>
              <th>缓存</th>
              <th class="num">大小</th>
              <th class="num">耗时</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in paged" :key="r.id">
              <td class="text-muted nowrap">{{ formatDateTime(r.ts) }}</td>
              <td class="text-2">{{ r.node_id }}</td>
              <td class="mono">{{ r.client_ip }}</td>
              <td>
                <span class="method" :class="r.method?.toLowerCase()">{{ r.method }}</span>
              </td>
              <td class="text-2">{{ r.host }}</td>
              <td>
                <div class="mono path-cell" :title="r.path">{{ r.path }}</div>
              </td>
              <td>
                <StatusTag :tone="statusTone(r.status)">{{ r.status }}</StatusTag>
              </td>
              <td>
                <StatusTag :status="r.cache_status">{{ r.cache_status }}</StatusTag>
              </td>
              <td class="num text-2">{{ formatBytes(r.bytes) }}</td>
              <td class="num" :class="r.latency_ms > 1000 ? 'text-danger' : 'text-2'">
                {{ r.latency_ms }} ms
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="loading" class="card-body">
        <div class="skeleton" style="height: 34px; width: 100%" />
      </div>

      <EmptyState
        v-else
        icon="logs"
        title="暂无访问日志"
        text="边缘端开启 ACCESS_LOG_REPORT=true 后，约 30 秒上报一次批量日志。"
      />

      <div v-if="filtered.length > pageSize" class="table-footer">
        <AppPagination v-model:page="page" :total="filtered.length" :page-size="pageSize" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()

const rows = ref<any[]>([])
const host = ref('')
const statusClass = ref('')
const limit = ref(200)
const loading = ref(false)
const page = ref(1)
const pageSize = 20

const filtered = computed(() => {
  return rows.value.filter((r) => {
    if (!statusClass.value) return true
    const bucket = `${Math.floor(Number(r.status) / 100)}xx`
    return bucket === statusClass.value
  })
})

const paged = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

function exportLogs() {
  exportCsv(`lagran-access-${new Date().toISOString().slice(0, 10)}`, filtered.value, [
    { key: 'ts', label: '时间' },
    { key: 'host', label: '域名' },
    { key: 'method', label: '方法' },
    { key: 'path', label: '路径' },
    { key: 'status', label: '状态码' },
    { key: 'cache_status', label: '缓存状态' },
    { key: 'bytes_sent', label: '响应字节' },
    { key: 'latency_ms', label: '耗时 ms' },
    { key: 'client_ip', label: '客户端 IP' },
    { key: 'user_agent', label: 'User-Agent' },
  ])
}

watch([statusClass, limit], () => {
  page.value = 1
})

function statusTone(status: number) {
  if (status >= 500) return 'danger'
  if (status >= 400) return 'warning'
  if (status >= 300) return 'info'
  return 'success'
}

async function load() {
  loading.value = true
  page.value = 1
  try {
    const q = host.value.trim()
      ? `?host=${encodeURIComponent(host.value.trim())}&limit=${limit.value}`
      : `?limit=${limit.value}`
    rows.value = (await api.get<any[]>(`/api/v1/access-logs${q}`)) || []
  } catch {
    rows.value = []
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.method {
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 3px;
  background: #f2f3f5;
  color: var(--text-2);
}

.method.get {
  background: var(--brand-bg);
  color: var(--brand);
}

.method.post {
  background: var(--success-bg);
  color: var(--success);
}

.method.delete {
  background: var(--danger-bg);
  color: var(--danger);
}

.method.put,
.method.patch {
  background: var(--warning-bg);
  color: var(--warning);
}

.path-cell {
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--text-2);
}
</style>
