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
        <input v-model="host" class="input" placeholder="按域名筛选，如 cdn.example.com" style="min-width: 240px"
          @keyup.enter="load" />
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
        <table class="table table-fixed log-table">
          <colgroup>
            <col style="width: var(--col-time)" />
            <col style="width: var(--col-node)" />
            <col style="width: var(--col-ip)" />
            <col style="width: var(--col-method)" />
            <col style="width: var(--col-host)" />
            <col />
            <col style="width: var(--col-ua)" />
            <col style="width: var(--col-status)" />
            <col style="width: var(--col-cache)" />
            <col style="width: var(--col-action)" />
            <col style="width: var(--col-size)" />
            <col style="width: var(--col-latency)" />
          </colgroup>
          <thead>
            <tr>
              <th>时间</th>
              <th>节点</th>
              <th>客户端 IP</th>
              <th>方法</th>
              <th>域名</th>
              <th style="min-width: 220px">路径</th>
              <th>User-Agent</th>
              <th>状态</th>
              <th>缓存</th>
              <th>动作</th>
              <th class="num">大小</th>
              <th class="num">耗时</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in paged" :key="r.id">
              <td class="time-cell text-muted nowrap">{{ formatDateTime(r.ts) }}</td>
              <td class="text-2">
                <span class="cell-ellipsis" :title="r.node_id || '—'">{{ r.node_id || '—' }}</span>
              </td>
              <td class="mono">
                <span class="cell-ellipsis" :title="r.client_ip || '—'">{{ r.client_ip || '—' }}</span>
              </td>
              <td>
                <span class="method" :class="r.method?.toLowerCase()">{{ r.method }}</span>
              </td>
              <td class="text-2">
                <span class="cell-ellipsis" :title="r.host || '—'">{{ r.host || '—' }}</span>
              </td>
              <td>
                <span class="mono cell-ellipsis" :title="r.path">{{ r.path }}</span>
              </td>
              <td class="ua-cell text-2">
                <span class="cell-ellipsis" :title="r.user_agent || '—'">{{ r.user_agent || '—' }}</span>
              </td>
              <td>
                <StatusTag :tone="statusTone(r.status)">{{ r.status }}</StatusTag>
              </td>
              <td>
                <StatusTag :status="r.cache_status">{{ r.cache_status }}</StatusTag>
              </td>
              <td>
                <span v-if="r.action" class="text-2 cell-ellipsis" :title="r.action">{{ r.action }}</span>
                <span v-else class="text-muted">—</span>
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

      <EmptyState v-else icon="logs" title="暂无访问日志" text="边缘端开启 ACCESS_LOG_REPORT=true 后，约 30 秒上报一次批量日志。" />

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

const filtered = computed(() => rows.value)

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
    { key: 'action', label: '动作' },
    { key: 'bytes_sent', label: '响应字节' },
    { key: 'latency_ms', label: '耗时 ms' },
    { key: 'client_ip', label: '客户端 IP' },
    { key: 'user_agent', label: 'User-Agent' },
  ])
}

watch([statusClass, limit], () => {
  page.value = 1
  load()
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
    const q = new URLSearchParams()
    const hostValue = host.value.trim()
    if (hostValue) q.set('host', hostValue)
    if (statusClass.value) q.set('status_class', statusClass.value)
    q.set('limit', String(limit.value))
    rows.value = (await api.get<any[]>(`/api/v1/access-logs?${q.toString()}`)) || []
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

/* Width presets are defined on the table so scoped col selectors below
   inherit the same custom properties. */
.log-table {
  --col-time: 160px;
  --col-node: 105px;
  --col-ip: 125px;
  --col-method: 68px;
  --col-host: 150px;
  --col-ua: 180px;
  --col-status: 68px;
  --col-cache: 78px;
  --col-action: 88px;
  --col-size: 78px;
  --col-latency: 78px;
  min-width: 1400px;
}


@media (min-width: 1920px) {
  .log-table {
    --col-time: 170px;
    --col-node: 125px;
    --col-ip: 145px;
    --col-method: 72px;
    --col-host: 190px;
    --col-ua: 300px;
    --col-status: 72px;
    --col-cache: 88px;
    --col-action: 105px;
    --col-size: 88px;
    --col-latency: 88px;
  }
}

@media (min-width: 2560px) {
  .log-table {
    --col-time: 220px;
    --col-node: 180px;
    --col-ip: 200px;
    --col-method: 90px;
    --col-host: 260px;
    --col-ua: 500px;
    --col-status: 90px;
    --col-cache: 110px;
    --col-action: 140px;
    --col-size: 110px;
    --col-latency: 110px;
  }

  .log-table th,
  .log-table td {
    padding-left: 18px;
    padding-right: 18px;
  }

  .log-table .cell-ellipsis {
    font-size: 14.5px;
  }
}

@media (min-width: 3200px) {
  .log-table {
    --col-time: 240px;
    --col-node: 200px;
    --col-ip: 220px;
    --col-method: 96px;
    --col-host: 300px;
    --col-ua: 500px;
    --col-status: 96px;
    --col-cache: 120px;
    --col-action: 160px;
    --col-size: 120px;
    --col-latency: 120px;
  }
}

.log-table th,
.log-table td {
  overflow: hidden;
}

.log-table td .cell-ellipsis {
  color: var(--text-2);
}

.log-table .method {
  display: inline-flex;
  max-width: 100%;
}

/* ---------------------------------------------------------------
   List typography
   --------------------------------------------------------------- */

.log-table {
  font-size: 13px;
}

.log-table th {
  padding: 10px 14px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.055em;
  text-transform: uppercase;
  color: var(--text-3);
}

.log-table td {
  padding: 11px 14px;
  font-size: 13px;
  line-height: 1.5;
}

.log-table .cell-ellipsis {
  font-size: 13px;
  line-height: 1.5;
}

.log-table .time-cell {
  font-size: 12.5px;
  font-variant-numeric: tabular-nums;
  color: var(--text-3);
}

.log-table td.mono,
.log-table .mono.cell-ellipsis {
  font-size: 12.5px;
  letter-spacing: -0.01em;
}

.log-table .num {
  font-size: 12.5px;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  color: var(--text-2);
}

.log-table .method {
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.045em;
  padding: 1px 6px;
}

.log-table .ua-cell .cell-ellipsis {
  font-size: 12.5px;
  color: var(--text-3);
}

@media (min-width: 2560px) {
  .log-table {
    font-size: 14px;
  }

  .log-table th {
    font-size: 11.5px;
    letter-spacing: 0.06em;
  }

  .log-table th,
  .log-table td {
    padding: 12px 18px;
  }

  .log-table td,
  .log-table .cell-ellipsis {
    font-size: 14px;
  }

  .log-table .time-cell,
  .log-table td.mono,
  .log-table .mono.cell-ellipsis,
  .log-table .num,
  .log-table .ua-cell .cell-ellipsis {
    font-size: 13px;
  }
}
</style>
