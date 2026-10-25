<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">边缘节点</div>
        <div class="page-desc">查看边缘节点的心跳与区域分布，节点启动后会自动注册</div>
      </div>
      <div class="page-actions">
        <label class="switch" :class="{ on: autoRefresh }">
          <span class="switch-track" />
          <input v-model="autoRefresh" type="checkbox" style="display: none" />
          自动刷新
        </label>
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
      </div>
    </div>

    <div class="stat-grid">
      <StatCard label="节点总数" :value="nodes.length" icon="node" />
      <StatCard label="在线节点" :value="online" icon="activity" tone="green" />
      <StatCard label="离线节点" :value="nodes.length - online" icon="alert" tone="orange" />
      <StatCard
        label="平均心跳间隔"
        :value="'15 秒'"
        hint="可在边缘端用 HEARTBEAT_INTERVAL 调整"
        icon="clock"
      />
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">节点列表</div>
          <div class="card-desc">最后心跳超过 60 秒的节点会被标记为离线</div>
        </div>
        <div class="card-extra text-muted" style="font-size: 12px">
          {{ lastUpdated ? `更新于 ${lastUpdated}` : '' }}
        </div>
      </div>

      <div v-if="nodes.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>节点名称</th>
              <th>区域</th>
              <th>状态</th>
              <th>Agent 地址</th>
              <th>最后心跳</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="n in nodes" :key="n.id">
              <td>
                <div class="cell-main">{{ n.name }}</div>
                <div class="cell-sub mono">{{ n.id.slice(0, 8) }}</div>
              </td>
              <td>{{ n.region || '默认区域' }}</td>
              <td>
                <StatusTag :status="n.status" dot>
                  {{ n.status === 'online' ? '在线' : '离线' }}
                </StatusTag>
              </td>
              <td>
                <span class="mono text-2">{{ n.agent_url || '—' }}</span>
              </td>
              <td>
                <div>{{ fromNow(n.last_heartbeat) }}</div>
                <div class="cell-sub">{{ formatDateTime(n.last_heartbeat) }}</div>
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
        icon="node"
        title="还没有边缘节点"
        text="在服务器上启动 lagran-edge 并配置 CONTROL_URL、NODE_ID 与 AGENT_URL 后，节点会自动出现在这里。"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()

const nodes = ref<any[]>([])
const loading = ref(false)
const autoRefresh = ref(true)
const lastUpdated = ref('')

const online = computed(() => nodes.value.filter(n => n.status === 'online').length)

let timer: ReturnType<typeof setInterval> | null = null

async function load() {
  loading.value = true
  try {
    nodes.value = (await api.get<any[]>('/api/v1/nodes')) || []
    lastUpdated.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  } catch (e: any) {
    nodes.value = []
  } finally {
    loading.value = false
  }
}

watch(autoRefresh, (on) => {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
  if (on) timer = setInterval(load, 10000)
})

onMounted(() => {
  load()
  if (autoRefresh.value) timer = setInterval(load, 10000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>
