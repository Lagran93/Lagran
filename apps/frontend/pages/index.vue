<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">仪表盘</div>
        <div class="page-desc">查看加速业务概览、缓存效果与边缘节点状态</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <NuxtLink to="/domains" class="btn btn-primary">
          <AppIcon name="plus" :size="15" />
          接入域名
        </NuxtLink>
      </div>
    </div>

    <div class="stat-grid">
      <StatCard
        label="总请求数（近 24 小时）"
        :value="formatNumber(stats.total_requests)"
        :hint="`缓存命中 ${formatNumber(stats.cache_hits)} 次`"
        icon="activity"
      />
      <StatCard
        label="缓存命中率"
        :value="percent(stats.hit_ratio)"
        :hint="`未命中 ${formatNumber(stats.cache_misses)} 次`"
        icon="zap"
        tone="green"
      />
      <StatCard
        label="加速域名"
        :value="formatNumber(stats.domain_count ?? domains.length)"
        hint="已接入并生效的域名"
        icon="domain"
      />
      <StatCard
        v-if="auth.isAdmin"
        label="在线边缘节点"
        :value="formatNumber(stats.online_nodes)"
        :hint="`共 ${formatNumber(nodes.length)} 个节点`"
        icon="node"
        tone="orange"
      />
      <StatCard
        v-else
        label="我的项目"
        :value="formatNumber(projects.length)"
        hint="当前账号可见的项目空间"
        icon="project"
        tone="orange"
      />
    </div>

    <div class="grid grid-main-side">
      <div>
        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">最近接入的域名</div>
              <div class="card-desc">按接入时间倒序展示</div>
            </div>
            <div class="card-extra">
              <NuxtLink to="/domains" class="link-btn">全部域名</NuxtLink>
            </div>
          </div>
          <div v-if="domains.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>域名</th>
                  <th>源站</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="d in domains.slice(0, 6)" :key="d.id">
                  <td>
                    <NuxtLink :to="`/domains/${d.id}`" class="cell-main">{{ d.name }}</NuxtLink>
                    <div class="cell-sub">限流 {{ d.rate_limit_rps || '不限' }} QPS</div>
                  </td>
                  <td class="mono text-2">
                    {{ d.origin_proto }}://{{ d.origin_host }}:{{ d.origin_port }}
                  </td>
                  <td>
                    <StatusTag :status="d.status" dot>
                      {{ d.status === 'active' ? '已启用' : '已停用' }}
                    </StatusTag>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState
            v-else
            icon="domain"
            title="还没有接入域名"
            text="接入域名并配置源站后，边缘节点会自动同步配置并开始加速。"
          >
            <NuxtLink to="/domains" class="btn btn-primary btn-sm">立即接入</NuxtLink>
          </EmptyState>
        </div>

        <div class="card">
          <div class="card-head">
            <div>
              <div class="card-title">源站健康</div>
              <div class="card-desc">边缘节点每 30 秒探测一次源站可用性</div>
            </div>
            <div class="card-extra">
              <NuxtLink to="/stats" class="link-btn">查看统计</NuxtLink>
            </div>
          </div>
          <div v-if="health.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>域名</th>
                  <th>状态</th>
                  <th>延迟</th>
                  <th>最近检查</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="h in health.slice(0, 5)" :key="h.domain_name">
                  <td>
                    <div class="cell-main">{{ h.domain_name }}</div>
                    <div class="cell-sub mono">{{ h.origin_url }}</div>
                  </td>
                  <td>
                    <StatusTag :tone="h.healthy ? 'success' : 'danger'" dot>
                      {{ h.healthy ? '健康' : '异常' }}
                    </StatusTag>
                  </td>
                  <td class="num">{{ h.latency_ms }} ms</td>
                  <td class="text-muted">{{ fromNow(h.last_check_at) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState
            v-else
            icon="shield"
            title="暂无源站探测数据"
            text="边缘节点启动并同步到域名后，约 30 秒内会上报源站健康状态。"
          />
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-head">
            <div class="card-title">快捷操作</div>
          </div>
          <div class="card-body quick-grid">
            <NuxtLink to="/domains" class="quick-item">
              <span class="quick-icon"><AppIcon name="plus" :size="18" /></span>
              <span>
                <strong>接入域名</strong>
                <small>配置源站并开启加速</small>
              </span>
            </NuxtLink>
            <NuxtLink to="/rules" class="quick-item">
              <span class="quick-icon"><AppIcon name="rules" :size="18" /></span>
              <span>
                <strong>缓存规则</strong>
                <small>按路径设置 TTL / SWR</small>
              </span>
            </NuxtLink>
            <NuxtLink to="/purge" class="quick-item">
              <span class="quick-icon"><AppIcon name="purge" :size="18" /></span>
              <span>
                <strong>刷新缓存</strong>
                <small>按 URL 或目录下发刷新</small>
              </span>
            </NuxtLink>
            <NuxtLink to="/certs" class="quick-item">
              <span class="quick-icon"><AppIcon name="cert" :size="18" /></span>
              <span>
                <strong>证书管理</strong>
                <small>上传或自动签发证书</small>
              </span>
            </NuxtLink>
          </div>
        </div>

        <div v-if="auth.isAdmin" class="card">
          <div class="card-head">
            <div class="card-title">边缘节点</div>
            <div class="card-extra">
              <NuxtLink to="/nodes" class="link-btn">管理</NuxtLink>
            </div>
          </div>
          <div class="card-body">
            <div class="node-summary">
              <div>
                <div class="stat-label">在线</div>
                <div class="node-num text-success">{{ onlineNodes }}</div>
              </div>
              <div>
                <div class="stat-label">离线</div>
                <div class="node-num text-muted">{{ offlineNodes }}</div>
              </div>
              <div>
                <div class="stat-label">总数</div>
                <div class="node-num">{{ nodes.length }}</div>
              </div>
            </div>
            <div v-if="nodes.length" class="node-list">
              <div v-for="n in nodes.slice(0, 3)" :key="n.id" class="node-row">
                <span class="dot" :class="n.status === 'online' ? 'text-success' : 'text-muted'" />
                <span class="flex-1 truncate">{{ n.name }}</span>
                <span class="text-muted" style="font-size: 12px">{{ n.region || '默认区域' }}</span>
              </div>
            </div>
            <p v-else class="text-muted mt-12" style="font-size: 13px">
              尚未注册节点，启动边缘端后会自动出现在这里。
            </p>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <div class="card-title">接入提示</div>
          </div>
          <div class="card-body tips">
            <div class="tip-row">
              <span class="tip-index">1</span>
              <span>在「域名管理」接入域名，填写源站地址与端口。</span>
            </div>
            <div class="tip-row">
              <span class="tip-index">2</span>
              <span>把域名 CNAME 到边缘节点 IP，等待配置同步（约 15 秒）。</span>
            </div>
            <div class="tip-row">
              <span class="tip-index">3</span>
              <span>在「证书管理」上传或签发证书，即可启用 HTTPS。</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()

const loading = ref(false)
const stats = ref<any>({
  total_requests: 0,
  cache_hits: 0,
  cache_misses: 0,
  hit_ratio: 0,
  domain_count: 0,
  online_nodes: 0,
})
const domains = ref<any[]>([])
const nodes = ref<any[]>([])
const health = ref<any[]>([])
const projects = ref<any[]>([])

const onlineNodes = computed(() => nodes.value.filter(n => n.status === 'online').length)
const offlineNodes = computed(() => nodes.value.filter(n => n.status !== 'online').length)

async function load() {
  loading.value = true
  try {
    const requests: Promise<any>[] = [
      api.get('/api/v1/stats/summary').catch(() => null),
      api.get('/api/v1/domains').catch(() => []),
      api.get('/api/v1/origin-health').catch(() => []),
    ]
    if (auth.isAdmin) requests.push(api.get('/api/v1/nodes').catch(() => []))
    if (!auth.isAdmin) requests.push(api.get('/api/v1/projects').catch(() => []))

    const [summary, domainList, healthList, extra] = await Promise.all(requests)
    if (summary) stats.value = { ...stats.value, ...summary }
    domains.value = domainList || []
    health.value = healthList || []
    if (auth.isAdmin) nodes.value = extra || []
    else projects.value = extra || []
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.quick-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.quick-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text);
  transition: all 0.15s ease;
}

.quick-item:hover {
  border-color: var(--brand);
  background: #f7faff;
}

.quick-icon {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  background: var(--brand-bg);
  color: var(--brand);
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.quick-item strong {
  display: block;
  font-size: 13.5px;
  font-weight: 500;
}

.quick-item small {
  display: block;
  margin-top: 1px;
  font-size: 12px;
  color: var(--text-3);
  line-height: 1.5;
}

.node-summary {
  display: flex;
  gap: 24px;
}

.node-num {
  font-size: 22px;
  font-weight: 600;
  margin-top: 2px;
}

.node-list {
  margin-top: 14px;
  border-top: 1px solid var(--divider);
  padding-top: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.node-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}

.tips {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.tip-row {
  display: flex;
  gap: 10px;
  font-size: 13px;
  color: var(--text-2);
  line-height: 1.6;
}

.tip-index {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
  margin-top: 1px;
}

@media (max-width: 640px) {
  .quick-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
