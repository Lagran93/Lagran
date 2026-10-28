<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">
          <NuxtLink to="/domains" class="btn btn-icon btn-default" aria-label="返回域名列表">
            <AppIcon name="arrow-left" :size="16" />
          </NuxtLink>
          <span>{{ domain?.name || '域名详情' }}</span>
          <StatusTag v-if="domain" :status="domain.status" dot>
            {{ domain.status === 'active' ? '已启用' : '已停用' }}
          </StatusTag>
        </div>
        <div class="page-desc">查看域名的源站、缓存策略、规则与证书绑定</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <NuxtLink to="/rules" class="btn btn-primary">
          <AppIcon name="rules" :size="15" />
          管理规则
        </NuxtLink>
      </div>
    </div>

    <div v-if="notFound" class="card">
      <EmptyState
        icon="domain"
        title="域名不存在"
        text="该域名可能已被删除，或你没有访问权限。"
      >
        <NuxtLink to="/domains" class="btn btn-default btn-sm">返回域名列表</NuxtLink>
      </EmptyState>
    </div>

    <template v-else>
      <div class="grid grid-main-side">
        <div>
          <div class="card">
            <div class="card-head">
              <div class="card-title">基础信息</div>
            </div>
            <div class="card-body">
              <div class="detail-grid">
                <div class="detail-item">
                  <div class="detail-label">加速域名</div>
                  <div class="detail-value mono">{{ domain?.name || '—' }}</div>
                </div>
                <div class="detail-item">
                  <div class="detail-label">源站地址</div>
                  <div class="detail-value mono">
                    {{ domain ? `${domain.origin_proto}://${domain.origin_host}:${domain.origin_port}` : '—' }}
                  </div>
                </div>
                <div class="detail-item">
                  <div class="detail-label">HTTPS</div>
                  <div class="detail-value">{{ domain?.ssl_enabled ? '已启用' : '未启用' }}</div>
                </div>
                <div class="detail-item">
                  <div class="detail-label">限流</div>
                  <div class="detail-value">
                    {{ domain?.rate_limit_rps ? `${domain.rate_limit_rps} QPS（突发 ${domain.rate_limit_burst}）` : '不限' }}
                  </div>
                </div>
                <div class="detail-item">
                  <div class="detail-label">所属项目</div>
                  <div class="detail-value">{{ projectName || '未归属项目' }}</div>
                </div>
                <div class="detail-item">
                  <div class="detail-label">域名 ID</div>
                  <div class="detail-value mono">{{ domain?.id || '—' }}</div>
                </div>
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-head">
              <div>
                <div class="card-title">缓存规则</div>
                <div class="card-desc">该域名下按优先级生效的规则</div>
              </div>
              <div class="card-extra">
                <NuxtLink to="/rules" class="link-btn">全部规则</NuxtLink>
              </div>
            </div>
            <div v-if="rules.length" class="table-wrap">
              <table class="table">
                <thead>
                  <tr>
                    <th>路径匹配</th>
                    <th>动作</th>
                    <th>TTL</th>
                    <th>SWR</th>
                    <th>优先级</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="r in rules" :key="r.id">
                    <td class="mono">{{ r.path_pattern }}</td>
                    <td>
                      <StatusTag :tone="r.action === 'cache' ? 'success' : r.action === 'bypass' ? 'warning' : 'danger'">
                        {{ r.action === 'cache' ? '缓存' : r.action === 'bypass' ? '绕过' : '不存储' }}
                      </StatusTag>
                    </td>
                    <td class="num">{{ r.action === 'cache' ? `${r.ttl_seconds} 秒` : '—' }}</td>
                    <td class="num">{{ r.swr_seconds ? `${r.swr_seconds} 秒` : '—' }}</td>
                    <td class="num">{{ r.priority }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <EmptyState
              v-else
              icon="rules"
              title="暂无专属规则"
              text="没有匹配规则时，边缘会按源站缓存头与域名默认 TTL 处理。"
            />
          </div>

          <div class="card">
            <div class="card-head">
              <div class="card-title">证书</div>
              <div class="card-extra">
                <NuxtLink to="/certs" class="link-btn">证书管理</NuxtLink>
              </div>
            </div>
            <div v-if="certs.length" class="table-wrap">
              <table class="table">
                <thead>
                  <tr>
                    <th>签发者</th>
                    <th>状态</th>
                    <th>有效期至</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="c in certs" :key="c.id">
                    <td>{{ c.issuer || '—' }}</td>
                    <td><StatusTag :status="c.status">{{ c.status }}</StatusTag></td>
                    <td class="text-2">{{ formatDay(c.not_after) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <EmptyState
              v-else
              icon="cert"
              title="该域名暂无证书"
              text="如需启用 HTTPS，请先在证书管理上传或签发证书。"
            />
          </div>
        </div>

        <div>
          <div class="card">
            <div class="card-head">
              <div class="card-title">高级设置</div>
            </div>
            <div class="card-body">
              <div v-if="settings" class="kv-list">
                <div class="kv">
                  <span class="kv-key">忽略查询串</span>
                  <span class="kv-val">{{ settings.ignore_query_string ? '是' : '否' }}</span>
                </div>
                <div class="kv">
                  <span class="kv-key">CORS 允许源</span>
                  <span class="kv-val mono">{{ settings.cors_origins || '—' }}</span>
                </div>
                <div class="kv">
                  <span class="kv-key">防盗链</span>
                  <span class="kv-val mono">{{ settings.hotlink_allow_referers || '关闭' }}</span>
                </div>
                <div class="kv">
                  <span class="kv-key">回源超时</span>
                  <span class="kv-val">{{ settings.origin_timeout_ms }} ms</span>
                </div>
                <div class="kv">
                  <span class="kv-key">限流</span>
                  <span class="kv-val">
                    {{ settings.rate_limit_rps ? `${settings.rate_limit_rps} QPS / 突发 ${settings.rate_limit_burst}` : '不限' }}
                  </span>
                </div>
                <div class="kv">
                  <span class="kv-key">Origin Shield</span>
                  <span class="kv-val mono">{{ settings.shield_url || '关闭' }}</span>
                </div>
                <div class="kv">
                  <span class="kv-key">自定义头</span>
                  <span class="kv-val mono pre">{{ settings.custom_headers || '—' }}</span>
                </div>
              </div>
              <p v-else class="text-muted" style="font-size: 13px">暂无高级设置数据</p>
              <NuxtLink to="/domains" class="btn btn-default btn-sm mt-16">
                <AppIcon name="edit" :size="14" />
                去域名列表修改
              </NuxtLink>
            </div>
          </div>

          <div class="card">
            <div class="card-head">
              <div class="card-title">接入检查</div>
            </div>
            <div class="card-body tips">
              <div class="tip-row">
                <AppIcon :name="domain?.status === 'active' ? 'check' : 'close'" :size="15" :class="domain?.status === 'active' ? 'text-success' : 'text-muted'" />
                <span>域名状态为启用</span>
              </div>
              <div class="tip-row">
                <AppIcon :name="certs.length ? 'check' : 'close'" :size="15" :class="certs.length ? 'text-success' : 'text-muted'" />
                <span>已配置 TLS 证书</span>
              </div>
              <div class="tip-row">
                <AppIcon :name="rules.length ? 'check' : 'close'" :size="15" :class="rules.length ? 'text-success' : 'text-muted'" />
                <span>已配置专属缓存规则</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const route = useRoute()

const id = computed(() => String(route.params.id || ''))
const loading = ref(false)
const notFound = ref(false)
const domain = ref<any>(null)
const settings = ref<any>(null)
const rules = ref<any[]>([])
const certs = ref<any[]>([])
const projects = ref<any[]>([])

const projectName = computed(() => {
  if (!domain.value?.project_id) return ''
  const p = projects.value.find((x) => x.id === domain.value.project_id)
  return p?.name || ''
})

async function load() {
  if (!id.value) return
  loading.value = true
  notFound.value = false
  try {
    domain.value = await api.get<any>(`/api/v1/domains/${id.value}`)
  } catch {
    notFound.value = true
    loading.value = false
    return
  }
  try {
    const [s, r, c, p] = await Promise.all([
      api.get<any>(`/api/v1/domains/${id.value}/settings`).catch(() => null),
      api.get<any[]>('/api/v1/rules').catch(() => []),
      api.get<any[]>('/api/v1/certs').catch(() => []),
      api.get<any[]>('/api/v1/projects').catch(() => []),
    ])
    settings.value = s
    rules.value = (r || []).filter((x) => x.domain_id === id.value)
    certs.value = (c || []).filter((x) => x.domain_name === domain.value?.name)
    projects.value = p || []
  } finally {
    loading.value = false
  }
}

watch(id, load)
onMounted(load)
</script>

<style scoped>
.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 18px 24px;
}

.detail-label {
  font-size: 12px;
  color: var(--text-3);
}

.detail-value {
  margin-top: 4px;
  font-size: 14px;
  color: var(--text);
  word-break: break-all;
}

.kv-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.kv {
  display: flex;
  gap: 12px;
  font-size: 13px;
}

.kv-key {
  width: 88px;
  flex: none;
  color: var(--text-3);
}

.kv-val {
  color: var(--text-2);
  word-break: break-all;
}

.kv-val.pre {
  white-space: pre-wrap;
}

.tips {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.tip-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: var(--text-2);
}

@media (max-width: 640px) {
  .detail-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
