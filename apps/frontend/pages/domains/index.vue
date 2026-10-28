<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">域名管理</div>
        <div class="page-desc">接入需要加速的域名，配置源站、项目归属与 CDN 高级策略</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" @click="exportDomains">
          <AppIcon name="upload" :size="15" />
          导出 CSV
        </button>
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <NuxtLink to="/domains/onboard" class="btn btn-default">
          <AppIcon name="activity" :size="15" />
          接入向导
        </NuxtLink>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          接入域名
        </button>
      </div>
    </div>

    <div class="card">
      <div class="filter-bar">
        <div class="search-box">
          <AppIcon name="search" :size="15" class="search-icon" />
          <input v-model="keyword" class="input" placeholder="搜索域名或源站" style="padding-left: 32px; min-width: 220px" />
        </div>
        <select v-model="statusFilter" class="select">
          <option value="">全部状态</option>
          <option value="active">已启用</option>
          <option value="disabled">已停用</option>
        </select>
        <select v-model="projectFilter" class="select">
          <option value="">全部项目</option>
          <option value="none">未归属项目</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <span class="spacer" />
        <span class="text-muted" style="font-size: 13px">共 {{ filtered.length }} 个域名</span>
      </div>

      <div v-if="loading" class="card-body">
        <div class="skeleton" style="height: 14px; width: 40%; margin-bottom: 12px" />
        <div class="skeleton" style="height: 34px; width: 100%; margin-bottom: 8px" />
        <div class="skeleton" style="height: 34px; width: 100%; margin-bottom: 8px" />
        <div class="skeleton" style="height: 34px; width: 100%" />
      </div>

      <template v-else-if="paged.length">
        <div v-if="selected.length" class="bulk-bar">
          <span>已选择 <b>{{ selected.length }}</b> 个域名</span>
          <button class="btn btn-text btn-sm" type="button" @click="bulkStatus('active')">批量启用</button>
          <button class="btn btn-text btn-sm" type="button" @click="bulkStatus('disabled')">批量停用</button>
          <button class="btn btn-text btn-sm danger" type="button" @click="bulkDelete">批量删除</button>
          <button class="btn btn-text btn-sm" type="button" @click="selected = []">取消</button>
        </div>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th class="check-col">
                  <input type="checkbox" :checked="allPageSelected" @change="togglePage" />
                </th>
                <th style="min-width: 220px">加速域名</th>
                <th style="min-width: 220px">源站</th>
                <th style="min-width: 160px">所属项目</th>
                <th>状态</th>
                <th>限流</th>
                <th style="min-width: 220px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="d in paged" :key="d.id">
                <td class="check-col">
                  <input v-model="selected" type="checkbox" :value="d.id" />
                </td>
                <td>
                  <NuxtLink :to="`/domains/${d.id}`" class="cell-main">{{ d.name }}</NuxtLink>
                  <div class="cell-sub">
                    {{ d.ssl_enabled ? 'HTTPS 已启用' : 'HTTP' }}
                    <span v-if="d.rate_limit_rps"> · {{ d.rate_limit_rps }} QPS</span>
                  </div>
                </td>
                <td>
                  <div class="mono text-2">
                    {{ d.origin_proto }}://{{ d.origin_host }}:{{ d.origin_port }}
                  </div>
                  <div class="cell-sub">
                    {{ d.origins?.length > 1 ? `${d.origins.length} 个源站 · 加权调度` : '主源站' }}
                  </div>
                </td>
                <td>
                  <select class="select proj-select" :value="d.project_id || ''"
                    :disabled="!auth.isAdmin && !projects.length"
                    @change="onProjectChange(d, ($event.target as HTMLSelectElement).value)">
                    <option v-if="auth.isAdmin" value="">未归属</option>
                    <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
                  </select>
                </td>
                <td>
                  <StatusTag :status="d.status" dot>
                    {{ d.status === 'active' ? '已启用' : '已停用' }}
                  </StatusTag>
                </td>
                <td class="text-2 num">{{ d.rate_limit_rps ? `${d.rate_limit_rps} QPS` : '不限' }}</td>
                <td>
                  <div class="ops">
                    <NuxtLink :to="`/domains/${d.id}`" class="btn btn-text btn-sm">详情</NuxtLink>
                    <button class="btn btn-text btn-sm" type="button" @click="openSettings(d)">
                      高级设置
                    </button>
                    <button class="btn btn-text btn-sm" type="button" @click="openEdit(d)">
                      编辑
                    </button>
                    <button class="btn btn-text btn-sm" type="button" @click="toggleStatus(d)">
                      {{ d.status === 'disabled' ? '启用' : '停用' }}
                    </button>
                    <button class="btn btn-text btn-sm danger" type="button" @click="remove(d)">
                      删除
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="table-footer">
          <AppPagination v-model:page="page" :total="filtered.length" :page-size="pageSize" />
        </div>
      </template>

      <EmptyState v-else icon="domain" :title="domains.length ? '没有匹配的域名' : '还没有接入域名'"
        :text="domains.length ? '试试调整搜索关键词或筛选条件。' : '接入域名并配置源站后，边缘节点会自动同步配置并开始加速。'">
        <button v-if="!domains.length" class="btn btn-primary btn-sm" type="button" @click="openCreate">
          接入第一个域名
        </button>
      </EmptyState>
    </div>

    <!-- 接入域名 -->
    <BaseModal v-model="createOpen" title="接入加速域名" confirm-text="确认接入" :loading="submitting" @confirm="createDomain">
      <div class="form-col">
        <div class="alert alert-info">
          <AppIcon name="info" :size="16" class="icon" />
          <span>接入后请把域名的 DNS 解析（CNAME 或 A）指向边缘节点，配置约 15 秒内同步生效。</span>
        </div>
        <div class="field">
          <label class="field-label">加速域名 <span class="req">*</span></label>
          <input v-model="createForm.name" class="input" placeholder="例如 cdn.example.com" />
        </div>
        <div class="form-grid">
          <div class="field">
            <label class="field-label">源站协议</label>
            <select v-model="createForm.origin_proto" class="select">
              <option value="https">HTTPS</option>
              <option value="http">HTTP</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">源站端口</label>
            <input v-model.number="createForm.origin_port" class="input" type="number" placeholder="443" />
          </div>
          <div class="field span-2">
            <label class="field-label">源站主机 <span class="req">*</span></label>
            <input v-model="createForm.origin_host" class="input" placeholder="例如 origin.example.com" />
            <span class="field-hint">接入后可在「编辑源站配置」中添加更多源站，并设置权重与优先级。</span>
          </div>
          <div class="field span-2">
            <label class="field-label">所属项目</label>
            <select v-model="createForm.project_id" class="select">
              <option v-if="auth.isAdmin" value="">不关联项目（仅管理员可见）</option>
              <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
            <span class="field-hint">普通用户留空时会自动归入自己的「Default」项目。</span>
          </div>
        </div>
        <p v-if="createError" class="text-danger" style="font-size: 13px">{{ createError }}</p>
      </div>
    </BaseModal>

    <!-- 编辑源站 -->
    <BaseModal v-model="editOpen" title="编辑源站配置" width="720px" confirm-text="保存修改" :loading="submitting"
      @confirm="saveOrigin">
      <div class="form-col">
        <div class="section-title">源站池</div>
        <div class="origin-row origin-head">
          <span>协议</span>
          <span>源站主机</span>
          <span>端口</span>
          <span>权重</span>
          <span>优先级</span>
          <span>状态</span>
          <span></span>
        </div>
        <div v-for="(origin, index) in editForm.origins" :key="index" class="origin-row">
          <select v-model="origin.proto" class="select">
            <option value="https">HTTPS</option>
            <option value="http">HTTP</option>
          </select>
          <input v-model="origin.host" class="input" placeholder="源站主机" />
          <input v-model.number="origin.port" class="input" type="number" placeholder="端口" />
          <input v-model.number="origin.weight" class="input" type="number" min="1" title="权重" placeholder="权重" />
          <input v-model.number="origin.priority" class="input" type="number" min="0" title="优先级" placeholder="优先级" />
          <label class="check origin-check">
            <input v-model="origin.enabled" type="checkbox" />
            启用
          </label>
          <button class="btn btn-text btn-sm danger" type="button" :disabled="editForm.origins.length <= 1"
            @click="removeOrigin(index)">
            删除
          </button>
        </div>
        <button class="btn btn-default btn-sm" type="button" @click="addOrigin">
          + 添加源站
        </button>
        <p class="field-hint">
          优先级数字越小越优先；同一优先级按权重分配流量。健康检查失败的源站会被自动跳过，全部异常时仍会尝试。
        </p>

        <label class="check">
          <input v-model="editForm.ssl_enabled" type="checkbox" />
          启用 HTTPS（需要有效证书）
        </label>
        <p class="field-hint" style="margin-top: 4px">
          开启后该域名的 HTTP 请求会 301/308 跳转到 HTTPS；跳转端口优先取
          EDGE_HTTPS_REDIRECT_PORT，其次取 HTTPS 监听端口（443 时省略）。
        </p>
        <p v-if="editError" class="text-danger" style="font-size: 13px">{{ editError }}</p>
      </div>
    </BaseModal>

    <!-- 高级设置 -->
    <BaseDrawer v-model="settingsOpen" :title="`高级设置 · ${settingsDomain?.name || ''}`" :loading="submitting"
      @confirm="saveSettings">
      <div class="form-col">
        <div class="alert alert-info">
          <AppIcon name="info" :size="16" class="icon" />
          <span>保存后边缘节点约 15 秒内自动同步，无需停用或重启。</span>
        </div>

        <div v-if="settingsDomain?.published_version_id" class="alert alert-warning">
          <AppIcon name="info" :size="16" class="icon" />
          <span>该域名已启用配置发布：保存后不会立即下发，请在「配置发布」创建并审批发布单后才会切换边缘版本。</span>
        </div>

        <label class="switch" :class="{ on: settings.ignore_query_string }">
          <span class="switch-track" />
          <input v-model="settings.ignore_query_string" type="checkbox" style="display: none" />
          忽略 URL 查询串（缓存键不含 ?query）
        </label>

        <div class="field">
          <label class="field-label">CORS 允许源</label>
          <input v-model="settings.cors_origins" class="input" placeholder="* 或 https://a.com,https://b.com" />
        </div>

        <div class="field">
          <label class="field-label">防盗链 Referer 白名单</label>
          <input v-model="settings.hotlink_allow_referers" class="input"
            placeholder="example.com,*.example.com（留空关闭）" />
        </div>

        <div class="form-grid">
          <div class="field">
            <label class="field-label">回源超时（毫秒）</label>
            <input v-model.number="settings.origin_timeout_ms" class="input" type="number" />
          </div>
          <div class="field">
            <label class="field-label">限流 RPS（0 = 不限）</label>
            <input v-model.number="settings.rate_limit_rps" class="input" type="number" />
          </div>
          <div class="field">
            <label class="field-label">限流突发</label>
            <input v-model.number="settings.rate_limit_burst" class="input" type="number" />
          </div>
        </div>

        <div class="field">
          <label class="field-label">Origin Shield 地址</label>
          <input
            v-model="settings.shield_url"
            class="input"
            placeholder="https://shield.example.com（留空关闭）"
          />
          <span class="field-hint">
            可选。配置后边缘优先向 Shield 回源，并保留当前域名 Host；Shield 不可用时自动回退到普通源站。
          </span>
        </div>

        <div class="field-label" style="margin-top: 24px; font-size: 15px">CC 防御</div>
        <div class="field">
          <label class="check">
            <input v-model="settings.cc_enabled" type="checkbox" />
            启用 CC 防御（按客户端 IP 限速，超限自动封禁）
          </label>
          <span class="field-hint">
            统计窗口为 1 秒；连续超限达到次数后临时封禁该 IP，封禁状态在边缘内存中，重启后清空。
          </span>
        </div>
        <div class="form-grid">
          <div class="field">
            <label class="field-label">每 IP 每秒请求数</label>
            <input v-model.number="settings.cc_rps" class="input" type="number" min="1" />
          </div>
          <div class="field">
            <label class="field-label">突发额度</label>
            <input v-model.number="settings.cc_burst" class="input" type="number" min="0" />
          </div>
          <div class="field">
            <label class="field-label">连续超限次数后封禁</label>
            <input v-model.number="settings.cc_ban_after" class="input" type="number" min="1" />
          </div>
          <div class="field">
            <label class="field-label">封禁时长（秒）</label>
            <input v-model.number="settings.cc_ban_seconds" class="input" type="number" min="1" max="86400" />
          </div>
          <div class="field">
            <label class="field-label">模式</label>
            <select v-model="settings.cc_mode" class="select">
              <option value="block">拦截（429）</option>
              <option value="monitor">观察（只记录）</option>
            </select>
          </div>
        </div>
        <div class="field">
          <label class="field-label">IP 白名单</label>
          <input v-model="settings.cc_allow_ips" class="input" placeholder="10.0.0.0/8, 203.0.113.7" />
          <span class="field-hint">逗号分隔，支持 IPv4/IPv6 与 CIDR；白名单 IP 不受 CC 限制。</span>
        </div>

        <div class="field">
          <label class="field-label">自定义响应头</label>
          <textarea v-model="settings.custom_headers" class="textarea" rows="4"
            placeholder="X-CDN: lagran&#10;X-Frame-Options: DENY" />
          <span class="field-hint">每行一个，格式 Name: Value。</span>
        </div>
      </div>
    </BaseDrawer>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { ask } = useConfirm()

const loading = ref(false)
const submitting = ref(false)
const domains = ref<any[]>([])
const projects = ref<any[]>([])

const keyword = ref('')
const statusFilter = ref('')
const projectFilter = ref('')
const page = ref(1)
const pageSize = 10

const createOpen = ref(false)
const createError = ref('')
const createForm = ref({
  name: '',
  origin_host: '',
  origin_port: 443,
  origin_proto: 'https',
  project_id: '',
})

const editOpen = ref(false)
const editError = ref('')
const editDomain = ref<any>(null)
interface OriginForm {
  host: string
  port: number
  proto: string
  weight: number
  priority: number
  enabled: boolean
}
const editForm = ref({
  origins: [] as OriginForm[],
  ssl_enabled: true,
})

const settingsOpen = ref(false)
const settingsDomain = ref<any>(null)
const settings = ref({
  ignore_query_string: false,
  cors_origins: '',
  hotlink_allow_referers: '',
  origin_timeout_ms: 10000,
  custom_headers: '',
  shield_url: '',
  rate_limit_rps: 0,
  rate_limit_burst: 0,
  cc_enabled: false,
  cc_rps: 20,
  cc_burst: 40,
  cc_ban_after: 5,
  cc_ban_seconds: 300,
  cc_mode: 'block',
  cc_allow_ips: '',
})

const filtered = computed(() => {
  const q = keyword.value.trim().toLowerCase()
  return domains.value.filter((d) => {
    if (statusFilter.value && d.status !== statusFilter.value) return false
    if (projectFilter.value === 'none' && d.project_id) return false
    if (projectFilter.value && projectFilter.value !== 'none' && d.project_id !== projectFilter.value)
      return false
    if (!q) return true
    return (
      String(d.name).toLowerCase().includes(q) ||
      String(d.origin_host).toLowerCase().includes(q)
    )
  })
})

const selected = ref<string[]>([])

const paged = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

const allPageSelected = computed(
  () => paged.value.length > 0 && paged.value.every((d) => selected.value.includes(d.id)),
)

function togglePage() {
  if (allPageSelected.value) {
    selected.value = selected.value.filter((id) => !paged.value.some((d) => d.id === id))
  } else {
    selected.value = [...new Set([...selected.value, ...paged.value.map((d) => d.id)])]
  }
}

async function bulkStatus(status: string) {
  if (!selected.value.length) return
  const ids = [...selected.value]
  await Promise.all(
    ids.map((id) => api.post(`/api/v1/domains/${id}/status`, { status }).catch(() => null)),
  )
  toast.success(`已提交 ${ids.length} 个域名的状态变更`)
  selected.value = []
  await load()
}

async function bulkDelete() {
  if (!selected.value.length) return
  const ok = await ask({
    title: '批量删除域名',
    message: `将删除 ${selected.value.length} 个域名及其规则，此操作不可恢复。`,
    confirmText: '确认删除',
    danger: true,
  })
  if (!ok) return
  await Promise.all(selected.value.map((id) => api.del(`/api/v1/domains/${id}`).catch(() => null)))
  toast.success('批量删除已提交')
  selected.value = []
  await load()
}

function exportDomains() {
  exportCsv(`lagran-domains-${new Date().toISOString().slice(0, 10)}`, filtered.value, [
    { key: 'name', label: '域名' },
    { key: 'status', label: '状态' },
    { key: 'origin_proto', label: '源站协议' },
    { key: 'origin_host', label: '源站主机' },
    { key: 'origin_port', label: '源站端口' },
    { key: 'ssl_enabled', label: 'HTTPS' },
    { key: 'rate_limit_rps', label: '限流 QPS' },
    { key: 'created_at', label: '创建时间' },
  ])
}

watch([keyword, statusFilter, projectFilter], () => {
  page.value = 1
})

async function load() {
  loading.value = true
  try {
    const [d, p] = await Promise.all([
      api.get<any[]>('/api/v1/domains').catch(() => []),
      api.get<any[]>('/api/v1/projects').catch(() => []),
    ])
    domains.value = d || []
    projects.value = p || []
  } finally {
    loading.value = false
  }
}

function openCreate() {
  createError.value = ''
  createForm.value = {
    name: '',
    origin_host: '',
    origin_port: 443,
    origin_proto: 'https',
    project_id: '',
  }
  createOpen.value = true
}

async function createDomain() {
  createError.value = ''
  if (!createForm.value.name.trim() || !createForm.value.origin_host.trim()) {
    createError.value = '请填写加速域名与源站主机'
    return
  }
  submitting.value = true
  try {
    const body: any = {
      name: createForm.value.name.trim(),
      origin_host: createForm.value.origin_host.trim(),
      origin_port: createForm.value.origin_port || 80,
      origin_proto: createForm.value.origin_proto,
      ssl_enabled: createForm.value.origin_proto === 'https',
    }
    if (createForm.value.project_id) body.project_id = createForm.value.project_id
    await api.post('/api/v1/domains', body)
    createOpen.value = false
    toast.success('域名已接入，等待边缘节点同步（约 15 秒）')
    await load()
  } catch (e: any) {
    createError.value = e?.data?.error || '接入失败，请检查域名是否已存在'
  } finally {
    submitting.value = false
  }
}

async function onProjectChange(d: any, value: string) {
  try {
    await api.put(`/api/v1/domains/${d.id}`, { project_id: value || null })
    toast.success('项目归属已更新')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '更新项目归属失败')
    await load()
  }
}

function openEdit(d: any) {
  editError.value = ''
  editDomain.value = d
  const pool: OriginForm[] =
    Array.isArray(d.origins) && d.origins.length
      ? d.origins.map((origin: any) => ({
        host: origin.host,
        port: origin.port,
        proto: origin.proto,
        weight: origin.weight ?? 100,
        priority: origin.priority ?? 0,
        enabled: origin.enabled !== false,
      }))
      : [
        {
          host: d.origin_host,
          port: d.origin_port,
          proto: d.origin_proto,
          weight: 100,
          priority: 0,
          enabled: true,
        },
      ]
  editForm.value = {
    origins: pool,
    ssl_enabled: !!d.ssl_enabled,
  }
  editOpen.value = true
}

function addOrigin() {
  editForm.value.origins.push({
    host: '',
    port: 443,
    proto: 'https',
    weight: 100,
    priority: 0,
    enabled: true,
  })
}

function removeOrigin(index: number) {
  if (editForm.value.origins.length <= 1) return
  editForm.value.origins.splice(index, 1)
}

async function saveOrigin() {
  editError.value = ''
  const pool = editForm.value.origins
    .map((origin) => ({
      host: origin.host.trim(),
      port: Number(origin.port) || (origin.proto === 'https' ? 443 : 80),
      proto: origin.proto,
      weight: Math.max(1, Number(origin.weight) || 100),
      priority: Math.max(0, Number(origin.priority) || 0),
      enabled: origin.enabled,
    }))
    .filter((origin) => origin.host)
  if (!pool.length) {
    editError.value = '至少填写一个源站主机'
    return
  }
  if (!pool.some((origin) => origin.enabled)) {
    editError.value = '至少启用一个源站'
    return
  }
  if (!editDomain.value) return
  submitting.value = true
  try {
    const primary = pool.find((origin) => origin.enabled) || pool[0]
    await api.put(`/api/v1/domains/${editDomain.value.id}`, {
      origin_host: primary.host,
      origin_port: primary.port,
      origin_proto: primary.proto,
      ssl_enabled: editForm.value.ssl_enabled,
      origins: pool,
    })
    editOpen.value = false
    toast.success('源站池已保存')
    await load()
  } catch (e: any) {
    editError.value = e?.data?.error || '保存失败'
  } finally {
    submitting.value = false
  }
}

async function openSettings(d: any) {
  settingsDomain.value = d
  try {
    const s = await api.get<any>(`/api/v1/domains/${d.id}/settings`)
    settings.value = {
      ignore_query_string: !!s.ignore_query_string,
      cors_origins: s.cors_origins || '',
      hotlink_allow_referers: s.hotlink_allow_referers || '',
      origin_timeout_ms: s.origin_timeout_ms || 10000,
      custom_headers: s.custom_headers || '',
      shield_url: s.shield_url || '',
      rate_limit_rps: s.rate_limit_rps || 0,
      rate_limit_burst: s.rate_limit_burst || 0,
      cc_enabled: !!s.cc_enabled,
      cc_rps: s.cc_rps ?? 20,
      cc_burst: s.cc_burst ?? 40,
      cc_ban_after: s.cc_ban_after ?? 5,
      cc_ban_seconds: s.cc_ban_seconds ?? 300,
      cc_mode: s.cc_mode || 'block',
      cc_allow_ips: s.cc_allow_ips || '',
    }
  } catch {
    toast.error('读取高级设置失败，已使用默认值')
  }
  settingsOpen.value = true
}

async function saveSettings() {
  if (!settingsDomain.value) return
  submitting.value = true
  try {
    await api.put(`/api/v1/domains/${settingsDomain.value.id}/settings`, settings.value)
    settingsOpen.value = false
    toast.success('高级设置已保存，边缘约 15 秒内同步')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '保存失败')
  } finally {
    submitting.value = false
  }
}

async function toggleStatus(d: any) {
  const next = d.status === 'disabled' ? 'active' : 'disabled'
  const ok = await ask({
    title: next === 'disabled' ? '停用域名' : '启用域名',
    message:
      next === 'disabled'
        ? `停用后，访问 ${d.name} 将返回「域名未接入」提示页，确认继续？`
        : `确认重新启用 ${d.name} 的加速服务？`,
    confirmText: next === 'disabled' ? '停用' : '启用',
    danger: next === 'disabled',
  })
  if (!ok) return
  try {
    await api.post(`/api/v1/domains/${d.id}/status`, { status: next })
    toast.success(next === 'disabled' ? '域名已停用' : '域名已启用')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '状态更新失败')
  }
}

async function remove(d: any) {
  const ok = await ask({
    title: '删除加速域名',
    message: `删除后 ${d.name} 将不再走 CDN，相关缓存规则会被一并删除。此操作不可恢复。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/domains/${d.id}`)
    toast.success('域名已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.search-box {
  position: relative;
  display: flex;
  align-items: center;
}

.search-icon {
  position: absolute;
  left: 10px;
  color: var(--text-3);
  pointer-events: none;
}

.proj-select {
  height: 30px;
  min-width: 130px;
  font-size: 13px;
}

.section-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-2);
  padding-bottom: 6px;
  border-bottom: 1px solid var(--divider);
}

.origin-row {
  display: grid;
  grid-template-columns: 88px minmax(160px, 1fr) 82px 78px 78px 64px 56px;
  gap: 8px;
  align-items: center;
}

.origin-head {
  font-size: 12px;
  color: var(--text-3);
  padding: 0 0 2px;
}

.origin-row .select,
.origin-row .input {
  height: 32px;
  min-width: 0;
}

.origin-check {
  white-space: nowrap;
  font-size: 12px;
}

.check-col {
  width: 38px;
}

.bulk-bar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 12px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--brand-bg);
  color: var(--text-2);
  font-size: 13px;
}

.bulk-bar b {
  color: var(--brand);
}

@media (max-width: 900px) {
  .origin-head {
    display: none;
  }

  .origin-row {
    display: flex;
    flex-wrap: wrap;
    padding: 12px;
    border: 1px solid var(--divider);
    border-radius: 10px;
    background: #fafbfc;
  }

  .origin-row .select {
    width: 84px;
    flex: none;
  }

  .origin-row .input {
    flex: 1 1 100px;
    width: auto;
  }

  .origin-row .input:first-of-type {
    flex: 1 1 100%;
  }

  .origin-row .origin-check {
    flex: none;
  }

  .origin-row .btn {
    flex: none;
    margin-left: auto;
  }
}
</style>
