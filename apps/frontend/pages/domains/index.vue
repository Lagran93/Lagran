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
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ projectLabel(p) }}</option>
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
                    <option v-for="p in projects" :key="p.id" :value="p.id">{{ projectLabel(p) }}</option>
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
            <input v-model="createForm.origin_host" class="input" placeholder="例如 origin.example.com 或 203.0.113.10" />
            <span class="field-hint">接入后可在「编辑源站配置」中添加更多源站，并设置权重与优先级。</span>
          </div>
          <div class="field">
            <label class="field-label">源站 TLS SNI</label>
            <input v-model="createForm.origin_sni" class="input" placeholder="例如 origin.example.com" />
            <span class="field-hint">源站填 IP 且 HTTPS 证书是域名证书时填写。</span>
          </div>
          <div class="field">
            <label class="field-label">回源 Host</label>
            <input v-model="createForm.origin_host_header" class="input" placeholder="留空则使用 SNI" />
            <span class="field-hint">源站虚拟主机需要的 Host，留空时回退到 SNI/源站主机。</span>
          </div>
          <div class="field span-2">
            <label class="field-label">所属项目</label>
            <select v-model="createForm.project_id" class="select">
              <option v-if="auth.isAdmin" value="">不关联项目（仅管理员可见）</option>
              <option v-for="p in projects" :key="p.id" :value="p.id">{{ projectLabel(p) }}</option>
            </select>
            <span class="field-hint">普通用户留空时会自动归入自己的「Default」项目。</span>
          </div>
        </div>
        <p v-if="createError" class="text-danger" style="font-size: 13px">{{ createError }}</p>
      </div>
    </BaseModal>

    <!-- 编辑源站 -->
    <BaseModal v-model="editOpen" title="编辑源站配置" width="860px" confirm-text="保存修改" :loading="submitting"
      @confirm="saveOrigin">
      <div class="origin-editor">
        <div v-if="editDomain" class="origin-context">
          <span class="origin-context-label">当前域名</span>
          <strong class="origin-context-name">{{ editDomain.name }}</strong>
          <span class="origin-context-address">
            {{ editDomain.origin_proto }}://{{ editDomain.origin_host }}:{{ editDomain.origin_port }}
          </span>
        </div>

        <div class="origin-editor-head">
          <div class="origin-title-line">
            <span class="origin-editor-title">源站池</span>
            <span class="origin-count" :class="{ empty: !enabledOriginCount }">
              <span class="origin-count-dot" />
              {{ enabledOriginCount }}/{{ editForm.origins.length }} 已启用
            </span>
          </div>
          <button class="btn btn-default btn-sm origin-add-btn" type="button" @click="addOrigin">
            <AppIcon name="plus" :size="14" />
            添加源站
          </button>
        </div>

        <div class="origin-list">
          <div v-for="(origin, index) in editForm.origins" :key="index" class="origin-card"
            :class="{ 'is-disabled': !origin.enabled }">
            <div class="origin-card-head">
              <div class="origin-identity">
                <span class="origin-number">{{ String(index + 1).padStart(2, '0') }}</span>
                <div class="origin-name-wrap">
                  <div class="origin-name">{{ origin.host || '新源站' }}</div>
                  <div class="origin-meta">
                    <span>{{ origin.proto.toUpperCase() }}</span>
                    <span class="origin-meta-separator" />
                    <span>权重 {{ origin.weight || 100 }}</span>
                    <span>优先级 {{ origin.priority ?? 0 }}</span>
                  </div>
                </div>
              </div>
              <div class="origin-card-actions">
                <label class="origin-enable" :class="{ active: origin.enabled }">
                  <input v-model="origin.enabled" type="checkbox" />
                  <span class="origin-switch" aria-hidden="true" />
                  <span>{{ origin.enabled ? '已启用' : '已停用' }}</span>
                </label>
                <button class="origin-delete" type="button" aria-label="删除该源站" :disabled="editForm.origins.length <= 1"
                  @click="removeOrigin(index)">
                  <AppIcon name="trash" :size="14" />
                  <span>删除</span>
                </button>
              </div>
            </div>

            <div class="origin-card-body">
              <div class="origin-config">
                <label class="origin-field origin-proto-field">
                  <span>协议</span>
                  <select v-model="origin.proto" class="select">
                    <option value="https">HTTPS</option>
                    <option value="http">HTTP</option>
                  </select>
                </label>
                <label class="origin-field origin-host-field">
                  <span>源站主机 / IP</span>
                  <input v-model="origin.host" class="input" inputmode="url" autocapitalize="none" spellcheck="false"
                    placeholder="origin.example.com 或 203.0.113.10" />
                </label>
                <label class="origin-field origin-port-field">
                  <span>端口</span>
                  <input v-model.number="origin.port" class="input" type="number" min="1" max="65535" />
                </label>
              </div>

              <div class="origin-tuning">
                <label class="origin-field">
                  <span>权重</span>
                  <input v-model.number="origin.weight" class="input" type="number" min="1" placeholder="100" />
                </label>
                <label class="origin-field">
                  <span>优先级</span>
                  <input v-model.number="origin.priority" class="input" type="number" min="0" placeholder="0" />
                </label>
                <label class="origin-field">
                  <span>TLS SNI <em>可选</em></span>
                  <input v-model="origin.sni" class="input" inputmode="url" autocapitalize="none" spellcheck="false"
                    placeholder="证书域名" />
                </label>
                <label class="origin-field">
                  <span>回源 Host <em>可选</em></span>
                  <input v-model="origin.host_header" class="input" inputmode="url" autocapitalize="none"
                    spellcheck="false" placeholder="留空用 SNI / 主机" />
                </label>
              </div>
            </div>
          </div>
        </div>

        <div class="origin-options">
          <span class="origin-option-icon">
            <AppIcon name="shield" :size="16" />
          </span>
          <div class="origin-option-copy">
            <label class="origin-enable origin-https-toggle" :class="{ active: editForm.ssl_enabled }">
              <input v-model="editForm.ssl_enabled" type="checkbox" />
              <span class="origin-switch" aria-hidden="true" />
              <span>启用 HTTPS 跳转</span>
            </label>
            <small>HTTP 请求 301/308 跳转到 HTTPS；源站为 IP + 域名证书时请填写 TLS SNI / 回源 Host。</small>
          </div>
        </div>

        <div v-if="editError" class="alert alert-danger origin-error" role="alert">
          <AppIcon name="alert" :size="16" class="icon" />
          <span>{{ editError }}</span>
        </div>
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
            <label class="field-label">回源鉴权 Header</label>
            <input v-model="settings.origin_auth_header" class="input" placeholder="例如 x-origin-token" />
          </div>
          <div class="field">
            <label class="field-label">回源鉴权值</label>
            <input v-model="settings.origin_auth_value" class="input" type="password" placeholder="仅 Edge 与源站知道" />
          </div>
        </div>
        <div class="field">
          <label class="field-label">防盗链签名</label>
          <label class="switch" :class="{ on: settings.hotlink_signature_enabled }">
            <span class="switch-track" />
            <input v-model="settings.hotlink_signature_enabled" type="checkbox" style="display: none" />
            使用签名 URL 密钥绕过 Referer 防盗链
          </label>
          <span class="field-hint">开启后，Referer 不在白名单时必须携带同一套 expires+sig；公开资源不受影响。</span>
        </div>

        <div class="field">
          <label class="field-label">签名 URL 防护</label>
          <select v-model="settings.signed_url_mode" class="select">
            <option value="off">关闭</option>
            <option value="all">整个域名都要求签名</option>
            <option value="paths">仅指定路径要求签名</option>
          </select>
          <span class="field-hint">
            选择「仅指定路径」后，只需保护 /private/*、/downloads/* 等私有目录，公开页面和静态资源不受影响。
          </span>
        </div>

        <div v-if="settings.signed_url_mode === 'paths'" class="field">
          <label class="field-label">需要签名的路径</label>
          <textarea v-model="settings.signed_url_paths" class="textarea" rows="4"
            placeholder="/private/*&#10;/downloads/*&#10;/vip/exact-file.mp4" />
          <span class="field-hint">每行一个规则，支持精确路径或 /prefix/*；不支持 .. 和正则。</span>
        </div>

        <div class="form-grid">
          <div class="field">
            <label class="field-label">签名有效期上限（秒）</label>
            <input v-model.number="settings.signed_url_ttl_secs" class="input" type="number" min="1" />
          </div>
          <div class="field">
            <label class="field-label">当前签名密钥</label>
            <input v-model="settings.signed_url_secret" class="input" type="text" placeholder="开启后自动生成；可手动填写" />
          </div>
        </div>
        <div class="field">
          <label class="field-label">上一个签名密钥（轮换兼容）</label>
          <input v-model="settings.signed_url_previous_secret" class="input" type="text"
            placeholder="轮换后旧密钥保留一段时间，留空则立即失效" />
          <span class="field-hint">
            修改密钥后旧链接会立即失效；建议使用接口 /signed-url/rotate 自动轮换。
          </span>
        </div>

        <div class="form-grid">
          <div class="field">
            <label class="field-label">回源连接超时（毫秒）</label>
            <input v-model.number="settings.origin_timeout_ms" class="input" type="number" />
          </div>
          <div class="field">
            <label class="field-label">全局限流 RPS（0 = 不限）</label>
            <input v-model.number="settings.rate_limit_rps" class="input" type="number" />
          </div>
          <div class="field">
            <label class="field-label">全局限流突发</label>
            <input v-model.number="settings.rate_limit_burst" class="input" type="number" />
          </div>
        </div>

        <div class="field">
          <label class="field-label">Origin Shield 地址</label>
          <input v-model="settings.shield_url" class="input" placeholder="https://shield.example.com（留空关闭）" />
          <span class="field-hint">
            可选。配置后边缘优先向 Shield 回源，并保留当前域名 Host；Shield 不可用时自动回退到普通源站。
          </span>
        </div>

        <div class="field-label" style="margin-top: 24px; font-size: 15px">CC 防御</div>
        <div class="field">
          <label class="check">
            <input v-model="settings.cc_enabled" type="checkbox" />
            启用 CC 防御（按客户端聚合组限速，超限自动挑战/封禁）
          </label>
          <span class="field-hint">
            全局限流 RPS 是域名总阈值：超过后自动进入 60 秒攻击模式，客户端限额减半；HTML 浏览器首次超限
            进入 PoW 挑战，验证通过后获得临时 2x 预算，持续超限才封禁。
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
import { friendlyErrorMessage } from '~/utils/friendlyError'

const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { ask } = useConfirm()

const loading = ref(false)
const submitting = ref(false)
const domains = ref<any[]>([])
const projects = ref<any[]>([])

function projectLabel(project: any) {
  const owner = project?.owner_email || project?.owner_name || ''
  return owner ? `${project.name}（${owner}）` : project.name
}

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
  origin_sni: '',
  origin_host_header: '',
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
  sni?: string
  host_header?: string
}
const editForm = ref({
  origins: [] as OriginForm[],
  ssl_enabled: true,
})
const enabledOriginCount = computed(
  () => editForm.value.origins.filter((origin) => origin.enabled).length,
)

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
  signed_url_enabled: false,
  signed_url_mode: 'off',
  signed_url_paths: '',
  signed_url_secret: '',
  signed_url_previous_secret: '',
  signed_url_ttl_secs: 3600,
  origin_auth_header: '',
  origin_auth_value: '',
  hotlink_signature_enabled: false,
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
    origin_sni: '',
    origin_host_header: '',
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
      origin_sni: createForm.value.origin_sni.trim(),
      origin_host_header: createForm.value.origin_host_header.trim(),
    }
    if (createForm.value.project_id) body.project_id = createForm.value.project_id
    await api.post('/api/v1/domains', body)
    createOpen.value = false
    toast.success('域名已接入，等待边缘节点同步（约 15 秒）')
    await load()
  } catch (e: any) {
    const message = friendlyErrorMessage(
      e?.data?.error,
      '接入失败，请检查域名是否已存在'
    )
    createError.value = message
    toast.error(message)
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
        sni: origin.sni || '',
        host_header: origin.host_header || '',
      }))
      : [
        {
          host: d.origin_host,
          port: d.origin_port,
          proto: d.origin_proto,
          weight: 100,
          priority: 0,
          enabled: true,
          sni: '',
          host_header: '',
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
    sni: '',
    host_header: '',
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
      sni: origin.sni?.trim() || '',
      host_header: origin.host_header?.trim() || '',
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
  const primary = pool.find((origin) => origin.enabled) ?? pool[0]
  if (!primary) {
    editError.value = '至少填写一个源站主机'
    return
  }
  submitting.value = true
  try {
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
      signed_url_enabled: !!s.signed_url_enabled,
      signed_url_mode: s.signed_url_mode || (s.signed_url_enabled ? 'all' : 'off'),
      signed_url_paths: s.signed_url_paths || '',
      signed_url_secret: s.signed_url_secret || '',
      signed_url_previous_secret: s.signed_url_previous_secret || '',
      signed_url_ttl_secs: s.signed_url_ttl_secs ?? 3600,
      origin_auth_header: s.origin_auth_header || '',
      origin_auth_value: s.origin_auth_value || '',
      hotlink_signature_enabled: !!s.hotlink_signature_enabled,
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

.origin-editor {
  display: flex;
  flex-direction: column;
  gap: 10px;
  min-width: 0;
}

.origin-context {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px 9px;
  min-width: 0;
  padding: 7px 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg);
}

.origin-context-label {
  padding: 2px 7px;
  border-radius: 5px;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 11px;
  font-weight: 500;
}

.origin-context-name {
  min-width: 0;
  color: var(--text);
  font-size: 13px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.origin-context-address {
  min-width: 0;
  margin-left: auto;
  color: var(--text-3);
  font-family: var(--mono);
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.origin-editor-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.origin-intro {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  min-width: 0;
}

.origin-intro-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  flex: none;
  border-radius: 10px;
  background: var(--brand-bg);
  color: var(--brand);
}

.origin-intro-copy {
  min-width: 0;
}

.origin-title-line {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  min-height: 22px;
}

.origin-editor-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
}

.origin-count {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 20px;
  padding: 0 7px;
  border: 1px solid var(--success-border);
  border-radius: 999px;
  background: var(--success-bg);
  color: var(--success);
  font-size: 10px;
  line-height: 1;
  white-space: nowrap;
}

.origin-count-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
}

.origin-count.empty {
  border-color: var(--border);
  background: var(--bg);
  color: var(--text-3);
}

.origin-editor-sub {
  margin-top: 4px;
  color: var(--text-3);
  font-size: 12px;
  line-height: 1.6;
}

.origin-add-btn {
  flex: none;
}

.origin-list {
  display: flex;
  flex-direction: column;
  gap: 9px;
}

.origin-card {
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--card);
  overflow: hidden;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.02);
  transition: border-color 0.15s ease, box-shadow 0.15s ease, opacity 0.15s ease;
}

.origin-card:hover {
  border-color: color-mix(in srgb, var(--brand) 35%, var(--border));
  box-shadow: 0 4px 14px rgba(15, 23, 42, 0.05);
}

.origin-card.is-disabled {
  background: color-mix(in srgb, var(--card) 86%, var(--bg));
}

.origin-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 10px;
  border-bottom: 1px solid var(--divider);
  background: color-mix(in srgb, var(--brand) 2%, var(--card));
}

.origin-card.is-disabled .origin-card-head {
  background: var(--bg);
}

.origin-identity {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.origin-number {
  width: 24px;
  height: 24px;
  border: 1px solid color-mix(in srgb, var(--brand) 18%, transparent);
  border-radius: 7px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
  background: var(--brand-bg);
  color: var(--brand);
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
}

.origin-name-wrap {
  min-width: 0;
}

.origin-name {
  color: var(--text);
  font-size: 13px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.origin-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 2px;
  color: var(--text-3);
  font-size: 10px;
}

.origin-meta-separator {
  width: 1px;
  height: 9px;
  background: var(--border-strong);
}

.origin-card-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: none;
}

.origin-enable {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 7px;
  min-height: 30px;
  padding: 0 9px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--card);
  color: var(--text-2);
  font-size: 12px;
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
  transition: border-color 0.15s ease, background 0.15s ease, color 0.15s ease;
}

.origin-enable:hover {
  border-color: var(--border-strong);
}

.origin-enable.active {
  border-color: var(--success-border);
  background: var(--success-bg);
  color: var(--success);
}

.origin-enable input {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
}

.origin-enable:focus-within {
  outline: 2px solid rgba(22, 119, 255, 0.28);
  outline-offset: 2px;
}

.origin-switch {
  position: relative;
  width: 28px;
  height: 16px;
  flex: none;
  border-radius: 999px;
  background: var(--text-4);
  transition: background 0.15s ease;
}

.origin-switch::after {
  content: "";
  position: absolute;
  top: 2px;
  left: 2px;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 3px rgba(15, 23, 42, 0.24);
  transition: transform 0.15s ease;
}

.origin-enable.active .origin-switch {
  background: var(--success);
}

.origin-enable.active .origin-switch::after {
  transform: translateX(12px);
}

.origin-delete {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  height: 30px;
  padding: 0 8px;
  border: none;
  border-radius: var(--radius);
  background: transparent;
  color: var(--text-3);
  font-size: 12px;
  cursor: pointer;
  transition: background 0.15s ease, color 0.15s ease;
}

.origin-delete:hover:not(:disabled) {
  background: var(--danger-bg);
  color: var(--danger);
}

.origin-delete:focus-visible {
  outline: 2px solid rgba(22, 119, 255, 0.28);
  outline-offset: 2px;
}

.origin-delete:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.origin-card-body {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px;
}

.origin-config {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr) 86px;
  gap: 8px;
}

.origin-tuning {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
}

.origin-advanced {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.origin-subgroup {
  min-width: 0;
  padding: 12px;
  border: 1px solid var(--divider);
  border-radius: 9px;
  background: color-mix(in srgb, var(--bg) 72%, var(--card));
}

.origin-subgroup-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 10px;
}

.origin-subgroup-head>span {
  color: var(--text-2);
  font-size: 12px;
  font-weight: 600;
}

.origin-subgroup-head em {
  color: var(--text-3);
  font-style: normal;
  font-weight: 400;
}

.origin-subgroup-head small {
  color: var(--text-3);
  font-size: 10px;
  line-height: 1.4;
  text-align: right;
}

.origin-subgroup-fields {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.origin-field {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 3px;
}

.origin-field>span {
  color: var(--text-2);
  font-size: 11px;
}

.origin-field>span em {
  color: var(--text-3);
  font-style: normal;
  font-weight: 400;
}

.origin-field .input,
.origin-field .select {
  height: 32px;
  width: 100%;
  min-width: 0;
}

.origin-options {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 9px 10px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--brand) 2%, var(--card));
}

.origin-option-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  flex: none;
  border-radius: 7px;
  background: var(--brand-bg);
  color: var(--brand);
}

.origin-option-copy {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: 2px;
}

.origin-https-toggle {
  align-self: flex-start;
  min-height: 20px;
  padding: 0;
  border: none;
  background: transparent;
  color: var(--text);
  font-size: 12px;
  font-weight: 500;
}

.origin-https-toggle:hover {
  border-color: transparent;
}

.origin-https-toggle.active {
  background: transparent;
}

.origin-option-copy small {
  color: var(--text-3);
  font-size: 11px;
  line-height: 1.45;
}

.origin-help {
  display: flex;
  align-items: flex-start;
  gap: 7px;
  color: var(--text-3);
  font-size: 12px;
  line-height: 1.55;
}

.origin-help .app-icon {
  margin-top: 2px;
  color: var(--text-4);
}

.origin-error {
  margin: 0;
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

@media (max-width: 720px) {
  .origin-editor {
    gap: 12px;
  }

  .origin-context-address {
    width: 100%;
    margin-left: 0;
    padding-left: 2px;
  }

  .origin-editor-head {
    flex-direction: column;
    gap: 12px;
  }

  .origin-add-btn {
    width: 100%;
    justify-content: center;
  }

  .origin-card {
    border-radius: 10px;
  }

  .origin-card-head {
    align-items: flex-start;
    gap: 10px;
  }

  .origin-card-actions {
    gap: 4px;
  }

  .origin-enable {
    min-height: 34px;
    padding: 0 8px;
  }

  .origin-delete {
    min-width: 34px;
    min-height: 34px;
    padding: 0 6px;
  }

  .origin-delete span {
    display: none;
  }

  .origin-card-body {
    gap: 8px;
    padding: 10px;
  }

  .origin-config {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }

  .origin-host-field {
    order: -1;
    grid-column: 1 / -1;
  }

  .origin-tuning {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .origin-field .input,
  .origin-field .select {
    height: 36px;
  }

  .origin-options {
    padding: 10px;
  }
}

@media (max-width: 520px) {
  .origin-intro-icon {
    width: 32px;
    height: 32px;
  }

  .origin-card-head {
    flex-wrap: wrap;
    padding: 12px;
  }

  .origin-card-actions {
    width: 100%;
    justify-content: space-between;
  }

  .origin-delete {
    min-width: auto;
    padding: 0 8px;
  }

  .origin-delete span {
    display: inline;
  }

  .origin-subgroup-head {
    align-items: flex-start;
    flex-direction: column;
    gap: 2px;
  }

  .origin-subgroup-head small {
    text-align: left;
  }

  .origin-tls-fields {
    grid-template-columns: minmax(0, 1fr);
  }

  .origin-options {
    gap: 9px;
  }

  .origin-option-icon {
    width: 28px;
    height: 28px;
  }
}
</style>
