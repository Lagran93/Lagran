<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">WAF 防护</div>
        <div class="page-desc">
          为域名开启 Web 应用防火墙：IP 黑白名单、SQL 注入 / XSS / 路径穿越 / 扫描器检测，以及自定义规则
        </div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="reload">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
      </div>
    </div>

    <div v-if="!domains.length" class="card">
      <EmptyState
        icon="shield"
        title="还没有可配置的域名"
        text="先在「域名管理」接入域名，再回到这里为它开启 WAF 防护。"
      >
        <NuxtLink to="/domains" class="btn btn-primary btn-sm">去接入域名</NuxtLink>
      </EmptyState>
    </div>

    <template v-else>
      <div class="card waf-toolbar">
        <div class="flex-center gap-12" style="flex-wrap: wrap">
          <span class="field-label" style="margin: 0">防护域名</span>
          <select v-model="domainId" class="select" style="min-width: 240px">
            <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
          </select>
          <StatusTag :tone="settings.enabled ? 'success' : 'neutral'" dot>
            {{ settings.enabled ? '防护已开启' : '防护未开启' }}
          </StatusTag>
          <StatusTag :tone="settings.mode === 'block' ? 'danger' : 'warning'">
            {{ settings.mode === 'block' ? '拦截模式' : '观察模式' }}
          </StatusTag>
          <span class="spacer" />
          <span class="text-muted" style="font-size: 12px">
            规则变更后边缘节点约 15 秒内同步
          </span>
        </div>
      </div>

      <div class="card">
        <div class="waf-tabs">
          <button
            v-for="t in tabs"
            :key="t.value"
            type="button"
            class="waf-tab"
            :class="{ active: tab === t.value }"
            @click="switchTab(t.value)"
          >
            {{ t.label }}
            <span v-if="t.count !== undefined" class="tab-count">{{ t.count }}</span>
          </button>
        </div>

        <!-- 防护设置 -->
        <div v-if="tab === 'settings'" class="card-body">
          <div class="alert" :class="settings.mode === 'block' ? 'alert-warning' : 'alert-info'">
            <AppIcon name="shield" :size="16" class="icon" />
            <span v-if="settings.mode === 'block'">
              拦截模式会直接拒绝命中规则的请求（403 页面）。上线初期建议先用观察模式确认没有误报。
            </span>
            <span v-else>
              观察模式只记录事件、不拦截请求。确认规则准确后，再切换为拦截模式。
            </span>
          </div>

          <div class="setting-row">
            <div>
              <div class="setting-title">开启 WAF 防护</div>
              <div class="setting-desc">关闭后该域名的 IP 名单与规则全部不生效</div>
            </div>
            <label class="switch" :class="{ on: settings.enabled }">
              <span class="switch-track" />
              <input v-model="settings.enabled" type="checkbox" style="display: none" />
            </label>
          </div>

          <div class="setting-row">
            <div>
              <div class="setting-title">防护模式</div>
              <div class="setting-desc">观察模式用于灰度验证规则，拦截模式用于正式防护</div>
            </div>
            <div class="segmented">
              <button
                type="button"
                :class="{ active: settings.mode === 'monitor' }"
                @click="settings.mode = 'monitor'"
              >
                观察
              </button>
              <button
                type="button"
                :class="{ active: settings.mode === 'block' }"
                @click="settings.mode = 'block'"
              >
                拦截
              </button>
            </div>
          </div>

          <div class="section-label">托管规则</div>
          <div class="managed-grid">
            <label
              v-for="m in managedRules"
              :key="m.key"
              class="managed-item"
              :class="{ on: settings[m.key] }"
            >
              <input v-model="settings[m.key]" type="checkbox" />
              <span class="managed-info">
                <strong>{{ m.label }}</strong>
                <small>{{ m.desc }}</small>
              </span>
              <AppIcon :name="settings[m.key] ? 'check' : 'plus'" :size="15" />
            </label>
          </div>

          <div class="section-label">浏览器质询</div>
          <div class="form-grid">
            <div class="field">
              <label class="field-label">质询难度（前导 0 的十六进制位数）</label>
              <input
                v-model.number="settings.challenge_difficulty"
                class="input"
                type="number"
                min="1"
                max="6"
              />
              <span class="field-hint">1 最轻、6 最重，默认 4（约 6.5 万次哈希）。</span>
            </div>
            <div class="field">
              <label class="field-label">免质询有效期（秒）</label>
              <input
                v-model.number="settings.challenge_ttl_secs"
                class="input"
                type="number"
                min="60"
                max="86400"
              />
              <span class="field-hint">通过后签发 HttpOnly Cookie，默认 1800 秒。</span>
            </div>
          </div>
          <p class="text-muted" style="font-size: 12px; margin-top: 8px">
            规则动作选择「质询」时生效；仅对 GET/HEAD 导航返回质询页，其他方法按拦截处理。
          </p>

          <div class="flex-between mt-24">
            <span class="text-muted" style="font-size: 12px">
              托管规则基于常见攻击特征匹配 URL、查询串、UA 与 Referer，不检查请求体。
            </span>
            <button class="btn btn-primary" type="button" :disabled="saving" @click="saveSettings">
              {{ saving ? '保存中…' : '保存设置' }}
            </button>
          </div>
        </div>

        <!-- 自定义规则 -->
        <div v-else-if="tab === 'rules'" class="card-body tight">
          <div class="filter-bar">
            <span class="text-muted" style="font-size: 13px">
              按优先级从高到低匹配，命中即停止；支持拦截、放行、仅记录三种动作
            </span>
            <span class="spacer" />
            <button class="btn btn-primary btn-sm" type="button" @click="openRuleModal()">
              <AppIcon name="plus" :size="14" />
              新建规则
            </button>
          </div>

          <div v-if="rules.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>规则名称</th>
                  <th>匹配条件</th>
                  <th>动作</th>
                  <th>优先级</th>
                  <th>状态</th>
                  <th class="text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="r in rules" :key="r.id">
                  <td class="cell-main">{{ r.name }}</td>
                  <td>
                    <span class="mono">{{ fieldLabel(r.field) }} {{ opLabel(r.operator) }} {{ r.value }}</span>
                  </td>
                  <td>
                    <StatusTag :tone="actionTone(r.action)">{{ actionLabel(r.action) }}</StatusTag>
                  </td>
                  <td class="num">{{ r.priority }}</td>
                  <td>
                    <StatusTag :tone="r.enabled ? 'success' : 'neutral'" dot>
                      {{ r.enabled ? '启用' : '停用' }}
                    </StatusTag>
                  </td>
                  <td class="text-right">
                    <div class="ops" style="justify-content: flex-end">
                      <button class="btn btn-text btn-sm" type="button" @click="toggleRule(r)">
                        {{ r.enabled ? '停用' : '启用' }}
                      </button>
                      <button class="btn btn-text btn-sm" type="button" @click="openRuleModal(r)">
                        编辑
                      </button>
                      <button class="btn btn-text btn-sm danger" type="button" @click="removeRule(r)">
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState
            v-else
            icon="rules"
            title="还没有自定义规则"
            text="例如：路径前缀 /admin 且来源不属于办公网时拦截，或对 /api/ 只记录日志。"
          >
            <button class="btn btn-primary btn-sm" type="button" @click="openRuleModal()">
              新建规则
            </button>
          </EmptyState>
        </div>

        <!-- IP 黑白名单 -->
        <div v-else-if="tab === 'ips'" class="card-body tight">
          <div class="filter-bar">
            <span class="text-muted" style="font-size: 13px">
              白名单优先于所有规则；黑名单命中后直接拦截。支持 IPv4/IPv6 与 CIDR
            </span>
            <span class="spacer" />
            <button class="btn btn-primary btn-sm" type="button" @click="openIpModal('deny')">
              <AppIcon name="plus" :size="14" />
              添加 IP / 网段
            </button>
          </div>

          <div v-if="ips.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>类型</th>
                  <th>IP / 网段</th>
                  <th>备注</th>
                  <th>添加时间</th>
                  <th class="text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="ip in ips" :key="ip.id">
                  <td>
                    <StatusTag :tone="ip.kind === 'allow' ? 'success' : 'danger'">
                      {{ ip.kind === 'allow' ? '白名单' : '黑名单' }}
                    </StatusTag>
                  </td>
                  <td class="mono">{{ ip.ip }}</td>
                  <td class="text-2">{{ ip.note || '—' }}</td>
                  <td class="text-muted">{{ formatDateTime(ip.created_at) }}</td>
                  <td class="text-right">
                    <button class="btn btn-text btn-sm danger" type="button" @click="removeIp(ip)">
                      删除
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState
            v-else
            icon="shield"
            title="还没有 IP 名单"
            text="把攻击来源加入黑名单，或把办公网、监控探针加入白名单以跳过所有 WAF 检查。"
          >
            <button class="btn btn-primary btn-sm" type="button" @click="openIpModal('deny')">
              添加第一条
            </button>
          </EmptyState>
        </div>

        <!-- 事件日志 -->
        <div v-else class="card-body tight">
          <div class="filter-bar">
            <select v-model="eventAction" class="select">
              <option value="">全部动作</option>
              <option value="block">拦截</option>
              <option value="challenge">质询</option>
              <option value="monitor">观察</option>
              <option value="log">仅记录</option>
            </select>
            <select v-model.number="eventLimit" class="select">
              <option :value="50">最近 50 条</option>
              <option :value="100">最近 100 条</option>
              <option :value="200">最近 200 条</option>
            </select>
            <button class="btn btn-default" type="button" :disabled="eventsLoading" @click="loadEvents">
              查询
            </button>
            <span class="spacer" />
            <span class="text-muted" style="font-size: 13px">{{ filteredEvents.length }} 条事件</span>
          </div>

          <div v-if="filteredEvents.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>动作</th>
                  <th>类型</th>
                  <th>规则</th>
                  <th>客户端 IP</th>
                  <th>方法</th>
                  <th style="min-width: 200px">路径</th>
                  <th>节点</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="e in filteredEvents" :key="e.id">
                  <td class="text-muted nowrap">{{ formatDateTime(e.ts) }}</td>
                  <td>
                    <StatusTag :tone="eventTone(e.action)">{{ eventLabel(e.action) }}</StatusTag>
                  </td>
                  <td>{{ categoryLabel(e.category) }}</td>
                  <td class="text-2">{{ e.rule_name || '—' }}</td>
                  <td class="mono">{{ e.client_ip }}</td>
                  <td class="mono">{{ e.method }}</td>
                  <td><div class="mono path-cell" :title="e.path">{{ e.path }}</div></td>
                  <td class="text-2">{{ e.node_id }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else-if="eventsLoading" class="card-body">
            <div class="skeleton" style="height: 32px; width: 100%" />
          </div>
          <EmptyState
            v-else
            icon="activity"
            title="暂无 WAF 事件"
            text="命中规则的请求会在这里展示；观察模式下只记录不拦截。"
          />
        </div>
      </div>
    </template>

    <BaseModal
      v-model="ruleModalOpen"
      :title="editingRule ? '编辑 WAF 规则' : '新建 WAF 规则'"
      confirm-text="保存"
      :loading="saving"
      @confirm="saveRule"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">规则名称 <span class="req">*</span></label>
          <input v-model="ruleForm.name" class="input" placeholder="例如：拦截后台探测" />
        </div>
        <div class="form-grid">
          <div class="field">
            <label class="field-label">匹配字段</label>
            <select v-model="ruleForm.field" class="select">
              <option value="path">路径 Path</option>
              <option value="query">查询串 Query</option>
              <option value="user_agent">User-Agent</option>
              <option value="referer">Referer</option>
              <option value="method">请求方法</option>
              <option value="ip">客户端 IP</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">匹配方式</label>
            <select v-model="ruleForm.operator" class="select">
              <option value="contains">包含</option>
              <option value="equals">等于</option>
              <option value="prefix">前缀</option>
              <option value="suffix">后缀</option>
            </select>
          </div>
          <div class="field span-2">
            <label class="field-label">匹配内容 <span class="req">*</span></label>
            <input v-model="ruleForm.value" class="input" placeholder="例如 /admin 或 sqlmap" />
          </div>
          <div class="field">
            <label class="field-label">命中动作</label>
            <select v-model="ruleForm.action" class="select">
              <option value="block">拦截</option>
              <option value="challenge">质询（JS 验证）</option>
              <option value="allow">放行</option>
              <option value="log">仅记录</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">优先级</label>
            <input v-model.number="ruleForm.priority" class="input" type="number" />
          </div>
        </div>
        <label class="check">
          <input v-model="ruleForm.enabled" type="checkbox" />
          启用这条规则
        </label>
        <p v-if="ruleError" class="text-danger" style="font-size: 13px">{{ ruleError }}</p>
      </div>
    </BaseModal>

    <BaseModal
      v-model="ipModalOpen"
      title="添加 IP / 网段"
      confirm-text="添加"
      :loading="saving"
      @confirm="saveIp"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">名单类型</label>
          <div class="segmented">
            <button type="button" :class="{ active: ipForm.kind === 'deny' }" @click="ipForm.kind = 'deny'">
              黑名单
            </button>
            <button type="button" :class="{ active: ipForm.kind === 'allow' }" @click="ipForm.kind = 'allow'">
              白名单
            </button>
          </div>
        </div>
        <div class="field">
          <label class="field-label">IP 或 CIDR <span class="req">*</span></label>
          <input v-model="ipForm.ip" class="input" placeholder="203.0.113.10 或 10.0.0.0/8" />
        </div>
        <div class="field">
          <label class="field-label">备注</label>
          <input v-model="ipForm.note" class="input" placeholder="例如：攻击来源 / 办公网出口" />
        </div>
        <p v-if="ipError" class="text-danger" style="font-size: 13px">{{ ipError }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

type Tab = 'settings' | 'rules' | 'ips' | 'events'

const domains = ref<any[]>([])
const domainId = ref('')
const tab = ref<Tab>('settings')
const loading = ref(false)
const saving = ref(false)

const settings = ref<any>({
  enabled: false,
  mode: 'block',
  sqli: true,
  xss: true,
  traversal: true,
  scanners: true,
  challenge_difficulty: 4,
  challenge_ttl_secs: 1800,
})

const rules = ref<any[]>([])
const ips = ref<any[]>([])
const events = ref<any[]>([])
const eventsLoading = ref(false)
const eventAction = ref('')
const eventLimit = ref(100)

const ruleModalOpen = ref(false)
const editingRule = ref<any>(null)
const ruleError = ref('')
const ruleForm = ref({
  name: '',
  field: 'path',
  operator: 'contains',
  value: '',
  action: 'block',
  priority: 0,
  enabled: true,
})

const ipModalOpen = ref(false)
const ipError = ref('')
const ipForm = ref({ kind: 'deny', ip: '', note: '' })

const managedRules = [
  { key: 'sqli', label: 'SQL 注入', desc: 'union select、or 1=1、sleep() 等特征' },
  { key: 'xss', label: 'XSS 跨站脚本', desc: '\u003cscript\u003e、javascript:、onerror= 等' },
  { key: 'traversal', label: '路径穿越', desc: '路径跳转 ../、/etc/passwd 读取' },
  { key: 'scanners', label: '扫描器与敏感路径', desc: 'sqlmap/nikto UA、/.git/config 等' },
]

const tabs = computed(() => [
  { value: 'settings' as Tab, label: '防护设置' },
  { value: 'rules' as Tab, label: '自定义规则', count: rules.value.length },
  { value: 'ips' as Tab, label: 'IP 黑白名单', count: ips.value.length },
  { value: 'events' as Tab, label: '事件日志' },
])

const filteredEvents = computed(() => {
  if (!eventAction.value) return events.value
  return events.value.filter((e) => e.action === eventAction.value)
})

function fieldLabel(field: string) {
  return (
    {
      path: '路径',
      query: '查询串',
      user_agent: 'UA',
      referer: 'Referer',
      method: '方法',
      ip: 'IP',
    } as Record<string, string>
  )[field] || field
}

function opLabel(op: string) {
  return ({ contains: '包含', equals: '等于', prefix: '前缀', suffix: '后缀' } as Record<string, string>)[op] || op
}

function actionLabel(action: string) {
  return (
    { block: '拦截', allow: '放行', log: '仅记录', challenge: '质询' } as Record<string, string>
  )[action] || action
}

function actionTone(action: string) {
  if (action === 'block') return 'danger'
  if (action === 'allow') return 'success'
  return 'info'
}

function eventLabel(action: string) {
  return (
    { block: '拦截', monitor: '观察', log: '记录', challenge: '质询' } as Record<string, string>
  )[action] || action
}

function eventTone(action: string) {
  return action === 'block' ? 'danger' : action === 'monitor' ? 'warning' : 'info'
}

function categoryLabel(category: string) {
  return (
    {
      sqli: 'SQL 注入',
      xss: 'XSS',
      traversal: '路径穿越',
      scanners: '扫描器',
      ip_deny: 'IP 黑名单',
      custom: '自定义规则',
    } as Record<string, string>
  )[category] || category || '—'
}

async function loadDomains() {
  domains.value = (await api.get<any[]>('/api/v1/domains').catch(() => [])) || []
  if (!domainId.value && domains.value.length) {
    domainId.value = domains.value[0].id
  }
}

async function loadSettings() {
  if (!domainId.value) return
  try {
    const s = await api.get<any>(`/api/v1/domains/${domainId.value}/waf`)
    settings.value = {
      enabled: !!s.enabled,
      mode: s.mode === 'monitor' ? 'monitor' : 'block',
      sqli: !!s.sqli,
      xss: !!s.xss,
      traversal: !!s.traversal,
      scanners: !!s.scanners,
      challenge_difficulty: s.challenge_difficulty || 4,
      challenge_ttl_secs: s.challenge_ttl_secs || 1800,
    }
  } catch {
    settings.value = {
      enabled: false,
      mode: 'block',
      sqli: true,
      xss: true,
      traversal: true,
      scanners: true,
      challenge_difficulty: 4,
      challenge_ttl_secs: 1800,
    }
  }
}

async function loadRules() {
  if (!domainId.value) return
  rules.value = (await api.get<any[]>(`/api/v1/domains/${domainId.value}/waf/rules`).catch(() => [])) || []
}

async function loadIps() {
  if (!domainId.value) return
  ips.value = (await api.get<any[]>(`/api/v1/domains/${domainId.value}/waf/ips`).catch(() => [])) || []
}

async function loadEvents() {
  if (!domainId.value) return
  eventsLoading.value = true
  try {
    const q = new URLSearchParams({
      domain: domains.value.find((d) => d.id === domainId.value)?.name || '',
      limit: String(eventLimit.value),
    })
    events.value = (await api.get<any[]>(`/api/v1/waf/events?${q.toString()}`)) || []
  } catch {
    events.value = []
  } finally {
    eventsLoading.value = false
  }
}

async function reload() {
  loading.value = true
  try {
    await loadDomains()
    await Promise.all([loadSettings(), loadRules(), loadIps()])
    if (tab.value === 'events') await loadEvents()
  } finally {
    loading.value = false
  }
}

async function switchTab(next: Tab) {
  tab.value = next
  if (next === 'events') await loadEvents()
  if (next === 'rules') await loadRules()
  if (next === 'ips') await loadIps()
  if (next === 'settings') await loadSettings()
}

async function saveSettings() {
  if (!domainId.value) return
  saving.value = true
  try {
    const s = await api.put<any>(`/api/v1/domains/${domainId.value}/waf`, settings.value)
    settings.value = {
      enabled: !!s.enabled,
      mode: s.mode === 'monitor' ? 'monitor' : 'block',
      sqli: !!s.sqli,
      xss: !!s.xss,
      traversal: !!s.traversal,
      scanners: !!s.scanners,
      challenge_difficulty: s.challenge_difficulty || 4,
      challenge_ttl_secs: s.challenge_ttl_secs || 1800,
    }
    toast.success('WAF 设置已保存，边缘约 15 秒内同步')
  } catch (e: any) {
    toast.error(e?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}

function openRuleModal(rule?: any) {
  ruleError.value = ''
  editingRule.value = rule || null
  ruleForm.value = rule
    ? {
        name: rule.name,
        field: rule.field,
        operator: rule.operator,
        value: rule.value,
        action: rule.action,
        priority: rule.priority,
        enabled: rule.enabled,
      }
    : {
        name: '',
        field: 'path',
        operator: 'contains',
        value: '',
        action: 'block',
        priority: 0,
        enabled: true,
      }
  ruleModalOpen.value = true
}

async function saveRule() {
  ruleError.value = ''
  if (!ruleForm.value.name.trim() || !ruleForm.value.value.trim()) {
    ruleError.value = '请填写规则名称与匹配内容'
    return
  }
  saving.value = true
  try {
    if (editingRule.value) {
      await api.put(`/api/v1/waf/rules/${editingRule.value.id}`, ruleForm.value)
      toast.success('规则已更新')
    } else {
      await api.post(`/api/v1/domains/${domainId.value}/waf/rules`, ruleForm.value)
      toast.success('规则已创建')
    }
    ruleModalOpen.value = false
    await loadRules()
  } catch (e: any) {
    ruleError.value = e?.data?.error || '保存失败'
  } finally {
    saving.value = false
  }
}

async function toggleRule(rule: any) {
  try {
    await api.put(`/api/v1/waf/rules/${rule.id}`, {
      name: rule.name,
      field: rule.field,
      operator: rule.operator,
      value: rule.value,
      action: rule.action,
      priority: rule.priority,
      enabled: !rule.enabled,
    })
    await loadRules()
  } catch (e: any) {
    toast.error(e?.data?.error || '更新失败')
  }
}

async function removeRule(rule: any) {
  const ok = await ask({
    title: '删除 WAF 规则',
    message: `确认删除「${rule.name}」？删除后立即生效（边缘约 15 秒内同步）。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/waf/rules/${rule.id}`)
    toast.success('规则已删除')
    await loadRules()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

function openIpModal(kind: 'allow' | 'deny') {
  ipError.value = ''
  ipForm.value = { kind, ip: '', note: '' }
  ipModalOpen.value = true
}

async function saveIp() {
  ipError.value = ''
  if (!ipForm.value.ip.trim()) {
    ipError.value = '请填写 IP 或 CIDR'
    return
  }
  saving.value = true
  try {
    await api.post(`/api/v1/domains/${domainId.value}/waf/ips`, ipForm.value)
    ipModalOpen.value = false
    toast.success('IP 名单已添加')
    await loadIps()
  } catch (e: any) {
    ipError.value = e?.data?.error || '添加失败，请检查 IP 格式'
  } finally {
    saving.value = false
  }
}

async function removeIp(ip: any) {
  const ok = await ask({
    title: '删除 IP 名单',
    message: `确认删除 ${ip.ip}（${ip.kind === 'allow' ? '白名单' : '黑名单'}）？`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/waf/ips/${ip.id}`)
    toast.success('已删除')
    await loadIps()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

watch(domainId, async (id) => {
  if (!id) return
  loading.value = true
  try {
    await Promise.all([loadSettings(), loadRules(), loadIps()])
    if (tab.value === 'events') await loadEvents()
  } finally {
    loading.value = false
  }
})

watch([eventAction, eventLimit], () => {
  if (tab.value === 'events') loadEvents()
})

onMounted(reload)
</script>

<style scoped>
.waf-toolbar {
  padding: 14px 18px;
  margin-bottom: 16px;
}

.waf-tabs {
  display: flex;
  gap: 4px;
  padding: 0 18px;
  border-bottom: 1px solid var(--divider);
  overflow-x: auto;
}

.waf-tab {
  position: relative;
  border: none;
  background: transparent;
  padding: 14px 12px 12px;
  font-size: 14px;
  color: var(--text-2);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  white-space: nowrap;
}

.waf-tab:hover {
  color: var(--brand);
}

.waf-tab.active {
  color: var(--brand);
  font-weight: 500;
  border-bottom-color: var(--brand);
}

.tab-count {
  margin-left: 4px;
  font-size: 11px;
  color: var(--text-3);
}

.setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 14px 0;
  border-bottom: 1px solid var(--divider);
}

.setting-title {
  font-size: 14px;
  color: var(--text);
}

.setting-desc {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-3);
}

.section-label {
  margin: 20px 0 10px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-2);
}

.managed-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.managed-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
  transition: all 0.15s ease;
}

.managed-item.on {
  border-color: #bedaff;
  background: #f7faff;
}

.managed-item input {
  margin-top: 3px;
  accent-color: var(--brand);
}

.managed-info {
  flex: 1;
  min-width: 0;
}

.managed-info strong {
  display: block;
  font-size: 13.5px;
  font-weight: 500;
  color: var(--text);
}

.managed-info small {
  display: block;
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-3);
  line-height: 1.5;
}

.managed-item .app-icon {
  color: var(--text-4);
}

.managed-item.on .app-icon {
  color: var(--brand);
}

@media (max-width: 900px) {
  .managed-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
