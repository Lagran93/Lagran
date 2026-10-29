<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">告警中心</div>
        <div class="page-desc">源站、证书、节点、缓存命中率与 WAF 异常告警，支持邮件、Webhook 和 Telegram 通知</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button
          v-if="tab === 'rules'"
          class="btn btn-primary"
          type="button"
          @click="openCreateRule"
        >
          <AppIcon name="plus" :size="15" />
          新建规则
        </button>
        <button
          v-else-if="tab === 'channels'"
          class="btn btn-primary"
          type="button"
          @click="openCreateChannel"
        >
          <AppIcon name="plus" :size="15" />
          添加渠道
        </button>
      </div>
    </div>

    <div class="stat-grid">
        <StatCard label="正在告警" :value="summary.firing" icon="alert" tone="red" />
        <StatCard label="已恢复" :value="summary.resolved" icon="check" tone="green" />
        <StatCard label="告警规则" :value="rules.length" icon="rules" />
        <StatCard label="通知渠道" :value="channels.filter((c) => c.enabled).length" icon="activity" tone="green" />
      </div>

      <div class="card">
        <div class="tabs">
          <button
            v-for="t in tabs"
            :key="t.value"
            type="button"
            class="tab"
            :class="{ active: tab === t.value }"
            @click="tab = t.value"
          >
            {{ t.label }}
            <span v-if="t.count !== undefined" class="tab-count">{{ t.count }}</span>
          </button>
        </div>

        <!-- rules -->
        <div v-if="tab === 'rules'" class="card-body tight">
          <div v-if="rules.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>规则</th>
                  <th>触发条件</th>
                  <th>通知渠道</th>
                  <th>状态</th>
                  <th>最近触发</th>
                  <th class="text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="rule in rules" :key="rule.id">
                  <td>
                    <div class="cell-main">{{ rule.name }}</div>
                    <div class="cell-sub">{{ metricLabel(rule.metric) }}</div>
                  </td>
                  <td>
                    <div>{{ conditionText(rule) }}</div>
                    <div v-if="usesWindow(rule.metric)" class="cell-sub">
                      统计窗口 {{ rule.window_minutes }} 分钟
                    </div>
                  </td>
                  <td>
                    <div class="channel-tags">
                      <span
                        v-for="id in rule.channel_ids"
                        :key="id"
                        class="tag tag-neutral"
                      >
                        {{ channelName(id) }}
                      </span>
                      <span v-if="!rule.channel_ids.length" class="text-muted">未绑定</span>
                    </div>
                  </td>
                  <td>
                    <StatusTag :tone="rule.enabled ? 'success' : 'neutral'" dot>
                      {{ rule.enabled ? '启用' : '停用' }}
                    </StatusTag>
                  </td>
                  <td class="text-2">{{ rule.last_triggered_at ? fromNow(rule.last_triggered_at) : '—' }}</td>
                  <td class="text-right">
                    <button class="btn btn-text btn-sm" type="button" @click="openEditRule(rule)">编辑</button>
                    <button class="btn btn-text btn-sm danger" type="button" @click="removeRule(rule)">删除</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState
            v-else
            icon="alert"
            title="还没有告警规则"
            text="创建规则后，控制面会定期评估源站健康、证书、节点、缓存和 WAF 指标。"
          >
            <button class="btn btn-primary btn-sm" type="button" @click="openCreateRule">新建规则</button>
          </EmptyState>
        </div>

        <!-- channels -->
        <div v-else-if="tab === 'channels'" class="card-body">
          <div v-if="channels.length" class="channel-grid">
            <div v-for="channel in channels" :key="channel.id" class="channel-card">
              <div class="channel-head">
                <div class="channel-icon" :class="channel.kind">
                  <AppIcon :name="channel.kind === 'email' ? 'logs' : channel.kind === 'telegram' ? 'external' : 'activity'" :size="18" />
                </div>
                <div class="flex-1" style="min-width: 0">
                  <div class="cell-main truncate">{{ channel.name }}</div>
                  <div class="cell-sub">{{ kindLabel(channel.kind) }}</div>
                </div>
                <StatusTag :tone="channel.enabled ? 'success' : 'neutral'" dot>
                  {{ channel.enabled ? '启用' : '停用' }}
                </StatusTag>
              </div>
              <div class="channel-target text-2">
                {{ channelTarget(channel) }}
              </div>
              <div class="channel-actions">
                <button class="btn btn-text btn-sm" type="button" :disabled="testing === channel.id" @click="testChannel(channel)">
                  {{ testing === channel.id ? '发送中…' : '发送测试' }}
                </button>
                <button class="btn btn-text btn-sm" type="button" @click="openEditChannel(channel)">编辑</button>
                <button class="btn btn-text btn-sm danger" type="button" @click="removeChannel(channel)">删除</button>
              </div>
            </div>
          </div>
          <EmptyState
            v-else
            icon="activity"
            title="还没有通知渠道"
            text="添加邮件、Webhook 或 Telegram 渠道后，告警触发时会自动通知。"
          >
            <button class="btn btn-primary btn-sm" type="button" @click="openCreateChannel">添加渠道</button>
          </EmptyState>
        </div>

        <!-- events -->
        <div v-else class="card-body tight">
          <div v-if="events.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>规则</th>
                  <th>对象</th>
                  <th>状态</th>
                  <th style="min-width: 260px">详情</th>
                  <th>通知</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="event in pagedEvents" :key="event.id">
                  <td class="text-2">{{ formatDateTime(event.started_at) }}</td>
                  <td>
                    <div class="cell-main">{{ event.rule_name }}</div>
                    <div class="cell-sub">{{ severityLabel(event.severity) }}</div>
                  </td>
                  <td class="mono text-2">{{ event.fingerprint }}</td>
                  <td>
                    <StatusTag :tone="event.status === 'firing' ? 'danger' : 'success'" dot>
                      {{ event.status === 'firing' ? '告警中' : '已恢复' }}
                    </StatusTag>
                  </td>
                  <td>
                    <div class="event-message">{{ event.message }}</div>
                  </td>
                  <td>
                    <StatusTag :tone="event.notified ? 'success' : 'neutral'">
                      {{ event.notified ? '已发送' : '未发送' }}
                    </StatusTag>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState v-else icon="clock" title="暂无告警事件" text="规则触发后会在这里留下记录。" />
          <div v-if="events.length > pageSize" class="table-footer">
            <AppPagination v-model:page="page" :total="events.length" :page-size="pageSize" unit="条" />
          </div>
        </div>
      </div>

    <!-- rule modal -->
    <BaseModal
      v-model="ruleOpen"
      :title="ruleEditing ? '编辑告警规则' : '新建告警规则'"
      width="680px"
      confirm-text="保存"
      :loading="saving"
      @confirm="saveRule"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">规则名称 <span class="req">*</span></label>
          <input v-model="ruleForm.name" class="input" placeholder="例如 核心源站健康异常" />
        </div>
        <div class="form-grid">
          <div class="field">
            <label class="field-label">监控指标</label>
            <select v-model="ruleForm.metric" class="select" @change="onMetricChange">
              <option v-for="m in metricOptions" :key="m.value" :value="m.value">{{ m.label }}</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">{{ thresholdLabel }} <span class="req">*</span></label>
            <input v-model.number="ruleForm.threshold" class="input" type="number" step="0.1" />
            <span class="field-hint">{{ thresholdHint }}</span>
          </div>
          <div v-if="usesWindow(ruleForm.metric)" class="field">
            <label class="field-label">统计窗口（分钟）</label>
            <input v-model.number="ruleForm.window_minutes" class="input" type="number" min="1" max="1440" />
          </div>
          <div class="field">
            <label class="field-label">冷却时间（秒）</label>
            <input v-model.number="ruleForm.cooldown_seconds" class="input" type="number" min="0" />
          </div>
        </div>
        <div class="field">
          <label class="field-label">通知渠道</label>
          <div v-if="channels.length" class="channel-select">
            <label v-for="channel in channels" :key="channel.id" class="check">
              <input v-model="ruleForm.channel_ids" type="checkbox" :value="channel.id" />
              {{ channel.name }}
              <span class="text-muted">（{{ kindLabel(channel.kind) }}）</span>
            </label>
          </div>
          <span v-else class="field-hint">还没有通知渠道，可先在“通知渠道”中添加。</span>
        </div>
        <label class="check">
          <input v-model="ruleForm.enabled" type="checkbox" />
          启用此规则
        </label>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>

    <!-- channel modal -->
    <BaseModal
      v-model="channelOpen"
      :title="channelEditing ? '编辑通知渠道' : '添加通知渠道'"
      width="680px"
      confirm-text="保存"
      :loading="saving"
      @confirm="saveChannel"
    >
      <div class="form-col">
        <div class="form-grid">
          <div class="field">
            <label class="field-label">渠道名称 <span class="req">*</span></label>
            <input v-model="channelForm.name" class="input" placeholder="例如 运维告警群" />
          </div>
          <div class="field">
            <label class="field-label">渠道类型</label>
            <select v-model="channelForm.kind" class="select">
              <option value="webhook">Webhook</option>
              <option value="telegram">Telegram</option>
              <option value="email">邮件 SMTP</option>
            </select>
          </div>
        </div>

        <template v-if="channelForm.kind === 'webhook'">
          <div class="field">
            <label class="field-label">Webhook 地址 <span class="req">*</span></label>
            <input v-model="channelForm.webhook_url" class="input" placeholder="https://example.com/hooks/lagran" />
          </div>
          <div class="field">
            <label class="field-label">签名密钥（可选）</label>
            <input v-model="channelForm.webhook_secret" class="input" placeholder="用于 X-Lagran-Signature-256" />
            <span class="field-hint">请求体使用 HMAC-SHA256 签名，值为 sha256=&lt;hex&gt;。</span>
          </div>
        </template>

        <template v-else-if="channelForm.kind === 'telegram'">
          <div class="field">
            <label class="field-label">Bot Token <span class="req">*</span></label>
            <input v-model="channelForm.telegram_bot_token" class="input" placeholder="123456:ABC..." />
          </div>
          <div class="field">
            <label class="field-label">Chat ID <span class="req">*</span></label>
            <input v-model="channelForm.telegram_chat_id" class="input" placeholder="-1001234567890" />
          </div>
          <div class="field">
            <label class="field-label">API 地址（可选）</label>
            <input
              v-model="channelForm.telegram_api_base"
              class="input"
              placeholder="默认 https://api.telegram.org"
            />
            <span class="field-hint">如果服务器无法直连 Telegram，可填写自建反向代理或中转地址。</span>
          </div>
          <div class="field">
            <label class="field-label">代理（可选）</label>
            <input
              v-model="channelForm.telegram_proxy"
              class="input"
              placeholder="http://127.0.0.1:7890 或 socks5://127.0.0.1:1080"
            />
            <span class="field-hint">留空时自动读取 HTTPS_PROXY / ALL_PROXY 环境变量。</span>
          </div>
        </template>

        <template v-else>
          <div class="form-grid">
            <div class="field">
              <label class="field-label">SMTP 主机 <span class="req">*</span></label>
              <input v-model="channelForm.email_host" class="input" placeholder="smtp.example.com" />
            </div>
            <div class="field">
              <label class="field-label">端口</label>
              <input v-model.number="channelForm.email_port" class="input" type="number" />
            </div>
            <div class="field">
              <label class="field-label">加密方式</label>
              <select v-model="channelForm.email_tls" class="select">
                <option value="starttls">STARTTLS（587）</option>
                <option value="implicit">SSL / TLS（465）</option>
                <option value="none">不加密（仅内网）</option>
              </select>
            </div>
            <div class="field">
              <label class="field-label">发件人 <span class="req">*</span></label>
              <input v-model="channelForm.email_from" class="input" placeholder="Lagran <alert@example.com>" />
            </div>
            <div class="field">
              <label class="field-label">用户名</label>
              <input v-model="channelForm.email_username" class="input" />
            </div>
            <div class="field">
              <label class="field-label">密码</label>
              <input v-model="channelForm.email_password" class="input" type="password" placeholder="留空表示不修改" />
            </div>
            <div class="field span-2">
              <label class="field-label">收件人 <span class="req">*</span></label>
              <input v-model="channelForm.email_to" class="input" placeholder="ops@example.com, oncall@example.com" />
            </div>
          </div>
        </template>

        <label class="check">
          <input v-model="channelForm.enabled" type="checkbox" />
          启用此渠道
        </label>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { ask } = useConfirm()

const tabs = [
  { label: '告警规则', value: 'rules' as const },
  { label: '通知渠道', value: 'channels' as const },
  { label: '告警事件', value: 'events' as const },
]
const tab = ref<'rules' | 'channels' | 'events'>('rules')
const loading = ref(false)
const saving = ref(false)
const testing = ref('')
const error = ref('')

const rules = ref<any[]>([])
const channels = ref<any[]>([])
const events = ref<any[]>([])
const summary = ref({ firing: 0, resolved: 0, total: 0 })
const page = ref(1)
const pageSize = 10

const pagedEvents = computed(() => {
  const start = (page.value - 1) * pageSize
  return events.value.slice(start, start + pageSize)
})

const metricOptions = computed(() =>
  [
    { value: 'origin_unhealthy', label: '源站健康异常' },
    { value: 'cert_expiring', label: '证书即将到期' },
    { value: 'node_offline', label: '边缘节点离线' },
    { value: 'cache_hit_ratio', label: '缓存命中率过低' },
    { value: 'waf_spike', label: 'WAF 事件突增' },
  ].filter((m) => auth.isAdmin || m.value !== 'node_offline'),
)

const ruleOpen = ref(false)
const ruleEditing = ref<any>(null)
const ruleForm = ref({
  name: '',
  metric: 'origin_unhealthy',
  threshold: 3,
  window_minutes: 5,
  channel_ids: [] as string[],
  enabled: true,
  cooldown_seconds: 900,
})

const channelOpen = ref(false)
const channelEditing = ref<any>(null)
const channelForm = ref({
  name: '',
  kind: 'webhook',
  enabled: true,
  webhook_url: '',
  webhook_secret: '',
  telegram_bot_token: '',
  telegram_chat_id: '',
  telegram_api_base: '',
  telegram_proxy: '',
  email_host: '',
  email_port: 587,
  email_tls: 'starttls',
  email_from: '',
  email_username: '',
  email_password: '',
  email_to: '',
})

const thresholdLabel = computed(() => {
  switch (ruleForm.value.metric) {
    case 'cert_expiring':
      return '剩余天数阈值'
    case 'node_offline':
      return '离线分钟阈值'
    case 'cache_hit_ratio':
      return '命中率下限（%）'
    case 'waf_spike':
      return '事件数阈值'
    default:
      return '连续失败次数'
  }
})

const thresholdHint = computed(() => {
  switch (ruleForm.value.metric) {
    case 'cert_expiring':
      return '证书剩余时间小于该值时告警'
    case 'node_offline':
      return '节点离线超过该分钟数时告警'
    case 'cache_hit_ratio':
      return '命中率低于该百分比时告警'
    case 'waf_spike':
      return '窗口内 WAF 事件数达到该值时告警'
    default:
      return '源站连续失败达到该次数时告警'
  }
})

function usesWindow(metric: string) {
  return metric === 'cache_hit_ratio' || metric === 'waf_spike'
}

function metricLabel(metric: string) {
  return metricOptions.value.find((m) => m.value === metric)?.label || metric
}

function kindLabel(kind: string) {
  return { email: '邮件', webhook: 'Webhook', telegram: 'Telegram' }[kind] || kind
}

function severityLabel(value: string) {
  return value === 'critical' ? '严重' : '警告'
}

function conditionText(rule: any) {
  switch (rule.metric) {
    case 'cert_expiring':
      return `证书剩余 ≤ ${rule.threshold} 天`
    case 'node_offline':
      return `节点离线 ≥ ${rule.threshold} 分钟`
    case 'cache_hit_ratio':
      return `命中率 < ${rule.threshold}%`
    case 'waf_spike':
      return `WAF 事件 ≥ ${rule.threshold}`
    default:
      return `连续失败 ≥ ${rule.threshold} 次`
  }
}

function channelName(id: string) {
  return channels.value.find((c) => c.id === id)?.name || '已删除渠道'
}

function channelTarget(channel: any) {
  if (channel.kind === 'webhook') return channel.config?.url || '未配置地址'
  if (channel.kind === 'telegram') return `Chat ID: ${channel.config?.chat_id || '—'}`
  const to = channel.config?.to
  return `${channel.config?.smtp_host || '—'} → ${Array.isArray(to) ? to.join(', ') : '—'}`
}

function formatDateTime(value: string) {
  if (!value) return '—'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function fromNow(value: string) {
  const diff = Date.now() - new Date(value).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return '刚刚'
  if (mins < 60) return `${mins} 分钟前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours} 小时前`
  return formatDateTime(value)
}

async function load() {
  loading.value = true
  try {
    const [r, c, e, s] = await Promise.all([
      api.get<any[]>('/api/v1/alert-rules').catch(() => []),
      api.get<any[]>('/api/v1/alert-channels').catch(() => []),
      api.get<any[]>('/api/v1/alert-events?limit=200').catch(() => []),
      api.get<any>('/api/v1/alerts/summary').catch(() => ({ firing: 0, resolved: 0, total: 0 })),
    ])
    rules.value = r || []
    channels.value = c || []
    events.value = e || []
    summary.value = s || { firing: 0, resolved: 0, total: 0 }
    page.value = Math.min(page.value, Math.max(1, Math.ceil(events.value.length / pageSize)))
  } finally {
    loading.value = false
  }
}

function onMetricChange() {
  ruleForm.value.window_minutes = usesWindow(ruleForm.value.metric) ? 15 : 5
}

function openCreateRule() {
  error.value = ''
  ruleEditing.value = null
  ruleForm.value = {
    name: '',
    metric: 'origin_unhealthy',
    threshold: 3,
    window_minutes: 5,
    channel_ids: [],
    enabled: true,
    cooldown_seconds: 900,
  }
  ruleOpen.value = true
}

function openEditRule(rule: any) {
  error.value = ''
  ruleEditing.value = rule
  ruleForm.value = {
    name: rule.name,
    metric: rule.metric,
    threshold: rule.threshold,
    window_minutes: rule.window_minutes || 5,
    channel_ids: [...(rule.channel_ids || [])],
    enabled: !!rule.enabled,
    cooldown_seconds: rule.cooldown_seconds ?? 900,
  }
  ruleOpen.value = true
}

async function saveRule() {
  error.value = ''
  if (!ruleForm.value.name.trim()) {
    error.value = '请填写规则名称'
    return
  }
  saving.value = true
  try {
    const body = {
      ...ruleForm.value,
      name: ruleForm.value.name.trim(),
      window_minutes: Math.max(1, Number(ruleForm.value.window_minutes) || 5),
      cooldown_seconds: Math.max(0, Number(ruleForm.value.cooldown_seconds) || 0),
    }
    if (ruleEditing.value) {
      await api.put(`/api/v1/alert-rules/${ruleEditing.value.id}`, body)
    } else {
      await api.post('/api/v1/alert-rules', body)
    }
    ruleOpen.value = false
    toast.success('告警规则已保存')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '保存失败'
  } finally {
    saving.value = false
  }
}

async function removeRule(rule: any) {
  const ok = await ask({
    title: '删除告警规则',
    message: `确认删除「${rule.name}」？历史告警事件会保留。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/alert-rules/${rule.id}`)
    toast.success('规则已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

function resetChannelForm() {
  channelForm.value = {
    name: '',
    kind: 'webhook',
    enabled: true,
    webhook_url: '',
    webhook_secret: '',
    telegram_bot_token: '',
    telegram_chat_id: '',
    telegram_api_base: '',
    telegram_proxy: '',
    email_host: '',
    email_port: 587,
    email_tls: 'starttls',
    email_from: '',
    email_username: '',
    email_password: '',
    email_to: '',
  }
}

function openCreateChannel() {
  error.value = ''
  channelEditing.value = null
  resetChannelForm()
  channelOpen.value = true
}

function openEditChannel(channel: any) {
  error.value = ''
  channelEditing.value = channel
  resetChannelForm()
  channelForm.value.name = channel.name
  channelForm.value.kind = channel.kind
  channelForm.value.enabled = !!channel.enabled
  const cfg = channel.config || {}
  if (channel.kind === 'webhook') {
    channelForm.value.webhook_url = cfg.url || ''
    channelForm.value.webhook_secret = cfg.secret || ''
  } else if (channel.kind === 'telegram') {
    channelForm.value.telegram_bot_token = cfg.bot_token || ''
    channelForm.value.telegram_chat_id = cfg.chat_id || ''
    channelForm.value.telegram_api_base = cfg.api_base || ''
    channelForm.value.telegram_proxy = cfg.proxy || ''
  } else {
    channelForm.value.email_host = cfg.smtp_host || ''
    channelForm.value.email_port = cfg.smtp_port || 587
    channelForm.value.email_tls = cfg.tls || 'starttls'
    channelForm.value.email_from = cfg.from || ''
    channelForm.value.email_username = cfg.username || ''
    channelForm.value.email_password = cfg.password || ''
    channelForm.value.email_to = Array.isArray(cfg.to) ? cfg.to.join(', ') : ''
  }
  channelOpen.value = true
}

async function saveChannel() {
  error.value = ''
  if (!channelForm.value.name.trim()) {
    error.value = '请填写渠道名称'
    return
  }
  let config: any
  if (channelForm.value.kind === 'webhook') {
    config = { url: channelForm.value.webhook_url.trim(), secret: channelForm.value.webhook_secret }
  } else if (channelForm.value.kind === 'telegram') {
    config = {
      bot_token: channelForm.value.telegram_bot_token.trim(),
      chat_id: channelForm.value.telegram_chat_id.trim(),
      api_base: channelForm.value.telegram_api_base.trim(),
      proxy: channelForm.value.telegram_proxy.trim(),
    }
  } else {
    config = {
      smtp_host: channelForm.value.email_host.trim(),
      smtp_port: Number(channelForm.value.email_port) || 587,
      tls: channelForm.value.email_tls,
      from: channelForm.value.email_from.trim(),
      username: channelForm.value.email_username.trim(),
      password: channelForm.value.email_password,
      to: channelForm.value.email_to
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    }
  }
  saving.value = true
  try {
    const body = {
      name: channelForm.value.name.trim(),
      kind: channelForm.value.kind,
      config,
      enabled: channelForm.value.enabled,
    }
    if (channelEditing.value) {
      await api.put(`/api/v1/alert-channels/${channelEditing.value.id}`, body)
    } else {
      await api.post('/api/v1/alert-channels', body)
    }
    channelOpen.value = false
    toast.success('通知渠道已保存')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '保存失败'
  } finally {
    saving.value = false
  }
}

async function testChannel(channel: any) {
  testing.value = channel.id
  try {
    const res = await api.post<any>(`/api/v1/alert-channels/${channel.id}/test`)
    if (res.success) toast.success(res.message || '测试通知已发送')
    else toast.error(res.message || '测试通知发送失败')
  } catch (e: any) {
    toast.error(e?.data?.error || '测试通知发送失败')
  } finally {
    testing.value = ''
  }
}

async function removeChannel(channel: any) {
  const ok = await ask({
    title: '删除通知渠道',
    message: `确认删除「${channel.name}」？引用该渠道的规则会跳过它。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/alert-channels/${channel.id}`)
    toast.success('通知渠道已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

watch(tab, () => {
  page.value = 1
})

onMounted(load)
</script>

<style scoped>
.tabs {
  display: flex;
  gap: 4px;
  padding: 0 16px;
  border-bottom: 1px solid var(--divider);
}

.tab {
  border: 0;
  background: transparent;
  padding: 13px 10px;
  font-size: 14px;
  color: var(--text-3);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.tab.active {
  color: var(--brand);
  border-bottom-color: var(--brand);
  font-weight: 500;
}

.tab-count {
  font-size: 11px;
  background: var(--brand-bg);
  color: var(--brand);
  border-radius: 8px;
  padding: 0 6px;
}

.channel-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.channel-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 14px;
}

.channel-card {
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.channel-head {
  display: flex;
  align-items: center;
  gap: 10px;
}

.channel-icon {
  width: 36px;
  height: 36px;
  border-radius: 9px;
  display: grid;
  place-items: center;
  background: var(--brand-bg);
  color: var(--brand);
  flex: none;
}

.channel-icon.email {
  background: var(--warning-bg);
  color: var(--warning);
}

.channel-icon.telegram {
  background: var(--success-bg);
  color: var(--success);
}

.channel-target {
  font-size: 12px;
  word-break: break-all;
  min-height: 20px;
}

.channel-actions {
  display: flex;
  gap: 2px;
  border-top: 1px solid var(--divider);
  padding-top: 8px;
}

.channel-select {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 10px 12px;
}

.event-message {
  white-space: pre-wrap;
  font-size: 12.5px;
  color: var(--text-2);
  max-width: 420px;
}

@media (max-width: 640px) {
  .tabs {
    padding: 0 8px;
    overflow-x: auto;
  }

  .tab {
    white-space: nowrap;
  }

  .channel-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .event-message {
    max-width: 260px;
  }
}
</style>
