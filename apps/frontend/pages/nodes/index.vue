<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">边缘节点</div>
        <div class="page-desc">
          预注册节点、生成安装命令、启停与下线；节点每 15 秒上报心跳，60 秒无心跳记为离线
        </div>
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
        <button class="btn btn-default" type="button" @click="openSchedule">
          <AppIcon name="globe" :size="15" />
          调度测试
        </button>
        <button class="btn btn-default" type="button" @click="openDnsTest">
          <AppIcon name="search" :size="15" />
          DNS 测试
        </button>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          添加节点
        </button>
      </div>
    </div>

    <div class="stat-grid">
      <StatCard label="节点总数" :value="nodes.length" icon="node" />
      <StatCard label="在线节点" :value="counts.online" icon="activity" tone="green" />
      <StatCard
        label="待接入 / 离线"
        :value="counts.pending + counts.offline"
        hint="安装后等待首次心跳"
        icon="clock"
        tone="orange"
      />
      <StatCard label="已停用" :value="counts.disabled" icon="alert" tone="red" />
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">节点列表</div>
          <div class="card-desc">停用后节点立即停止代理流量，但仍保留心跳与管理接口</div>
        </div>
        <div class="card-extra text-muted" style="font-size: 12px">
          {{ lastUpdated ? `更新于 ${lastUpdated}` : '' }}
        </div>
      </div>

      <div v-if="nodes.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="min-width: 190px">节点</th>
              <th>区域 / 线路</th>
              <th>状态</th>
              <th class="num">版本</th>
              <th style="min-width: 150px">资源</th>
              <th style="min-width: 190px">Agent 地址</th>
              <th style="min-width: 140px">最后心跳</th>
              <th style="min-width: 230px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="n in nodes" :key="n.id">
              <td>
                <div class="cell-main">{{ n.name }}</div>
                <div class="cell-sub mono">{{ n.id.slice(0, 8) }}</div>
              </td>
              <td>
                <div>{{ n.region || '默认区域' }}</div>
                <div class="cell-sub">
                  {{ [n.province, n.city, n.isp].filter(Boolean).join(' · ') || '未设置线路' }}
                </div>
                <div class="cell-sub mono">{{ n.public_ip || '未设置公网 IP' }}</div>
              </td>
              <td>
                <StatusTag :tone="statusTone(n.status)" dot>
                  {{ statusLabel(n.status) }}
                </StatusTag>
              </td>
              <td class="num text-2">{{ n.version || '—' }}</td>
              <td>
                <div class="resource">
                  <span class="res-label">CPU</span>
                  <div class="progress res-bar">
                    <div
                      class="progress-bar"
                      :style="{ width: `${n.cpu_usage ?? 0}%`, background: usageColor(n.cpu_usage) }"
                    />
                  </div>
                  <span class="res-val">{{ n.cpu_usage != null ? `${n.cpu_usage.toFixed(0)}%` : '—' }}</span>
                </div>
                <div class="resource">
                  <span class="res-label">MEM</span>
                  <div class="progress res-bar">
                    <div
                      class="progress-bar"
                      :style="{ width: `${n.memory_usage ?? 0}%`, background: usageColor(n.memory_usage) }"
                    />
                  </div>
                  <span class="res-val">{{ n.memory_usage != null ? `${n.memory_usage.toFixed(0)}%` : '—' }}</span>
                </div>
              </td>
              <td>
                <span class="mono text-2">{{ n.agent_url || '—' }}</span>
              </td>
              <td>
                <div>{{ fromNow(n.last_heartbeat) }}</div>
                <div class="cell-sub">{{ formatDateTime(n.last_heartbeat) }}</div>
              </td>
              <td>
                <div class="ops">
                  <button class="btn btn-text btn-sm" type="button" @click="openDetail(n)">
                    详情
                  </button>
                  <button class="btn btn-text btn-sm" type="button" @click="openEdit(n)">
                    编辑
                  </button>
                  <button class="btn btn-text btn-sm" type="button" @click="toggle(n)">
                    {{ n.status === 'disabled' ? '启用' : '停用' }}
                  </button>
                  <button class="btn btn-text btn-sm danger" type="button" @click="remove(n)">
                    删除
                  </button>
                </div>
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
        text="点击「添加节点」预注册一个节点，控制台会生成带一次性令牌的安装命令；在服务器上运行后约 15 秒出现在列表里。"
      >
        <button class="btn btn-primary btn-sm" type="button" @click="openCreate">
          添加第一个节点
        </button>
      </EmptyState>
    </div>

    <!-- 新增 / 编辑 -->
    <BaseModal
      v-model="formOpen"
      :title="editing ? '编辑节点' : '添加边缘节点'"
      :confirm-text="editing ? '保存修改' : '生成安装命令'"
      :loading="saving"
      @confirm="submitForm"
    >
      <div class="form-col">
        <div v-if="!editing" class="alert alert-info">
          <AppIcon name="info" :size="16" class="icon" />
          <span>
            预注册后节点处于「待接入」状态；在服务器上执行生成的命令并完成首次心跳后自动上线。
          </span>
        </div>
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">节点名称 <span class="req">*</span></label>
            <input
              v-model="form.name"
              class="input"
              placeholder="例如 edge-hk-01"
              :disabled="editing"
            />
            <span class="field-hint">
              {{ editing ? '名称用于心跳标识，修改后需同步调整节点环境变量 NODE_ID。' : '全局唯一，对应边缘端的 NODE_ID。' }}
            </span>
          </div>
          <div class="field">
            <label class="field-label">区域</label>
            <input v-model="form.region" class="input" placeholder="例如 香港 / cn-hongkong" />
          </div>
          <div class="field">
            <label class="field-label">公网 IP</label>
            <input v-model="form.public_ip" class="input" placeholder="DNS 调度返回的 IP" />
          </div>
          <div class="field">
            <label class="field-label">省份</label>
            <input v-model="form.province" class="input" placeholder="例如 广东" />
          </div>
          <div class="field">
            <label class="field-label">城市</label>
            <input v-model="form.city" class="input" placeholder="例如 深圳" />
          </div>
          <div class="field">
            <label class="field-label">运营商</label>
            <input v-model="form.isp" class="input" placeholder="电信 / 联通 / 移动 / BGP" />
          </div>
          <div class="field">
            <label class="field-label">调度权重</label>
            <input v-model.number="form.weight" class="input" type="number" min="0" max="1000" />
            <span class="field-hint">数值越大越优先，默认 100。</span>
          </div>
          <div class="field span-2">
            <label class="field-label">Agent 地址</label>
            <input
              v-model="form.agent_url"
              class="input"
              placeholder="http://1.2.3.4:8081"
            />
            <span class="field-hint">
              控制面回调该节点的地址（下发刷新、证书、ACME），必须是控制面能访问到的 URL。
              留空可稍后再填。
            </span>
          </div>
        </div>
        <p v-if="formError" class="text-danger" style="font-size: 13px">{{ formError }}</p>
      </div>
    </BaseModal>

    <!-- 安装命令 -->
    <BaseModal
      v-model="installOpen"
      title="节点安装命令"
      width="720px"
      hide-footer
    >
      <div v-if="created" class="form-col">
        <div class="alert alert-warning">
          <AppIcon name="alert" :size="16" class="icon" />
          <span>
            令牌等同于该节点的身份凭证，请通过安全通道传递；删除节点会立即吊销它。
            命令中的 <code class="mono">AGENT_URL</code> 请替换成该节点的公网地址。
          </span>
        </div>

        <div class="field">
          <label class="field-label">节点令牌</label>
          <div class="copy-row">
            <input class="input mono" :value="created.token" readonly />
            <button class="btn btn-default" type="button" @click="copy(created.token, '令牌')">
              <AppIcon name="copy" :size="15" />
              复制
            </button>
          </div>
        </div>

        <div class="segmented">
          <button type="button" :class="{ active: installTab === 'binary' }" @click="installTab = 'binary'">
            二进制
          </button>
          <button type="button" :class="{ active: installTab === 'docker' }" @click="installTab = 'docker'">
            Docker
          </button>
        </div>

        <div class="command-box">
          <pre class="mono">{{ currentCommand }}</pre>
          <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(currentCommand, '安装命令')">
            <AppIcon name="copy" :size="14" />
            复制
          </button>
        </div>

        <div class="tips">
          <div class="tip-row">
            <span class="tip-index">1</span>
            <span>把二进制 / 镜像传到节点服务器，或直接在代码目录运行。</span>
          </div>
          <div class="tip-row">
            <span class="tip-index">2</span>
            <span>确保节点能访问控制面地址，且 8081 端口对访客开放。</span>
          </div>
          <div class="tip-row">
            <span class="tip-index">3</span>
            <span>启动后约 15 秒节点会自动上线；命令可随时在「详情」里重新查看。</span>
          </div>
        </div>

        <div class="flex-between mt-8">
          <span class="text-muted" style="font-size: 12px">
            {{ created.node.name }} · {{ created.node.region || '默认区域' }}
          </span>
          <button class="btn btn-primary" type="button" @click="installOpen = false">完成</button>
        </div>
      </div>
    </BaseModal>

    <!-- 节点详情 -->
    <BaseDrawer v-model="detailOpen" :title="`节点 · ${detail?.node?.name || ''}`">
      <template #footer>
        <button class="btn btn-default" type="button" @click="detailOpen = false">关闭</button>
        <button
          v-if="detail"
          class="btn"
          :class="detail.node.status === 'disabled' ? 'btn-primary' : 'btn-default'"
          type="button"
          @click="toggle(detail.node)"
        >
          {{ detail.node.status === 'disabled' ? '启用节点' : '停用节点' }}
        </button>
      </template>

      <div v-if="detail" class="form-col">
        <div class="detail-grid">
          <div class="detail-item">
            <div class="detail-label">节点 ID</div>
            <div class="detail-value mono">{{ detail.node.id }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">状态</div>
            <div class="detail-value">
              <StatusTag :tone="statusTone(detail.node.status)" dot>
                {{ statusLabel(detail.node.status) }}
              </StatusTag>
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">区域</div>
            <div class="detail-value">{{ detail.node.region || '默认区域' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">版本</div>
            <div class="detail-value">{{ detail.node.version || '—' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">公网 IP</div>
            <div class="detail-value mono">{{ detail.node.public_ip || '未配置' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">省份 / 城市</div>
            <div class="detail-value">
              {{ [detail.node.province, detail.node.city].filter(Boolean).join(' / ') || '未配置' }}
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">运营商</div>
            <div class="detail-value">{{ detail.node.isp || '未配置' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">调度权重</div>
            <div class="detail-value">{{ detail.node.weight ?? 100 }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">节点 IP</div>
            <div class="detail-value mono">{{ detail.node.ip || '—' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">创建时间</div>
            <div class="detail-value">{{ formatDateTime(detail.node.created_at) }}</div>
          </div>
          <div class="detail-item span-2">
            <div class="detail-label">Agent 地址</div>
            <div class="detail-value mono">{{ detail.node.agent_url || '未配置' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">最后心跳</div>
            <div class="detail-value">{{ formatDateTime(detail.node.last_heartbeat) }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">资源占用</div>
            <div class="detail-value">
              CPU {{ detail.node.cpu_usage != null ? `${detail.node.cpu_usage.toFixed(0)}%` : '—' }}
              · MEM {{ detail.node.memory_usage != null ? `${detail.node.memory_usage.toFixed(0)}%` : '—' }}
            </div>
          </div>
        </div>

        <div class="section-title">节点令牌</div>
        <div class="copy-row">
          <input class="input mono" :value="detail.token" readonly />
          <button class="btn btn-default" type="button" @click="copy(detail.token, '令牌')">
            <AppIcon name="copy" :size="15" />
            复制
          </button>
        </div>

        <div class="section-title">安装 / 启动命令</div>
        <div class="segmented">
          <button type="button" :class="{ active: installTab === 'binary' }" @click="installTab = 'binary'">
            二进制
          </button>
          <button type="button" :class="{ active: installTab === 'docker' }" @click="installTab = 'docker'">
            Docker
          </button>
        </div>
        <div class="command-box">
          <pre class="mono">{{ currentCommand }}</pre>
          <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(currentCommand, '安装命令')">
            <AppIcon name="copy" :size="14" />
            复制
          </button>
        </div>
      </div>
    </BaseDrawer>
    <!-- 调度测试 -->
    <BaseModal v-model="schedOpen" title="调度测试" width="720px" hide-footer>
      <div class="form-col">
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">域名（可选）</label>
            <input v-model="schedForm.domain" class="input" placeholder="cdn.example.com" />
          </div>
          <div class="field">
            <label class="field-label">客户端 IP</label>
            <input v-model="schedForm.ip" class="input" placeholder="例如 203.0.113.9" />
            <span class="field-hint">用于匹配 GEOIP_JSON_PATH 的 CIDR 表。</span>
          </div>
          <div class="field">
            <label class="field-label">省份覆盖</label>
            <input v-model="schedForm.province" class="input" placeholder="例如 广东" />
          </div>
          <div class="field">
            <label class="field-label">运营商覆盖</label>
            <input v-model="schedForm.isp" class="input" placeholder="电信 / 联通 / 移动" />
          </div>
          <div class="field">
            <label class="field-label">城市覆盖</label>
            <input v-model="schedForm.city" class="input" placeholder="可选" />
          </div>
        </div>

        <div class="flex-between">
          <span class="text-muted" style="font-size: 12px">
            仅在线且填写了公网 IP 的节点参与调度；省份/运营商覆盖优先于 IP 解析。
          </span>
          <button class="btn btn-primary" type="button" :disabled="schedLoading" @click="runSchedule">
            {{ schedLoading ? '测试中…' : '开始测试' }}
          </button>
        </div>

        <template v-if="schedResult">
          <div class="alert alert-info" style="margin-top: 4px">
            <AppIcon name="info" :size="16" class="icon" />
            <span>
              客户端：{{ schedResult.client.province || '未知省份' }} /
              {{ schedResult.client.isp || '未知运营商' }} · TTL {{ schedResult.ttl }}s ·
              {{ schedResult.note }}
            </span>
          </div>
          <div class="sched-pick">
            <div class="sched-card primary">
              <div class="sched-label">主节点</div>
              <div class="sched-name">{{ schedResult.primary?.name || '无可用节点' }}</div>
              <div class="mono">{{ schedResult.primary?.public_ip || '—' }}</div>
              <div class="cell-sub">
                {{ [schedResult.primary?.province, schedResult.primary?.isp].filter(Boolean).join(' · ') || '未设置线路' }}
              </div>
            </div>
            <div class="sched-card">
              <div class="sched-label">备用节点</div>
              <div class="sched-name">{{ schedResult.backup?.name || '无' }}</div>
              <div class="mono">{{ schedResult.backup?.public_ip || '—' }}</div>
              <div class="cell-sub">
                {{ [schedResult.backup?.province, schedResult.backup?.isp].filter(Boolean).join(' · ') || '—' }}
              </div>
            </div>
          </div>

          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>候选节点</th>
                  <th>省份 / 运营商</th>
                  <th class="num">权重</th>
                  <th class="num">得分</th>
                  <th>原因</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="c in schedResult.candidates" :key="c.name">
                  <td class="mono">{{ c.name }}</td>
                  <td>{{ [c.province, c.isp].filter(Boolean).join(' · ') || '—' }}</td>
                  <td class="num">{{ c.weight }}</td>
                  <td class="num">{{ c.score }}</td>
                  <td class="text-2" style="font-size: 12px">{{ c.reason }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="flex-between">
            <span />
            <button class="btn btn-default" type="button" @click="schedOpen = false">关闭</button>
          </div>
        </template>
      </div>
    </BaseModal>
    <!-- DNS 测试 -->
    <BaseModal v-model="dnsOpen" title="DNS 解析测试" width="620px" hide-footer>
      <div class="form-col">
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">查询名称</label>
            <input v-model="dnsForm.name" class="input" placeholder="cdn.edge.lagran.net" />
          </div>
          <div class="field span-2">
            <label class="field-label">客户端 IP / 子网（可选，作为 ECS）</label>
            <input v-model="dnsForm.ip" class="input" placeholder="203.0.113.9/24" />
            <span class="field-hint">控制面用 DNS_TEST_SERVER 指定的权威 DNS 发起真实查询。</span>
          </div>
        </div>
        <div class="flex-between">
          <span class="text-muted" style="font-size: 12px">
            返回 rcode / IP / TTL；DNS 未配置或超时会显示错误。
          </span>
          <button class="btn btn-primary" type="button" :disabled="dnsLoading" @click="runDnsTest">
            {{ dnsLoading ? '查询中…' : '查询' }}
          </button>
        </div>

        <template v-if="dnsResult">
          <div class="alert alert-info">
            <AppIcon name="info" :size="16" class="icon" />
            <span>
              {{ dnsResult.server }} · rcode={{ dnsResult.rcode }} ·
              {{ dnsResult.elapsed_ms }}ms{{ dnsResult.truncated ? ' · TC' : '' }}
            </span>
          </div>
          <div v-if="dnsResult.answers.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th class="num">TTL</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="a in dnsResult.answers" :key="a.ip">
                  <td class="mono">{{ a.ip }}</td>
                  <td class="num">{{ a.ttl }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="text-muted" style="font-size: 13px">
            没有 A 记录（rcode={{ dnsResult.rcode }}）。
          </div>
          <div class="flex-between">
            <span />
            <button class="btn btn-default" type="button" @click="dnsOpen = false">关闭</button>
          </div>
        </template>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

interface CreatedNode {
  node: any
  token: string
  commands: { binary: string; docker: string }
}

const nodes = ref<any[]>([])
const loading = ref(false)
const saving = ref(false)
const autoRefresh = ref(true)
const lastUpdated = ref('')

const formOpen = ref(false)
const editing = ref<any>(null)
const formError = ref('')
const form = ref({
  name: '',
  region: '',
  ip: '',
  agent_url: '',
  public_ip: '',
  province: '',
  city: '',
  isp: '',
  weight: 100,
})

const schedOpen = ref(false)
const schedLoading = ref(false)
const schedResult = ref<any>(null)
const schedForm = ref({ domain: '', ip: '', province: '', isp: '', city: '' })

const dnsOpen = ref(false)
const dnsLoading = ref(false)
const dnsResult = ref<any>(null)
const dnsForm = ref({ name: 'cdn.edge.lagran.net', ip: '' })

const installOpen = ref(false)
const installTab = ref<'binary' | 'docker'>('binary')
const created = ref<CreatedNode | null>(null)

const detailOpen = ref(false)
const detail = ref<CreatedNode | null>(null)

let timer: ReturnType<typeof setInterval> | null = null

const counts = computed(() => {
  const result = { online: 0, offline: 0, pending: 0, disabled: 0 }
  for (const n of nodes.value) {
    if (n.status === 'online') result.online += 1
    else if (n.status === 'pending') result.pending += 1
    else if (n.status === 'disabled') result.disabled += 1
    else result.offline += 1
  }
  return result
})

const currentCommand = computed(() => {
  const source = created.value || detail.value
  if (!source) return ''
  return installTab.value === 'docker' ? source.commands.docker : source.commands.binary
})

function statusLabel(status: string) {
  return (
    {
      online: '在线',
      offline: '离线',
      pending: '待接入',
      disabled: '已停用',
    } as Record<string, string>
  )[status] || status
}

function statusTone(status: string) {
  if (status === 'online') return 'success'
  if (status === 'pending') return 'warning'
  if (status === 'disabled') return 'danger'
  return 'neutral'
}

function usageColor(value?: number | null) {
  if (value == null) return 'var(--brand)'
  if (value >= 85) return 'var(--danger)'
  if (value >= 70) return 'var(--warning)'
  return 'var(--brand)'
}

async function load() {
  loading.value = true
  try {
    nodes.value = (await api.get<any[]>('/api/v1/nodes')) || []
    lastUpdated.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  } catch (e: any) {
    // Non-admin or control-plane error: keep the previous list.
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  formError.value = ''
  form.value = {
    name: '',
    region: '',
    ip: '',
    agent_url: '',
    public_ip: '',
    province: '',
    city: '',
    isp: '',
    weight: 100,
  }
  formOpen.value = true
}

function openEdit(node: any) {
  editing.value = node
  formError.value = ''
  form.value = {
    name: node.name,
    region: node.region || '',
    ip: node.ip || '',
    agent_url: node.agent_url || '',
    public_ip: node.public_ip || '',
    province: node.province || '',
    city: node.city || '',
    isp: node.isp || '',
    weight: node.weight ?? 100,
  }
  formOpen.value = true
}

function openSchedule() {
  schedResult.value = null
  schedForm.value = { domain: '', ip: '', province: '', isp: '', city: '' }
  schedOpen.value = true
}

async function runSchedule() {
  schedLoading.value = true
  try {
    schedResult.value = await api.post('/api/v1/schedule/test', {
      domain: schedForm.value.domain.trim(),
      ip: schedForm.value.ip.trim(),
      province: schedForm.value.province.trim(),
      isp: schedForm.value.isp.trim(),
      city: schedForm.value.city.trim(),
    })
  } catch (e: any) {
    toast.error(e?.data?.error || '调度测试失败')
  } finally {
    schedLoading.value = false
  }
}

function openDnsTest() {
  dnsResult.value = null
  dnsOpen.value = true
}

async function runDnsTest() {
  if (!dnsForm.value.name.trim()) {
    toast.error('请填写查询名称')
    return
  }
  dnsLoading.value = true
  try {
    dnsResult.value = await api.post('/api/v1/dns/test', {
      name: dnsForm.value.name.trim(),
      ip: dnsForm.value.ip.trim(),
    })
  } catch (e: any) {
    toast.error(e?.data?.error || 'DNS 查询失败')
  } finally {
    dnsLoading.value = false
  }
}

async function submitForm() {
  formError.value = ''
  if (!form.value.name.trim()) {
    formError.value = '请填写节点名称'
    return
  }
  saving.value = true
  try {
    const payload = {
      region: form.value.region.trim(),
      agent_url: form.value.agent_url.trim(),
      public_ip: form.value.public_ip.trim(),
      province: form.value.province.trim(),
      city: form.value.city.trim(),
      isp: form.value.isp.trim(),
      weight: Number(form.value.weight) || 100,
    }
    if (editing.value) {
      await api.put(`/api/v1/nodes/${editing.value.id}`, payload)
      formOpen.value = false
      toast.success('节点信息已更新')
      await load()
    } else {
      const res = await api.post<CreatedNode>('/api/v1/nodes', {
        name: form.value.name.trim(),
        ip: form.value.ip.trim(),
        ...payload,
      })
      formOpen.value = false
      created.value = res
      installTab.value = 'binary'
      installOpen.value = true
      await load()
    }
  } catch (e: any) {
    formError.value = e?.data?.error || '保存失败'
  } finally {
    saving.value = false
  }
}

async function openDetail(node: any) {
  installTab.value = 'binary'
  detail.value = null
  detailOpen.value = true
  try {
    detail.value = await api.get<CreatedNode>(`/api/v1/nodes/${node.id}`)
  } catch (e: any) {
    detailOpen.value = false
    toast.error(e?.data?.error || '读取节点详情失败')
  }
}

async function toggle(node: any) {
  const enable = node.status === 'disabled'
  if (!enable) {
    const ok = await ask({
      title: '停用节点',
      message: `停用后 ${node.name} 将立即返回 503，不再代理任何流量；心跳和健康检查仍然保留。确认停用？`,
      confirmText: '停用',
      danger: true,
    })
    if (!ok) return
  }
  try {
    await api.post(`/api/v1/nodes/${node.id}/status`, { enabled: enable })
    toast.success(enable ? '节点已启用，等待下一次心跳' : '节点已停用，边缘将在下一次心跳后停止代理')
    await load()
    if (detailOpen.value && detail.value?.node.id === node.id) {
      detail.value = await api.get<CreatedNode>(`/api/v1/nodes/${node.id}`).catch(() => detail.value)
    }
  } catch (e: any) {
    toast.error(e?.data?.error || '状态更新失败')
  }
}

async function remove(node: any) {
  const ok = await ask({
    title: '删除节点',
    message: `删除 ${node.name} 后会吊销其令牌并停止下发刷新/证书。如果该节点仍在运行，下次心跳会自动重新注册。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/nodes/${node.id}`)
    toast.success('节点已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

async function copy(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success(`${label}已复制`)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    try {
      document.execCommand('copy')
      toast.success(`${label}已复制`)
    } catch {
      toast.error('复制失败，请手动选择文本')
    }
    document.body.removeChild(ta)
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

<style scoped>
.resource {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 2px 0;
}

.res-label {
  width: 30px;
  font-size: 11px;
  color: var(--text-3);
}

.res-bar {
  flex: 1;
  min-width: 60px;
}

.res-val {
  width: 30px;
  text-align: right;
  font-size: 11px;
  color: var(--text-3);
  font-variant-numeric: tabular-nums;
}

.copy-row {
  display: flex;
  gap: 8px;
}

.copy-row .input {
  flex: 1;
  font-size: 13px;
}

.command-box {
  position: relative;
  background: #0f172a;
  border-radius: var(--radius);
  padding: 14px 16px;
  overflow-x: auto;
}

.command-box pre {
  margin: 0;
  color: #d6e8ff;
  font-size: 12.5px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
}

.copy-float {
  position: absolute;
  top: 8px;
  right: 8px;
  background: rgba(255, 255, 255, 0.12);
  border-color: rgba(255, 255, 255, 0.2);
  color: #fff;
}

.copy-float:hover {
  color: #fff;
  border-color: #fff;
}

.tips {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 14px;
  background: #fafbfc;
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.tip-row {
  display: flex;
  gap: 8px;
  font-size: 12.5px;
  color: var(--text-2);
  line-height: 1.6;
}

.tip-index {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 11px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
  margin-top: 1px;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px 18px;
}

.sched-pick {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.sched-card {
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: #fafbfc;
}

.sched-card.primary {
  border-color: #bedaff;
  background: var(--brand-bg);
}

.sched-label {
  font-size: 11.5px;
  color: var(--text-3);
}

.sched-name {
  margin-top: 4px;
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
}

.detail-item.span-2 {
  grid-column: span 2;
}

.detail-label {
  font-size: 12px;
  color: var(--text-3);
}

.detail-value {
  margin-top: 3px;
  font-size: 13.5px;
  color: var(--text);
  word-break: break-all;
}

.section-title {
  margin-top: 4px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--divider);
  font-size: 13px;
  font-weight: 500;
  color: var(--text-2);
}

@media (max-width: 640px) {
  .detail-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .detail-item.span-2 {
    grid-column: span 1;
  }
}
</style>
