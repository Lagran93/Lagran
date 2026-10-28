<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">配置发布</div>
        <div class="page-desc">配置版本、差异对比、审批与灰度发布；发布失败自动回滚</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-default" type="button" @click="openSnapshot">
          <AppIcon name="plus" :size="15" />
          创建版本
        </button>
        <button class="btn btn-primary" type="button" @click="openRelease">
          <AppIcon name="plus" :size="15" />
          新建发布单
        </button>
      </div>
    </div>

    <div class="segmented" style="margin-bottom: 16px; display: inline-flex">
      <button type="button" :class="{ active: tab === 'versions' }" @click="tab = 'versions'">
        版本历史
      </button>
      <button type="button" :class="{ active: tab === 'releases' }" @click="tab = 'releases'">
        发布单
      </button>
    </div>

    <div v-if="tab === 'versions'" class="card">
      <div class="card-head">
        <div>
          <div class="card-title">配置版本</div>
          <div class="card-desc">每次域名、缓存规则、WAF 或高级设置变更后自动生成快照</div>
        </div>
        <div class="card-extra">
          <select v-model="versionDomain" class="select" style="min-width: 180px">
            <option value="">全部域名</option>
            <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
          </select>
        </div>
      </div>
      <div class="card-body tight">
        <div v-if="filteredVersions.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>域名</th>
                <th>版本</th>
                <th>操作</th>
                <th>变更说明</th>
                <th>操作人</th>
                <th>时间</th>
                <th class="text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="v in filteredVersions" :key="v.id">
                <td class="cell-main">{{ v.domain }}</td>
                <td>
                  <StatusTag tone="info">v{{ v.version }}</StatusTag>
                  <StatusTag v-if="isPublished(v)" tone="success" dot>生效中</StatusTag>
                </td>
                <td>{{ actionLabel(v.action) }}</td>
                <td class="text-2">{{ v.message || '—' }}</td>
                <td class="text-2">{{ v.actor || '—' }}</td>
                <td class="text-2">{{ formatTime(v.created_at) }}</td>
                <td class="text-right">
                  <button class="btn btn-text btn-sm" type="button" @click="showDiff(v)">查看 Diff</button>
                  <button class="btn btn-text btn-sm" type="button" @click="rollbackVersion(v)">回滚</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="clock"
          title="还没有配置版本"
          text="修改域名配置或点击「创建版本」后会生成第一份快照。"
        />
      </div>
    </div>

    <div v-else class="card">
      <div class="card-head">
        <div>
          <div class="card-title">发布单</div>
          <div class="card-desc">审批通过后发布；指定目标节点时先灰度，目标节点全部成功后才全量生效</div>
        </div>
      </div>
      <div class="card-body tight">
        <div v-if="releases.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>状态</th>
                <th>域名 / 版本</th>
                <th>目标节点</th>
                <th>创建人</th>
                <th>时间</th>
                <th class="text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in releases" :key="r.id">
                <td><StatusTag :tone="releaseTone(r.status)" dot>{{ releaseLabel(r.status) }}</StatusTag></td>
                <td>
                  <div v-for="d in r.domains" :key="d.domain" class="cell-sub">
                    <span class="mono">{{ d.domain }}</span>
                    <span class="text-muted"> · v{{ d.version ?? '?' }}</span>
                  </div>
                </td>
                <td class="text-2">
                  {{ r.target_nodes.length ? r.target_nodes.join(', ') : '全部节点（直接全量）' }}
                </td>
                <td class="text-2">{{ r.created_by }}</td>
                <td class="text-2">{{ formatTime(r.created_at) }}</td>
                <td class="text-right nowrap">
                  <button class="btn btn-text btn-sm" type="button" @click="dryRun(r)">Dry-run</button>
                  <button
                    v-if="r.status === 'pending_approval'"
                    class="btn btn-text btn-sm"
                    type="button"
                    @click="approve(r)"
                  >
                    审批
                  </button>
                  <button
                    v-if="r.status === 'approved'"
                    class="btn btn-text btn-sm"
                    type="button"
                    @click="publish(r)"
                  >
                    发布
                  </button>
                  <button
                    v-if="r.status === 'publishing' || r.status === 'published'"
                    class="btn btn-text btn-sm danger"
                    type="button"
                    @click="rollbackRelease(r)"
                  >
                    回滚
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="upload"
          title="还没有发布单"
          text="选择配置版本、目标节点后创建发布单，审批通过即可发布。"
        />
      </div>
    </div>

    <BaseModal v-model="diffOpen" title="配置差异" width="860px" hide-footer>
      <div v-if="diffLoading" class="text-muted">加载中…</div>
      <div v-else-if="diffEntries.length" class="diff-list">
        <div v-for="(entry, i) in diffEntries" :key="i" class="diff-row">
          <div class="diff-path mono">{{ entry.path }}</div>
          <div class="diff-cols">
            <pre class="diff-before">{{ pretty(entry.before) }}</pre>
            <pre class="diff-after">{{ pretty(entry.after) }}</pre>
          </div>
        </div>
      </div>
      <EmptyState v-else icon="check" title="没有差异" text="该版本与当前生效配置一致。" />
    </BaseModal>

    <BaseModal v-model="dryOpen" title="发布前 Dry-run" width="860px" hide-footer>
      <div v-if="dryLoading" class="text-muted">校验中…</div>
      <template v-else-if="dryResult">
        <div class="alert" :class="dryResult.ok ? 'alert-success' : 'alert-danger'">
          <AppIcon :name="dryResult.ok ? 'check' : 'alert'" :size="16" class="icon" />
          <span>{{ dryResult.ok ? '配置校验通过' : `发现 ${dryResult.warnings.length} 个问题` }}</span>
        </div>
        <div v-if="dryResult.warnings.length" class="warning-list">
          <div v-for="(w, i) in dryResult.warnings" :key="i" class="warning-row">{{ w }}</div>
        </div>
        <div v-for="(d, i) in dryResult.domains" :key="i" class="dry-domain">
          <div class="section-label">{{ d.domain }} · v{{ d.version }}（{{ d.diff.length }} 处差异）</div>
          <div v-for="(entry, j) in d.diff" :key="j" class="diff-row compact">
            <div class="diff-path mono">{{ entry.path }}</div>
            <div class="diff-cols">
              <pre class="diff-before">{{ pretty(entry.before) }}</pre>
              <pre class="diff-after">{{ pretty(entry.after) }}</pre>
            </div>
          </div>
        </div>
      </template>
    </BaseModal>

    <BaseModal
      v-model="releaseOpen"
      title="新建发布单"
      width="820px"
      confirm-text="提交审批"
      :loading="submitting"
      @confirm="createRelease"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">配置版本 <span class="req">*</span></label>
          <div v-for="(pick, i) in picks" :key="i" class="pick-row">
            <select v-model="pick.domain" class="select">
              <option value="">选择域名</option>
              <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
            </select>
            <select v-model="pick.version_id" class="select">
              <option value="">选择版本</option>
              <option v-for="v in versionsFor(pick.domain)" :key="v.id" :value="v.id">
                v{{ v.version }} · {{ v.message || actionLabel(v.action) }}
              </option>
            </select>
            <button v-if="picks.length > 1" class="btn btn-text danger" type="button" @click="picks.splice(i, 1)">
              删除
            </button>
          </div>
          <button class="btn btn-text btn-sm" type="button" @click="picks.push({ domain: '', version_id: '' })">
            + 添加域名
          </button>
        </div>

        <div class="field">
          <label class="field-label">灰度目标节点</label>
          <div class="node-grid">
            <label v-for="node in nodes" :key="node.id" class="check">
              <input v-model="targetNodes" type="checkbox" :value="node.name" />
              {{ node.name }}
              <span class="text-muted">（{{ node.status }}）</span>
            </label>
          </div>
          <span class="field-hint">
            不选节点表示直接全量发布；选中节点时先只下发到这些节点，全部上报成功后全量生效，失败自动回滚。
          </span>
        </div>

        <div class="field">
          <label class="field-label">备注</label>
          <textarea v-model="note" class="textarea" rows="3" placeholder="例如：v12 缓存规则灰度到华东节点" />
        </div>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>

    <BaseModal
      v-model="snapshotOpen"
      title="创建配置版本"
      width="560px"
      confirm-text="创建"
      :loading="submitting"
      @confirm="createSnapshot"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">域名 <span class="req">*</span></label>
          <select v-model="snapshotDomain" class="select">
            <option value="">请选择域名</option>
            <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
          </select>
        </div>
        <p class="text-muted" style="font-size: 13px">
          手动快照用于在批量变更前后建立基线；与最新快照相同时不会重复创建。
        </p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

const tab = ref<'versions' | 'releases'>('versions')
const loading = ref(false)
const submitting = ref(false)
const error = ref('')

const domains = ref<any[]>([])
const nodes = ref<any[]>([])
const versions = ref<any[]>([])
const releases = ref<any[]>([])
const versionDomain = ref('')

const diffOpen = ref(false)
const diffLoading = ref(false)
const diffEntries = ref<any[]>([])

const dryOpen = ref(false)
const dryLoading = ref(false)
const dryResult = ref<any>(null)

const releaseOpen = ref(false)
const picks = ref<{ domain: string; version_id: string }[]>([{ domain: '', version_id: '' }])
const targetNodes = ref<string[]>([])
const note = ref('')

const snapshotOpen = ref(false)
const snapshotDomain = ref('')

const filteredVersions = computed(() =>
  versionDomain.value ? versions.value.filter((v) => v.domain === versionDomain.value) : versions.value,
)

function versionsFor(domain: string) {
  return versions.value.filter((v) => v.domain === domain)
}

function isPublished(v: any) {
  const domain = domains.value.find((d) => d.name === v.domain)
  return !!domain && domain.published_version_id === v.id
}

function actionLabel(action: string) {
  const labels: Record<string, string> = {
    'domain.create': '创建域名',
    'domain.update': '更新域名',
    'domain.settings': '高级设置',
    'domain.status': '状态变更',
    'rule.create': '新增规则',
    'rule.update': '更新规则',
    'rule.delete': '删除规则',
    'manual.snapshot': '手动快照',
    'initial.baseline': '初始化基线',
    'waf.settings': 'WAF 设置',
    'waf.rule.create': '新增 WAF 规则',
    'waf.rule.update': '更新 WAF 规则',
    'waf.rule.delete': '删除 WAF 规则',
    'waf.ip.create': '新增 WAF IP',
    'waf.ip.delete': '删除 WAF IP',
  }
  return labels[action] || action || '变更'
}

function releaseTone(status: string) {
  if (status === 'published') return 'success'
  if (status === 'rolled_back') return 'danger'
  if (status === 'publishing') return 'info'
  if (status === 'approved') return 'warning'
  return 'neutral'
}

function releaseLabel(status: string) {
  return {
    pending_approval: '待审批',
    approved: '已审批',
    publishing: '灰度中',
    published: '已发布',
    rolled_back: '已回滚',
    failed: '失败',
  }[status] || status
}

function formatTime(value: string) {
  if (!value) return '—'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function pretty(value: any) {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2)
}

async function load() {
  loading.value = true
  try {
    const [d, n, v, r] = await Promise.all([
      api.get<any[]>('/api/v1/domains').catch(() => []),
      api.get<any[]>('/api/v1/nodes').catch(() => []),
      api.get<any[]>('/api/v1/config/versions?limit=200').catch(() => []),
      api.get<any[]>('/api/v1/config/releases').catch(() => []),
    ])
    domains.value = d || []
    nodes.value = n || []
    versions.value = v || []
    releases.value = r || []
  } finally {
    loading.value = false
  }
}

async function showDiff(v: any) {
  diffOpen.value = true
  diffLoading.value = true
  diffEntries.value = []
  try {
    const detail = await api.get<any>(`/api/v1/config/versions/${v.id}`)
    diffEntries.value = detail.diff || []
  } catch {
    toast.error('读取版本差异失败')
  } finally {
    diffLoading.value = false
  }
}

async function rollbackVersion(v: any) {
  const ok = await ask({
    title: '一键回滚',
    message: `将 ${v.domain} 回滚到 v${v.version}？所有节点会在下次同步时切换到该版本。`,
    confirmText: '确认回滚',
    danger: true,
  })
  if (!ok) return
  try {
    await api.post(`/api/v1/config/versions/${v.id}/rollback`, {})
    toast.success('回滚已生效')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '回滚失败')
  }
}

function openRelease() {
  error.value = ''
  releaseOpen.value = true
  picks.value = [{ domain: '', version_id: '' }]
  targetNodes.value = []
  note.value = ''
}

async function createRelease() {
  error.value = ''
  const valid = picks.value.filter((p) => p.domain && p.version_id)
  if (!valid.length) {
    error.value = '请至少选择一个域名版本'
    return
  }
  submitting.value = true
  try {
    await api.post('/api/v1/config/releases', {
      versions: valid,
      target_nodes: targetNodes.value,
      note: note.value,
    })
    releaseOpen.value = false
    tab.value = 'releases'
    toast.success('发布单已创建，等待审批')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '创建发布单失败'
  } finally {
    submitting.value = false
  }
}

async function approve(r: any) {
  const ok = await ask({
    title: '审批发布单',
    message: `确认审批通过 ${r.domains.map((d: any) => d.domain).join(', ')} 的配置发布？`,
    confirmText: '审批通过',
  })
  if (!ok) return
  try {
    await api.post(`/api/v1/config/releases/${r.id}/approve`, {})
    toast.success('已审批通过')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '审批失败')
  }
}

async function publish(r: any) {
  const ok = await ask({
    title: '发布配置',
    message: r.target_nodes.length
      ? `先灰度到 ${r.target_nodes.length} 个节点，全部成功后全量生效。确认发布？`
      : '将立即全量生效，确认发布？',
    confirmText: '确认发布',
    danger: true,
  })
  if (!ok) return
  try {
    await api.post(`/api/v1/config/releases/${r.id}/publish`, {})
    toast.success(r.target_nodes.length ? '已开始灰度发布' : '配置已全量发布')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '发布失败')
  }
}

async function rollbackRelease(r: any) {
  const ok = await ask({
    title: '回滚发布',
    message: '确认回滚该发布单？灰度中的节点会立即恢复旧配置。',
    confirmText: '确认回滚',
    danger: true,
  })
  if (!ok) return
  try {
    await api.post(`/api/v1/config/releases/${r.id}/rollback`, {})
    toast.success('发布单已回滚')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '回滚失败')
  }
}

async function dryRun(r: any) {
  dryOpen.value = true
  dryLoading.value = true
  dryResult.value = null
  try {
    dryResult.value = await api.post(`/api/v1/config/releases/${r.id}/dry-run`, {})
  } catch (e: any) {
    toast.error(e?.data?.error || 'Dry-run 失败')
    dryOpen.value = false
  } finally {
    dryLoading.value = false
  }
}

function openSnapshot() {
  snapshotDomain.value = ''
  snapshotOpen.value = true
}

async function createSnapshot() {
  if (!snapshotDomain.value) {
    toast.error('请选择域名')
    return
  }
  submitting.value = true
  try {
    await api.post(`/api/v1/config/domains/${snapshotDomain.value}/versions`, {})
    snapshotOpen.value = false
    toast.success('配置版本已创建')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '创建版本失败')
  } finally {
    submitting.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.pick-row {
  display: grid;
  grid-template-columns: 1fr 1.4fr auto;
  gap: 8px;
  margin-bottom: 8px;
}

.node-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 8px 14px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.diff-list,
.dry-domain {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.diff-row {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}

.diff-row.compact {
  margin-top: 8px;
}

.diff-path {
  padding: 8px 12px;
  background: #f7f8fa;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  color: var(--text-2);
}

.diff-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
}

.diff-before,
.diff-after {
  margin: 0;
  padding: 10px 12px;
  font-family: var(--mono);
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 220px;
  overflow: auto;
}

.diff-before {
  background: #fff5f5;
  border-right: 1px solid var(--border);
}

.diff-after {
  background: #f2fbf5;
}

.warning-list {
  margin: 12px 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.warning-row {
  padding: 8px 12px;
  background: #fff7e6;
  border: 1px solid #ffd591;
  border-radius: var(--radius);
  font-size: 13px;
}

@media (max-width: 720px) {
  .pick-row,
  .diff-cols {
    grid-template-columns: 1fr;
  }

  .diff-before {
    border-right: 0;
    border-bottom: 1px solid var(--border);
  }
}
</style>
