<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">缓存规则</div>
        <div class="page-desc">
          按路径、方法、查询串匹配，设置缓存动作、边缘 TTL、浏览器 TTL 与 SWR；未命中时依次使用源站 Cache-Control / Expires，最后回退域名默认 TTL
        </div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          新建规则
        </button>
      </div>
    </div>

    <!-- 规则测试 -->
    <div class="card tester">
      <div class="card-head">
        <div>
          <div class="card-title">规则测试</div>
          <div class="card-desc">输入一次请求，看看会命中哪条规则、最终生效的策略</div>
        </div>
      </div>
      <div class="tester-form">
        <select v-model="tester.domain_id" class="select" style="min-width: 190px">
          <option value="">选择域名</option>
          <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
        </select>
        <input v-model="tester.path" class="input" placeholder="/static/app.js" style="flex: 1; min-width: 180px" />
        <select v-model="tester.method" class="select" style="width: 110px">
          <option v-for="m in methodOptions" :key="m" :value="m">{{ m }}</option>
        </select>
        <input v-model="tester.query" class="input" placeholder="查询串（可选）" style="width: 180px" />
        <button class="btn btn-primary" type="button" :disabled="testing" @click="runTest">
          {{ testing ? '测试中…' : '测试' }}
        </button>
      </div>

      <div v-if="testResult" class="test-result">
        <div v-if="testResult.matched" class="test-hit">
          <div class="test-head">
            <StatusTag tone="success" dot>命中规则</StatusTag>
            <span class="mono test-path">{{ testResult.matched.path_pattern }}</span>
            <span class="text-muted" style="font-size: 12px">
              优先级 {{ testResult.matched.priority }} · {{ testResult.note }}
            </span>
          </div>
          <div class="effective-grid">
            <div class="effective-item">
              <span class="eff-label">动作</span>
              <span class="eff-value">{{ actionLabel(testResult.effective.action) }}</span>
            </div>
            <div class="effective-item">
              <span class="eff-label">边缘 TTL</span>
              <span class="eff-value">{{ testResult.effective.action === 'cache' ? `${testResult.effective.ttl_seconds} 秒` : '—' }}</span>
            </div>
            <div class="effective-item">
              <span class="eff-label">SWR</span>
              <span class="eff-value">{{ testResult.effective.swr_seconds ? `${testResult.effective.swr_seconds} 秒` : '—' }}</span>
            </div>
            <div class="effective-item">
              <span class="eff-label">浏览器 TTL</span>
              <span class="eff-value">{{ testResult.effective.browser_ttl_seconds ? `${testResult.effective.browser_ttl_seconds} 秒` : '跟随源站' }}</span>
            </div>
            <div class="effective-item">
              <span class="eff-label">Query</span>
              <span class="eff-value">{{ queryModeLabel(testResult.effective.ignore_query) }}</span>
            </div>
          </div>
        </div>
        <div v-else class="test-miss">
          <StatusTag tone="neutral" dot>未命中规则</StatusTag>
          <span class="text-2" style="font-size: 13px">{{ testResult.note }}</span>
          <span class="text-muted" style="font-size: 12px">默认 TTL 由域名设置决定，源站缓存头优先。</span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="filter-bar">
        <input v-model="keyword" class="input" placeholder="搜索路径 / 备注" style="min-width: 190px" />
        <select v-model="domainFilter" class="select">
          <option value="">全部域名</option>
          <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
        </select>
        <select v-model="actionFilter" class="select">
          <option value="">全部动作</option>
          <option value="cache">缓存</option>
          <option value="bypass">绕过缓存</option>
          <option value="no_store">不存储</option>
        </select>
        <select v-model="statusFilter" class="select">
          <option value="">全部状态</option>
          <option value="enabled">启用</option>
          <option value="disabled">停用</option>
        </select>
        <span class="spacer" />
        <span class="text-muted" style="font-size: 13px">共 {{ filtered.length }} 条规则</span>
      </div>

      <div v-if="filtered.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>域名</th>
              <th style="min-width: 210px">匹配条件</th>
              <th>动作</th>
              <th class="num">边缘 TTL</th>
              <th class="num">SWR</th>
              <th class="num">浏览器 TTL</th>
              <th class="num">优先级</th>
              <th>状态</th>
              <th class="text-right" style="min-width: 130px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in paged" :key="r.id">
              <td class="cell-main">{{ r.domain_name }}</td>
              <td>
                <div class="mono cell-main">{{ r.path_pattern }}</div>
                <div class="cond-row">
                  <span v-if="r.match_methods" class="cond-chip">{{ r.match_methods.replaceAll(',', ' / ') }}</span>
                  <span v-else class="cond-chip muted">全部方法</span>
                  <span v-if="r.match_query" class="cond-chip">query 含 {{ r.match_query }}</span>
                  <span v-if="r.ignore_query === true" class="cond-chip warn">忽略 Query</span>
                  <span v-else-if="r.ignore_query === false" class="cond-chip">区分 Query</span>
                  <span v-if="r.note" class="cond-chip muted" :title="r.note">{{ r.note }}</span>
                </div>
              </td>
              <td>
                <StatusTag :tone="actionTone(r.action)">{{ actionLabel(r.action) }}</StatusTag>
              </td>
              <td class="num">
                <template v-if="r.action === 'cache'">{{ r.ttl_seconds }} 秒</template>
                <span v-else class="text-muted">—</span>
              </td>
              <td class="num">
                <template v-if="r.swr_seconds">{{ r.swr_seconds }} 秒</template>
                <span v-else class="text-muted">—</span>
              </td>
              <td class="num">
                <template v-if="r.browser_ttl_seconds">{{ r.browser_ttl_seconds }} 秒</template>
                <span v-else class="text-muted">跟随源站</span>
              </td>
              <td class="num">{{ r.priority }}</td>
              <td>
                <label class="switch" :class="{ on: r.enabled }">
                  <span class="switch-track" />
                  <input type="checkbox" :checked="r.enabled" style="display: none" @change="toggleEnabled(r)" />
                </label>
              </td>
              <td class="text-right">
                <div class="ops" style="justify-content: flex-end">
                  <button class="btn btn-text btn-sm" type="button" @click="openEdit(r)">编辑</button>
                  <button class="btn btn-text btn-sm danger" type="button" @click="remove(r)">删除</button>
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
        icon="rules"
        :title="rules.length ? '没有匹配的规则' : '还没有缓存规则'"
        :text="rules.length ? '试试调整筛选条件。' : '默认会按源站缓存头缓存；你可以为静态资源、API 等路径设置更精细的策略。'"
      >
        <button v-if="!rules.length" class="btn btn-primary btn-sm" type="button" @click="openCreate">
          新建第一条规则
        </button>
      </EmptyState>

      <div v-if="filtered.length > pageSize" class="table-footer">
        <AppPagination v-model:page="page" :total="filtered.length" :page-size="pageSize" />
      </div>
    </div>

    <BaseModal
      v-model="formOpen"
      :title="editing ? '编辑缓存规则' : '新建缓存规则'"
      :confirm-text="editing ? '保存修改' : '创建规则'"
      :loading="submitting"
      width="640px"
      @confirm="submit"
    >
      <div class="form-col">
        <div v-if="!editing" class="preset-row">
          <span class="preset-label">快速模板</span>
          <button
            v-for="p in presets"
            :key="p.label"
            class="btn btn-default btn-xs"
            type="button"
            @click="applyPreset(p)"
          >
            {{ p.label }}
          </button>
        </div>

        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">所属域名 <span class="req">*</span></label>
            <select v-model="form.domain_id" class="select" :disabled="!!editing">
              <option value="">请选择域名</option>
              <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
            </select>
          </div>

          <div class="field span-2">
            <label class="field-label">路径匹配 <span class="req">*</span></label>
            <input v-model="form.path_pattern" class="input" placeholder="/static/*" />
            <span class="field-hint">支持 `/static/*` 前缀和 `/img*` 通配；`/*` 匹配全部路径。</span>
          </div>

          <div class="field span-2">
            <label class="field-label">请求方法</label>
            <div class="chip-row">
              <button
                v-for="m in methodOptions"
                :key="m"
                type="button"
                class="chip"
                :class="{ on: form.methods.includes(m) }"
                @click="toggleMethod(m)"
              >
                {{ m }}
              </button>
              <span class="field-hint" style="margin-left: 6px">不选表示全部方法</span>
            </div>
          </div>

          <div class="field span-2">
            <label class="field-label">查询串包含（可选）</label>
            <input v-model="form.match_query" class="input" placeholder="例如 debug=1" />
            <span class="field-hint">不区分大小写；留空表示不限制查询串。</span>
          </div>

          <div class="field span-2">
            <label class="field-label">缓存动作</label>
            <div class="segmented">
              <button
                v-for="opt in actionOptions"
                :key="opt.value"
                type="button"
                :class="{ active: form.action === opt.value }"
                @click="form.action = opt.value"
              >
                {{ opt.label }}
              </button>
            </div>
            <span class="field-hint">{{ actionHint }}</span>
          </div>

          <template v-if="form.action === 'cache'">
            <div class="field">
              <label class="field-label">边缘 TTL（秒）</label>
              <input v-model.number="form.ttl_seconds" class="input" type="number" min="1" />
            </div>
            <div class="field">
              <label class="field-label">SWR（秒）</label>
              <input v-model.number="form.swr_seconds" class="input" type="number" min="0" />
              <span class="field-hint">过期先回旧内容再后台刷新。</span>
            </div>
            <div class="field">
              <label class="field-label">浏览器 TTL（秒）</label>
              <input v-model.number="form.browser_ttl_seconds" class="input" type="number" min="0" />
              <span class="field-hint">0 = 跟随源站 Cache-Control；只影响客户端缓存。</span>
            </div>
          </template>

          <div class="field">
            <label class="field-label">优先级</label>
            <input v-model.number="form.priority" class="input" type="number" />
            <span class="field-hint">数值越大越优先。</span>
          </div>

          <div class="field span-2">
            <label class="field-label">Query 缓存键</label>
            <div class="segmented">
              <button type="button" :class="{ active: form.ignore_query === 'inherit' }" @click="form.ignore_query = 'inherit'">
                继承域名
              </button>
              <button type="button" :class="{ active: form.ignore_query === 'on' }" @click="form.ignore_query = 'on'">
                忽略 Query
              </button>
              <button type="button" :class="{ active: form.ignore_query === 'off' }" @click="form.ignore_query = 'off'">
                区分 Query
              </button>
            </div>
            <span class="field-hint">忽略 Query 时 /a?x=1 与 /a?x=2 共用同一份缓存。</span>
          </div>

          <div class="field span-2">
            <label class="field-label">备注</label>
            <input v-model="form.note" class="input" placeholder="可选，便于团队识别这条规则" maxlength="200" />
          </div>

          <div class="field span-2">
            <label class="check">
              <input v-model="form.enabled" type="checkbox" />
              启用这条规则（停用后边缘忽略它）
            </label>
          </div>
        </div>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

const loading = ref(false)
const submitting = ref(false)
const rules = ref<any[]>([])
const domains = ref<any[]>([])

const keyword = ref('')
const domainFilter = ref('')
const actionFilter = ref('')
const statusFilter = ref('')
const page = ref(1)
const pageSize = 10

const tester = ref({ domain_id: '', path: '/', method: 'GET', query: '' })
const testing = ref(false)
const testResult = ref<any>(null)

const formOpen = ref(false)
const editing = ref<any>(null)
const error = ref('')
const form = ref({
  domain_id: '',
  path_pattern: '/*',
  action: 'cache',
  ttl_seconds: 60,
  swr_seconds: 0,
  browser_ttl_seconds: 0,
  methods: [] as string[],
  match_query: '',
  ignore_query: 'inherit' as 'inherit' | 'on' | 'off',
  priority: 0,
  enabled: true,
  note: '',
})

const methodOptions = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
const actionOptions = [
  { value: 'cache', label: '缓存' },
  { value: 'bypass', label: '绕过缓存' },
  { value: 'no_store', label: '不存储' },
]

const presets = [
  { label: '静态资源 7 天', path: '/static/*', ttl: 604800, swr: 86400, browser: 604800, methods: ['GET', 'HEAD'] },
  { label: '图片 30 天', path: '/images/*', ttl: 2592000, swr: 86400, browser: 2592000, methods: ['GET', 'HEAD'] },
  { label: 'HTML 5 分钟', path: '/', ttl: 300, swr: 60, browser: 300, methods: ['GET', 'HEAD'] },
  { label: 'API 不缓存', path: '/api/*', bypass: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] },
  { label: '下载 1 天', path: '/download/*', ttl: 86400, swr: 3600, browser: 86400, methods: ['GET', 'HEAD'] },
]

const actionHint = computed(() => {
  if (form.value.action === 'bypass') return '请求不读也不写缓存，直接回源（适合登录态、动态接口）。'
  if (form.value.action === 'no_store') return '照常回源，但响应不写入缓存。'
  return '按 TTL 缓存响应；源站 no-store / private 仍会阻止缓存。'
})

const filtered = computed(() => {
  const q = keyword.value.trim().toLowerCase()
  return rules.value.filter((r) => {
    if (domainFilter.value && r.domain_id !== domainFilter.value) return false
    if (actionFilter.value && r.action !== actionFilter.value) return false
    if (statusFilter.value === 'enabled' && !r.enabled) return false
    if (statusFilter.value === 'disabled' && r.enabled) return false
    if (q) {
      const hay = `${r.path_pattern} ${r.note || ''}`.toLowerCase()
      if (!hay.includes(q)) return false
    }
    return true
  })
})

const paged = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

watch([keyword, domainFilter, actionFilter, statusFilter], () => {
  page.value = 1
})

function actionLabel(action: string) {
  return action === 'bypass' ? '绕过缓存' : action === 'no_store' ? '不存储' : '缓存'
}

function actionTone(action: string) {
  return action === 'bypass' ? 'warning' : action === 'no_store' ? 'danger' : 'success'
}

function queryModeLabel(value: boolean | null) {
  if (value === true) return '忽略'
  if (value === false) return '区分'
  return '继承域名'
}

function toggleMethod(method: string) {
  const idx = form.value.methods.indexOf(method)
  if (idx >= 0) form.value.methods.splice(idx, 1)
  else form.value.methods.push(method)
}

function applyPreset(preset: any) {
  form.value.path_pattern = preset.path
  form.value.action = preset.bypass ? 'bypass' : 'cache'
  form.value.ttl_seconds = preset.ttl || 60
  form.value.swr_seconds = preset.swr || 0
  form.value.browser_ttl_seconds = preset.browser || 0
  form.value.methods = [...preset.methods]
  form.value.note = preset.label
}

async function load() {
  loading.value = true
  try {
    const [r, d] = await Promise.all([
      api.get<any[]>('/api/v1/rules').catch(() => []),
      api.get<any[]>('/api/v1/domains').catch(() => []),
    ])
    rules.value = r || []
    domains.value = d || []
    if (!tester.value.domain_id && domains.value.length) {
      tester.value.domain_id = domains.value[0].id
    }
  } finally {
    loading.value = false
  }
}

function openCreate() {
  error.value = ''
  editing.value = null
  form.value = {
    domain_id: domainFilter.value || domains.value[0]?.id || '',
    path_pattern: '/*',
    action: 'cache',
    ttl_seconds: 60,
    swr_seconds: 0,
    browser_ttl_seconds: 0,
    methods: [],
    match_query: '',
    ignore_query: 'inherit',
    priority: 0,
    enabled: true,
    note: '',
  }
  formOpen.value = true
}

function openEdit(rule: any) {
  error.value = ''
  editing.value = rule
  form.value = {
    domain_id: rule.domain_id,
    path_pattern: rule.path_pattern,
    action: rule.action,
    ttl_seconds: rule.ttl_seconds,
    swr_seconds: rule.swr_seconds,
    browser_ttl_seconds: rule.browser_ttl_seconds,
    methods: rule.match_methods ? String(rule.match_methods).split(',').filter(Boolean) : [],
    match_query: rule.match_query || '',
    ignore_query: rule.ignore_query === true ? 'on' : rule.ignore_query === false ? 'off' : 'inherit',
    priority: rule.priority,
    enabled: rule.enabled,
    note: rule.note || '',
  }
  formOpen.value = true
}

function payload() {
  return {
    path_pattern: form.value.path_pattern.trim(),
    action: form.value.action,
    ttl_seconds: Number(form.value.ttl_seconds) || 0,
    swr_seconds: Number(form.value.swr_seconds) || 0,
    browser_ttl_seconds: Number(form.value.browser_ttl_seconds) || 0,
    match_methods: form.value.methods.join(','),
    match_query: form.value.match_query.trim(),
    ignore_query: form.value.ignore_query === 'inherit' ? null : form.value.ignore_query === 'on',
    priority: Number(form.value.priority) || 0,
    enabled: form.value.enabled,
    note: form.value.note.trim(),
  }
}

async function submit() {
  error.value = ''
  if (!form.value.domain_id) {
    error.value = '请选择域名'
    return
  }
  if (!form.value.path_pattern.trim()) {
    error.value = '请填写路径匹配'
    return
  }
  submitting.value = true
  try {
    if (editing.value) {
      await api.put(`/api/v1/rules/${editing.value.id}`, payload())
      toast.success('规则已更新，边缘约 15 秒内同步')
    } else {
      await api.post('/api/v1/rules', { domain_id: form.value.domain_id, ...payload() })
      toast.success('规则已创建，边缘约 15 秒内同步')
    }
    formOpen.value = false
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '保存失败'
  } finally {
    submitting.value = false
  }
}

async function toggleEnabled(rule: any) {
  try {
    await api.put(`/api/v1/rules/${rule.id}`, { enabled: !rule.enabled })
    toast.success(rule.enabled ? '规则已停用' : '规则已启用')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '更新失败')
  }
}

async function remove(rule: any) {
  const ok = await ask({
    title: '删除缓存规则',
    message: `确认删除 ${rule.domain_name} 的 ${rule.path_pattern} 规则？`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/rules/${rule.id}`)
    toast.success('规则已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

async function runTest() {
  if (!tester.value.domain_id) {
    toast.error('请先选择域名')
    return
  }
  testing.value = true
  try {
    testResult.value = await api.post('/api/v1/rules/test', {
      domain_id: tester.value.domain_id,
      path: tester.value.path || '/',
      method: tester.value.method,
      query: tester.value.query,
    })
  } catch (e: any) {
    toast.error(e?.data?.error || '测试失败')
  } finally {
    testing.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.tester {
  margin-bottom: 16px;
}

.tester-form {
  display: flex;
  gap: 10px;
  padding: 0 18px 16px;
  flex-wrap: wrap;
}

.test-result {
  margin: 0 18px 18px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  background: #fafbfc;
}

.test-head {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.test-path {
  font-size: 13.5px;
  font-weight: 500;
}

.effective-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin-top: 12px;
}

.effective-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px 10px;
  background: #fff;
  border: 1px solid var(--divider);
  border-radius: var(--radius-sm);
}

.eff-label {
  font-size: 11.5px;
  color: var(--text-3);
}

.eff-value {
  font-size: 13px;
  color: var(--text);
}

.test-miss {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.cond-row {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-top: 4px;
}

.cond-chip {
  font-size: 11px;
  padding: 1px 6px;
  border-radius: 4px;
  background: var(--brand-bg);
  color: var(--brand);
}

.cond-chip.muted {
  background: #f2f3f5;
  color: var(--text-3);
}

.cond-chip.warn {
  background: var(--warning-bg);
  color: var(--warning);
}

.preset-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  padding-bottom: 4px;
  border-bottom: 1px dashed var(--divider);
}

.preset-label {
  font-size: 12px;
  color: var(--text-3);
}

.chip-row {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.chip {
  padding: 3px 10px;
  font-size: 12px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: #fff;
  color: var(--text-2);
  cursor: pointer;
}

.chip:hover {
  border-color: var(--brand);
  color: var(--brand);
}

.chip.on {
  background: var(--brand-bg);
  border-color: var(--brand);
  color: var(--brand);
}

@media (max-width: 760px) {
  .effective-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
