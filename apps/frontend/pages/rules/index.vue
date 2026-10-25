<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">缓存规则</div>
        <div class="page-desc">
          按路径匹配设置缓存动作与 TTL；未命中规则时依次使用源站 Cache-Control / Expires，最后回退到域名默认 TTL
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

    <div class="card">
      <div class="filter-bar">
        <input v-model="keyword" class="input" placeholder="搜索路径" style="min-width: 180px" />
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
        <span class="spacer" />
        <span class="text-muted" style="font-size: 13px">共 {{ filtered.length }} 条规则</span>
      </div>

      <div v-if="filtered.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th>域名</th>
              <th>路径匹配</th>
              <th>动作</th>
              <th>TTL</th>
              <th>SWR</th>
              <th>优先级</th>
              <th class="text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in paged" :key="r.id">
              <td class="cell-main">{{ r.domain_name }}</td>
              <td><span class="mono">{{ r.path_pattern }}</span></td>
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
              <td class="num">{{ r.priority }}</td>
              <td class="text-right">
                <button class="btn btn-text btn-sm danger" type="button" @click="remove(r)">删除</button>
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
      v-model="createOpen"
      title="新建缓存规则"
      confirm-text="创建规则"
      :loading="submitting"
      @confirm="createRule"
    >
      <div class="form-col">
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">所属域名 <span class="req">*</span></label>
            <select v-model="form.domain_id" class="select">
              <option value="">请选择域名</option>
              <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
            </select>
          </div>
          <div class="field span-2">
            <label class="field-label">路径匹配 <span class="req">*</span></label>
            <input v-model="form.path_pattern" class="input" placeholder="/static/* 或 /api/*" />
            <span class="field-hint">支持前缀通配：/static/* 匹配 /static 下所有资源。</span>
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
          <div v-if="form.action === 'cache'" class="field">
            <label class="field-label">TTL（秒）</label>
            <input v-model.number="form.ttl_seconds" class="input" type="number" min="1" />
          </div>
          <div v-if="form.action === 'cache'" class="field">
            <label class="field-label">SWR（秒）</label>
            <input v-model.number="form.swr_seconds" class="input" type="number" min="0" />
            <span class="field-hint">过期后先返回旧内容，再后台刷新。</span>
          </div>
          <div class="field">
            <label class="field-label">优先级</label>
            <input v-model.number="form.priority" class="input" type="number" />
            <span class="field-hint">数值越大越优先。</span>
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
const page = ref(1)
const pageSize = 10

const createOpen = ref(false)
const error = ref('')
const form = ref({
  domain_id: '',
  path_pattern: '/*',
  action: 'cache',
  ttl_seconds: 60,
  swr_seconds: 0,
  priority: 0,
})

const actionOptions = [
  { value: 'cache', label: '缓存' },
  { value: 'bypass', label: '绕过缓存' },
  { value: 'no_store', label: '不存储' },
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
    if (q && !String(r.path_pattern).toLowerCase().includes(q)) return false
    return true
  })
})

const paged = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

watch([keyword, domainFilter, actionFilter], () => {
  page.value = 1
})

function actionLabel(action: string) {
  return action === 'bypass' ? '绕过缓存' : action === 'no_store' ? '不存储' : '缓存'
}

function actionTone(action: string) {
  return action === 'bypass' ? 'warning' : action === 'no_store' ? 'danger' : 'success'
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
  } finally {
    loading.value = false
  }
}

function openCreate() {
  error.value = ''
  form.value = {
    domain_id: domains.value[0]?.id || '',
    path_pattern: '/*',
    action: 'cache',
    ttl_seconds: 60,
    swr_seconds: 0,
    priority: 0,
  }
  createOpen.value = true
}

async function createRule() {
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
    const body: any = {
      domain_id: form.value.domain_id,
      path_pattern: form.value.path_pattern.trim(),
      action: form.value.action,
      priority: Number(form.value.priority) || 0,
      ttl_seconds: form.value.action === 'cache' ? Number(form.value.ttl_seconds) || 0 : 0,
      swr_seconds: Number(form.value.swr_seconds) || 0,
    }
    await api.post('/api/v1/rules', body)
    createOpen.value = false
    toast.success('规则已创建，边缘约 15 秒内同步')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '创建失败'
  } finally {
    submitting.value = false
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

onMounted(load)
</script>
