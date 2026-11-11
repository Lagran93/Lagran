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
        <button class="btn btn-default" type="button" @click="openTester">
          <AppIcon name="search" :size="15" />
          规则测试
        </button>
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
                  <span v-if="r.match_type === 'regex'" class="cond-chip warn">正则</span>
                  <span v-if="r.match_methods" class="cond-chip">{{ r.match_methods.replaceAll(',', ' / ') }}</span>
                  <span v-else class="cond-chip muted">全部方法</span>
                  <span v-if="r.match_query" class="cond-chip">query 含 {{ r.match_query }}</span>
                  <span v-if="r.match_content_type" class="cond-chip">Content-Type 含 {{ r.match_content_type }}</span>
                  <span v-if="r.ignore_query === true" class="cond-chip warn">忽略 Query</span>
                  <span v-else-if="r.ignore_query === false" class="cond-chip">区分 Query</span>
                  <span v-if="r.ignore_cookie" class="cond-chip warn">忽略 Cookie</span>
                  <span v-if="keyHeaderLabel(r.ignore_key_headers)" class="cond-chip warn">
                    {{ keyHeaderLabel(r.ignore_key_headers) }}
                  </span>
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

      <EmptyState v-else icon="rules" :title="rules.length ? '没有匹配的规则' : '还没有缓存规则'"
        :text="rules.length ? '试试调整筛选条件。' : '默认会按源站缓存头缓存；你可以为静态资源、API 等路径设置更精细的策略。'">
        <button v-if="!rules.length" class="btn btn-primary btn-sm" type="button" @click="openCreate">
          新建第一条规则
        </button>
      </EmptyState>

      <div v-if="filtered.length > pageSize" class="table-footer">
        <AppPagination v-model:page="page" :total="filtered.length" :page-size="pageSize" />
      </div>
    </div>

    <BaseModal v-model="formOpen" :title="editing ? '编辑缓存规则' : '新建缓存规则'" :confirm-text="editing ? '保存修改' : '创建规则'"
      :loading="submitting" width="880px" @confirm="submit">
      <div class="rule-editor">
        <div class="rule-summary">
          <div class="rule-summary-main">
            <div class="rule-summary-path mono">{{ form.path_pattern || '未设置路径' }}</div>
            <div class="rule-summary-tags">
              <span class="rule-tag">{{ previewDomain }}</span>
              <span class="rule-tag">{{ previewMethods }}</span>
              <span class="rule-tag" :class="`tone-${actionTone(form.action)}`">{{ actionLabel(form.action) }}</span>
              <span v-if="form.action === 'cache'" class="rule-tag">{{ formatDuration(form.ttl_seconds) }}</span>
              <span class="rule-tag">P{{ form.priority }}</span>
            </div>
          </div>
          <label class="switch rule-summary-switch" :class="{ on: form.enabled }">
            <span class="rule-summary-switch-text">{{ form.enabled ? '已启用' : '已停用' }}</span>
            <span class="switch-track" />
            <input v-model="form.enabled" type="checkbox" style="display: none" />
          </label>
        </div>

        <div class="rule-layout">
          <div class="rule-main">
            <section class="rule-block">
              <header class="rule-block-head">
                <h4>基础匹配</h4>
                <span>域名、路径与请求方法</span>
              </header>
              <div class="rule-block-body">
                <div class="rule-grid rule-grid-match">
                  <div class="field">
                    <label class="field-label">所属域名 <span class="req">*</span></label>
                    <select v-model="form.domain_id" class="select" :disabled="!!editing">
                      <option value="">请选择域名</option>
                      <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
                    </select>
                  </div>

                  <div class="field">
                    <label class="field-label">匹配路径 <span class="req">*</span></label>
                    <div class="path-combo">
                      <select v-model="form.match_type" class="select">
                        <option value="glob">通配符</option>
                        <option value="regex">正则</option>
                      </select>
                      <input v-model="form.path_pattern" class="input mono"
                        :placeholder="form.match_type === 'regex' ? '\\.(css|js)$' : '/static/*'" />
                    </div>
                  </div>

                  <div class="field span-2">
                    <label class="field-label">请求方法</label>
                    <div class="chip-row">
                      <button v-for="m in methodOptions" :key="m" type="button" class="chip"
                        :class="{ on: form.methods.includes(m) }" @click="toggleMethod(m)">
                        {{ m }}
                      </button>
                    </div>
                    <span class="field-hint">不选表示全部方法；路径支持 `/static/*`、`/img*`，`/*` 匹配全部。</span>
                  </div>
                </div>
              </div>
            </section>

            <section class="rule-block">
              <header class="rule-block-head">
                <h4>匹配条件</h4>
                <span>可选，进一步缩小命中范围</span>
              </header>
              <div class="rule-block-body">
                <div class="rule-grid">
                  <div class="field">
                    <label class="field-label">查询串包含</label>
                    <input v-model="form.match_query" class="input" placeholder="例如 debug=1" />
                  </div>
                  <div class="field">
                    <label class="field-label">Content-Type 包含</label>
                    <input v-model="form.match_content_type" class="input" placeholder="例如 text/html" />
                  </div>
                </div>
                <p class="rule-tip">
                  <AppIcon name="info" :size="13" />
                  <span>留空表示不限制；Content-Type 在响应阶段匹配，因此不能配置 Cache Key 请求头。</span>
                </p>
              </div>
            </section>

            <section class="rule-block">
              <header class="rule-block-head">
                <h4>缓存策略</h4>
                <span>命中后如何处理与缓存多久</span>
              </header>
              <div class="rule-block-body">
                <div class="rule-action-row">
                  <div class="field">
                    <label class="field-label">缓存动作</label>
                    <div class="segmented rule-segmented">
                      <button v-for="opt in actionOptions" :key="opt.value" type="button"
                        :class="{ active: form.action === opt.value }" @click="form.action = opt.value">
                        {{ opt.label }}
                      </button>
                    </div>
                  </div>
                  <div class="field rule-priority">
                    <label class="field-label">优先级</label>
                    <input v-model.number="form.priority" class="input" type="number" title="数值越大越优先" />
                  </div>
                </div>
                <span class="field-hint rule-action-hint">{{ actionHint }}</span>

                <div v-if="form.action === 'cache'" class="ttl-grid">
                  <div class="field">
                    <label class="field-label">边缘 TTL</label>
                    <div class="input-affix">
                      <input v-model.number="form.ttl_seconds" class="input" type="number" min="1" />
                      <span>秒</span>
                    </div>
                  </div>
                  <div class="field">
                    <label class="field-label">SWR</label>
                    <div class="input-affix">
                      <input v-model.number="form.swr_seconds" class="input" type="number" min="0" />
                      <span>秒</span>
                    </div>
                  </div>
                  <div class="field">
                    <label class="field-label">浏览器 TTL</label>
                    <div class="input-affix">
                      <input v-model.number="form.browser_ttl_seconds" class="input" type="number" min="0" />
                      <span>秒</span>
                    </div>
                  </div>
                </div>

              </div>
            </section>
          </div>

          <aside class="rule-side">
            <section v-if="!editing" class="rule-block">
              <header class="rule-block-head">
                <h4>快速模板</h4>
                <span>一键套用常用策略</span>
              </header>
              <div class="rule-block-body rule-presets">
                <button v-for="p in presets" :key="p.label" class="rule-preset" type="button" @click="applyPreset(p)">
                  {{ p.label }}
                </button>
              </div>
            </section>

            <section class="rule-block">
              <header class="rule-block-head">
                <h4>附加选项</h4>
                <span>Cookie 与备注</span>
              </header>
              <div class="rule-block-body">
                <label class="option-row">
                  <div>
                    <div class="option-title">忽略 Cookie</div>
                    <div class="option-desc">仅用于公共静态资源。</div>
                  </div>
                  <span class="switch" :class="{ on: form.ignore_cookie }">
                    <span class="switch-track" />
                    <input v-model="form.ignore_cookie" type="checkbox" style="display: none" />
                  </span>
                </label>

                <div class="field">
                  <label class="field-label">备注</label>
                  <input v-model="form.note" class="input" placeholder="可选，便于团队识别" maxlength="200" />
                </div>
              </div>
            </section>

            <section class="rule-block">
              <header class="rule-block-head">
                <h4>Cache Key 组成</h4>
                <span>区分缓存对象的维度</span>
              </header>
              <div class="rule-block-body">
                <div class="key-table">
                  <div class="key-row">
                    <div class="key-name">
                      <div>Query</div>
                      <small>URL 查询串</small>
                    </div>
                    <div class="key-toggle">
                      <button type="button" :class="{ active: form.ignore_query === 'inherit' }"
                        @click="form.ignore_query = 'inherit'">继承</button>
                      <button type="button" :class="{ active: form.ignore_query === 'on' }"
                        @click="form.ignore_query = 'on'">忽略</button>
                      <button type="button" :class="{ active: form.ignore_query === 'off' }"
                        @click="form.ignore_query = 'off'">区分</button>
                    </div>
                  </div>

                  <div class="key-row">
                    <div class="key-name">
                      <div>Origin</div>
                      <small>CORS 来源</small>
                    </div>
                    <div class="key-toggle">
                      <button type="button" :class="{ active: form.origin_mode === 'inherit' }"
                        @click="form.origin_mode = 'inherit'">继承</button>
                      <button type="button" :class="{ active: form.origin_mode === 'ignore' }"
                        @click="form.origin_mode = 'ignore'">忽略</button>
                      <button type="button" :class="{ active: form.origin_mode === 'keep' }"
                        @click="form.origin_mode = 'keep'">区分</button>
                    </div>
                  </div>

                  <div class="key-row">
                    <div class="key-name">
                      <div>Language</div>
                      <small>Accept-Language</small>
                    </div>
                    <div class="key-toggle">
                      <button type="button" :class="{ active: form.language_mode === 'inherit' }"
                        @click="form.language_mode = 'inherit'">继承</button>
                      <button type="button" :class="{ active: form.language_mode === 'ignore' }"
                        @click="form.language_mode = 'ignore'">忽略</button>
                      <button type="button" :class="{ active: form.language_mode === 'keep' }"
                        @click="form.language_mode = 'keep'">区分</button>
                    </div>
                  </div>
                </div>
                <div class="key-note">
                  「继承」跟随域名设置；忽略后对应 Vary 也按忽略处理。
                </div>
              </div>
            </section>
          </aside>
        </div>

        <p v-if="error" class="rule-error">{{ error }}</p>
      </div>
    </BaseModal>

    <BaseModal v-model="testerOpen" title="规则测试" width="780px">
      <div class="tester-modal">
        <p class="tester-lead">
          输入一次请求，查看会命中哪条规则、最终生效的缓存策略。
        </p>

        <div class="tester-grid">
          <div class="field">
            <label class="field-label">域名 <span class="req">*</span></label>
            <select v-model="tester.domain_id" class="select">
              <option value="">选择域名</option>
              <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
            </select>
          </div>

          <div class="field">
            <label class="field-label">请求方法</label>
            <select v-model="tester.method" class="select">
              <option v-for="m in methodOptions" :key="m" :value="m">{{ m }}</option>
            </select>
          </div>

          <div class="field span-2">
            <label class="field-label">请求路径 <span class="req">*</span></label>
            <input v-model="tester.path" class="input" placeholder="/static/app.js" />
          </div>

          <div class="field">
            <label class="field-label">查询串（可选）</label>
            <input v-model="tester.query" class="input" placeholder="例如 v=1" />
          </div>

          <div class="field">
            <label class="field-label">Content-Type（可选）</label>
            <input v-model="tester.content_type" class="input" placeholder="例如 video/mp4" />
          </div>
        </div>

        <p class="tester-hint">
          提示：Content-Type 条件只在源站响应返回后生效。若请求阶段命中了 `/api/*` 等 bypass
          兜底规则，即使响应是 video/mp4，也不会读写缓存；需要额外添加一条不带 Content-Type 的路径 cache 规则。
        </p>

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
                <span class="eff-value">{{ testResult.effective.action === 'cache' ?
                  `${testResult.effective.ttl_seconds}
                  秒` : '—' }}</span>
              </div>
              <div class="effective-item">
                <span class="eff-label">SWR</span>
                <span class="eff-value">{{ testResult.effective.swr_seconds ? `${testResult.effective.swr_seconds} 秒` :
                  '—' }}</span>
              </div>
              <div class="effective-item">
                <span class="eff-label">浏览器 TTL</span>
                <span class="eff-value">{{ testResult.effective.browser_ttl_seconds ?
                  `${testResult.effective.browser_ttl_seconds} 秒` : '跟随源站' }}</span>
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

      <template #footer>
        <button class="btn btn-default" type="button" @click="testerOpen = false">关闭</button>
        <button class="btn btn-primary" type="button" :disabled="testing" @click="runTest">
          {{ testing ? '测试中…' : '开始测试' }}
        </button>
      </template>
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

const tester = ref({ domain_id: '', path: '/', method: 'GET', query: '', content_type: '' })
const testing = ref(false)
const testResult = ref<any>(null)
const testerOpen = ref(false)

const formOpen = ref(false)
const editing = ref<any>(null)
const error = ref('')
const form = ref({
  domain_id: '',
  path_pattern: '/*',
  match_type: 'glob',
  action: 'cache',
  ttl_seconds: 60,
  swr_seconds: 0,
  browser_ttl_seconds: 0,
  methods: [] as string[],
  match_query: '',
  match_content_type: '',
  ignore_query: 'inherit' as 'inherit' | 'on' | 'off',
  ignore_cookie: false,
  origin_mode: 'inherit' as 'inherit' | 'ignore' | 'keep',
  language_mode: 'inherit' as 'inherit' | 'ignore' | 'keep',
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
  { label: 'CSS/JS 后缀 7 天', path: '\\.(css|js)$', matchType: 'regex', ignoreCookie: true, ttl: 604800, swr: 86400, browser: 604800, methods: ['GET', 'HEAD'] },
  { label: '静态资源 7 天', path: '/static/*', ttl: 604800, swr: 86400, browser: 604800, methods: ['GET', 'HEAD'] },
  { label: '图片 30 天', path: '/images/*', ttl: 2592000, swr: 86400, browser: 2592000, methods: ['GET', 'HEAD'] },
  { label: 'HTML 5 分钟', path: '/', ttl: 300, swr: 60, browser: 300, methods: ['GET', 'HEAD'] },
  { label: 'API 不缓存', path: '/api/*', bypass: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] },
  { label: '下载 1 天', path: '/download/*', ttl: 86400, swr: 3600, browser: 86400, methods: ['GET', 'HEAD'] },
]

const actionHint = computed(() => {
  if (form.value.action === 'bypass') return '请求不读也不写缓存，直接回源（适合登录态、动态接口）。'
  if (form.value.action === 'no_store') return '照常回源，但响应不写入缓存。'
  return '按 TTL 缓存响应；源站 no-store / private / no-cache / max-age=0 仍会阻止写入。'
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

const previewMethods = computed(() =>
  form.value.methods.length ? form.value.methods.join(' · ') : 'ALL',
)

const previewDomain = computed(() => {
  if (editing.value?.domain_name) return editing.value.domain_name
  return domains.value.find((d) => d.id === form.value.domain_id)?.name || '未选择域名'
})

function formatDuration(seconds: number) {
  const value = Number(seconds) || 0
  if (value <= 0) return '跟随源站'
  if (value % 86400 === 0) return `${value / 86400} 天`
  if (value % 3600 === 0) return `${value / 3600} 小时`
  if (value % 60 === 0) return `${value / 60} 分钟`
  return `${value} 秒`
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
  form.value.match_type = preset.matchType || 'glob'
  form.value.match_content_type = ''
  form.value.ignore_cookie = !!preset.ignoreCookie
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
    match_type: 'glob',
    action: 'cache',
    ttl_seconds: 60,
    swr_seconds: 0,
    browser_ttl_seconds: 0,
    methods: [],
    match_query: '',
    match_content_type: '',
    ignore_query: 'inherit',
    ignore_cookie: false,
    origin_mode: 'inherit',
    language_mode: 'inherit',
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
    match_type: rule.match_type || 'glob',
    action: rule.action,
    ttl_seconds: rule.ttl_seconds,
    swr_seconds: rule.swr_seconds,
    browser_ttl_seconds: rule.browser_ttl_seconds,
    methods: rule.match_methods ? String(rule.match_methods).split(',').filter(Boolean) : [],
    match_query: rule.match_query || '',
    match_content_type: rule.match_content_type || '',
    ignore_query: rule.ignore_query === true ? 'on' : rule.ignore_query === false ? 'off' : 'inherit',
    ignore_cookie: !!rule.ignore_cookie,
    origin_mode: parseKeyHeaderMode(rule.ignore_key_headers, 'origin'),
    language_mode: parseKeyHeaderMode(rule.ignore_key_headers, 'accept-language'),
    priority: rule.priority,
    enabled: rule.enabled,
    note: rule.note || '',
  }
  formOpen.value = true
}

type KeyHeaderMode = 'inherit' | 'ignore' | 'keep'

function parseKeyHeaderMode(raw: any, name: string): KeyHeaderMode {
  if (raw == null) return 'inherit'
  const value = String(raw).trim()
  if (value.includes('=')) {
    const part = value
      .split(',')
      .map((v) => v.trim())
      .find((v) => v.split('=')[0]?.trim().toLowerCase() === name)
    const state = part?.split('=')[1]?.trim().toLowerCase()
    return state === 'ignore' ? 'ignore' : state === 'keep' ? 'keep' : 'inherit'
  }
  if (!value) return 'keep'
  return value
    .split(',')
    .some((v) => v.trim().toLowerCase() === name)
    ? 'ignore'
    : 'keep'
}

function keyHeaderLabel(raw: any) {
  if (raw == null) return ''
  const origin = parseKeyHeaderMode(raw, 'origin')
  const language = parseKeyHeaderMode(raw, 'accept-language')
  const labels: string[] = []
  if (origin === 'ignore') labels.push('忽略 Origin')
  else if (origin === 'keep') labels.push('区分 Origin')
  if (language === 'ignore') labels.push('忽略语言')
  else if (language === 'keep') labels.push('区分语言')
  return labels.join(' · ')
}

function payload() {
  return {
    path_pattern: form.value.path_pattern.trim(),
    match_type: form.value.match_type,
    action: form.value.action,
    ttl_seconds: Number(form.value.ttl_seconds) || 0,
    swr_seconds: Number(form.value.swr_seconds) || 0,
    browser_ttl_seconds: Number(form.value.browser_ttl_seconds) || 0,
    match_methods: form.value.methods.join(','),
    match_query: form.value.match_query.trim(),
    match_content_type: form.value.match_content_type.trim(),
    ignore_query: form.value.ignore_query === 'inherit' ? null : form.value.ignore_query === 'on',
    ignore_cookie: form.value.ignore_cookie,
    ignore_key_headers:
      form.value.origin_mode === 'inherit' && form.value.language_mode === 'inherit'
        ? null
        : `origin=${form.value.origin_mode},accept-language=${form.value.language_mode}`,
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

function openTester() {
  if (!tester.value.domain_id && domains.value.length) {
    tester.value.domain_id = domains.value[0].id
  }
  testerOpen.value = true
}

async function runTest() {
  if (!tester.value.domain_id) {
    toast.error('请先选择域名')
    return
  }
  testing.value = true
  testResult.value = null
  try {
    testResult.value = await api.post('/api/v1/rules/test', {
      domain_id: tester.value.domain_id,
      path: tester.value.path || '/',
      method: tester.value.method,
      query: tester.value.query,
      content_type: tester.value.content_type || null,
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
.tester-modal {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.tester-lead {
  margin: 0;
  color: var(--text-3);
  font-size: 13px;
  line-height: 1.65;
}

.tester-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px 14px;
}

.tester-grid .span-2 {
  grid-column: span 2;
}

.tester-hint {
  margin: 0;
  padding: 9px 11px;
  border: 1px solid var(--divider);
  border-radius: var(--radius-sm);
  background: var(--bg);
  color: var(--text-3);
  font-size: 12px;
  line-height: 1.6;
}

.test-result {
  margin: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  background: var(--bg);
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
  background: var(--card);
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

.chip-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.chip {
  padding: 4px 8px;
  font-size: 12px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--card);
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

/* --------------------------------------------------------- rule editor */

.rule-editor {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

/* --- compact live summary ------------------------------------------- */

.rule-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 11px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background:
    linear-gradient(120deg, var(--brand-bg), transparent 62%),
    var(--bg);
}

.rule-summary-main {
  min-width: 0;
}

.rule-summary-path {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rule-summary-tags {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 5px;
  margin-top: 6px;
}

.rule-tag {
  padding: 1px 7px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--card);
  color: var(--text-3);
  font-size: 11px;
  line-height: 16px;
  white-space: nowrap;
}

.rule-tag.tone-success {
  border-color: transparent;
  background: var(--success-bg);
  color: var(--success);
}

.rule-tag.tone-warning {
  border-color: transparent;
  background: var(--warning-bg);
  color: var(--warning);
}

.rule-tag.tone-danger {
  border-color: transparent;
  background: var(--danger-bg);
  color: var(--danger);
}

.rule-summary-switch {
  flex: none;
  gap: 8px;
}

.rule-summary-switch-text {
  font-size: 12px;
  color: var(--text-3);
}

/* --- two column shell ----------------------------------------------- */

.rule-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 296px;
  gap: 12px;
  align-items: start;
}

.rule-main,
.rule-side {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-width: 0;
}

/* --- flat blocks ---------------------------------------------------- */

.rule-block {
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--card);
  overflow: hidden;
}

.rule-block-head {
  display: flex;
  align-items: baseline;
  gap: 8px;
  padding: 9px 13px;
  border-bottom: 1px solid var(--divider);
  background: #fbfcfd;
}

.rule-block-head h4 {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
}

.rule-block-head span {
  font-size: 11px;
  color: var(--text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rule-block-body {
  display: flex;
  flex-direction: column;
  gap: 11px;
  padding: 12px 13px 13px;
}

.rule-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 11px 12px;
}

.rule-grid .span-2 {
  grid-column: 1 / -1;
}

.rule-grid-match {
  grid-template-columns: 168px minmax(0, 1fr);
}

.rule-block .field {
  gap: 5px;
}

.rule-block .field-label {
  font-size: 12px;
}

.rule-block .field-hint {
  font-size: 11px;
  line-height: 1.45;
}

.rule-segmented {
  display: flex;
  width: 100%;
}

.rule-action-row {
  display: flex;
  align-items: flex-end;
  gap: 10px;
}

.rule-action-row .field:first-child {
  flex: 1;
  min-width: 0;
}

.rule-priority {
  flex: none;
  width: 104px;
}

.rule-action-hint {
  margin-top: -4px;
}

.rule-segmented button {
  flex: 1;
  height: 30px;
  padding: 0 10px;
  font-size: 12.5px;
}

.path-combo {
  display: grid;
  grid-template-columns: 106px minmax(0, 1fr);
  gap: 8px;
}

.ttl-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 9px;
}

.input-affix {
  position: relative;
}

.input-affix .input {
  padding-right: 30px;
}

.input-affix > span {
  position: absolute;
  top: 50%;
  right: 9px;
  transform: translateY(-50%);
  font-size: 11px;
  color: var(--text-3);
  pointer-events: none;
}

.rule-tip {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  margin: 0;
  padding: 7px 9px;
  border-radius: var(--radius);
  background: var(--brand-bg);
  color: var(--text-2);
  font-size: 11px;
  line-height: 1.5;
}

.rule-tip .app-icon {
  flex: none;
  margin-top: 1px;
  color: var(--brand);
}

/* --- side column ---------------------------------------------------- */

.rule-presets {
  flex-direction: row;
  flex-wrap: wrap;
  gap: 6px;
  padding: 11px 12px 12px;
}

.rule-preset {
  padding: 3px 9px;
  border: 1px dashed var(--border-strong);
  border-radius: 999px;
  background: transparent;
  color: var(--text-2);
  font-size: 11.5px;
  line-height: 17px;
  cursor: pointer;
  transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
}

.rule-preset:hover {
  border-color: var(--brand);
  background: var(--brand-bg);
  color: var(--brand);
}

.option-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 10px;
  border: 1px solid var(--divider);
  border-radius: var(--radius);
  background: var(--bg);
  cursor: pointer;
}

.option-title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-2);
}

.option-desc {
  margin-top: 1px;
  font-size: 11px;
  color: var(--text-3);
}

.key-table {
  border: 1px solid var(--divider);
  border-radius: var(--radius);
  overflow: hidden;
}

.key-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 126px;
  align-items: center;
  gap: 8px;
  padding: 7px 9px;
  background: var(--bg);
}

.key-row + .key-row {
  border-top: 1px solid var(--divider);
}

.key-name > div {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-2);
}

.key-name small {
  display: block;
  margin-top: 1px;
  font-size: 10px;
  color: var(--text-4);
}

.key-toggle {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 2px;
  padding: 2px;
  border-radius: 7px;
  background: var(--card);
}

.key-toggle button {
  height: 24px;
  padding: 0;
  border: none;
  border-radius: 5px;
  background: transparent;
  color: var(--text-3);
  font-size: 11px;
  cursor: pointer;
}

.key-toggle button:hover {
  color: var(--text);
}

.key-toggle button.active {
  background: var(--brand);
  color: #fff;
  font-weight: 500;
  box-shadow: var(--shadow-sm);
}

.key-note {
  font-size: 11px;
  line-height: 1.5;
  color: var(--text-3);
}

.rule-error {
  margin: 0;
  padding: 8px 10px;
  border-radius: var(--radius);
  background: var(--danger-bg);
  font-size: 12px;
  color: var(--danger);
}

@media (max-width: 860px) {
  .rule-layout {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (max-width: 760px) {
  .rule-summary {
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }

  .rule-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .rule-grid .span-2 {
    grid-column: auto;
  }

  .path-combo,
  .ttl-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .rule-action-row {
    flex-direction: column;
    align-items: stretch;
  }

  .rule-priority {
    width: auto;
  }

  .effective-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .tester-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .tester-grid .span-2 {
    grid-column: auto;
  }
}
</style>
