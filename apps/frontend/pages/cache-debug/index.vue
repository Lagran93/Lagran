<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">缓存诊断</div>
        <div class="page-desc">模拟一次真实请求，读取边缘返回的 X-Lagran-Cache-Reason，定位“为什么没有缓存”</div>
      </div>
    </div>

    <div class="grid grid-main-side">
      <div class="card">
        <div class="card-head">
          <div class="card-title">请求条件</div>
        </div>
        <div class="card-body">
          <div class="form-col">
            <div class="field">
              <label class="field-label">域名 <span class="req">*</span></label>
              <select v-model="form.domain" class="select">
                <option value="">请选择域名</option>
                <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
              </select>
            </div>
            <div class="form-grid">
              <div class="field">
                <label class="field-label">协议</label>
                <select v-model="form.scheme" class="select">
                  <option value="">跟随域名配置</option>
                  <option value="https">HTTPS</option>
                  <option value="http">HTTP</option>
                </select>
              </div>
              <div class="field">
                <label class="field-label">路径 <span class="req">*</span></label>
                <input v-model="form.path" class="input" placeholder="/static/app.js" />
              </div>
            </div>
            <div class="field">
              <label class="field-label">模拟请求头</label>
              <div class="diag-options">
                <label class="check">
                  <input v-model="form.simulate_cookie" type="checkbox" />
                  携带 Cookie
                </label>
                <label class="check">
                  <input v-model="form.simulate_authorization" type="checkbox" />
                  携带 Authorization
                </label>
                <label class="check">
                  <input v-model="form.no_store" type="checkbox" />
                  Cache-Control: no-store
                </label>
                <label class="check">
                  <input v-model="form.no_cache" type="checkbox" />
                  Cache-Control: no-cache
                </label>
              </div>
            </div>
            <div class="flex-between">
              <span class="text-muted" style="font-size: 12px">
                诊断请求会真实经过边缘节点，可能命中或写入缓存。
              </span>
              <button class="btn btn-primary" type="button" :disabled="loading" @click="diagnose">
                <AppIcon name="search" :size="15" />
                {{ loading ? '诊断中…' : '开始诊断' }}
              </button>
            </div>
            <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="card-title">诊断说明</div>
        </div>
        <div class="card-body tips">
          <div class="tip-row">
            <span class="tip-index">1</span>
            <span>响应头 `X-Lagran-Cache-Reason` 会给出具体绕过原因。</span>
          </div>
          <div class="tip-row">
            <span class="tip-index">2</span>
            <span>常见原因：Cookie、Authorization、Range、no-store、no-cache、Vary。</span>
          </div>
          <div class="tip-row">
            <span class="tip-index">3</span>
            <span>规则 bypass 显示为 `rule-bypass`，Content-Type 规则显示为 `content-type-bypass`。</span>
          </div>
          <div class="tip-row">
            <span class="tip-index">4</span>
            <span>若诊断请求本身命中缓存，会显示 `hit`；可先刷新后重试。</span>
          </div>
        </div>
      </div>
    </div>

    <div v-if="result" class="card mt-16">
      <div class="card-head">
        <div>
          <div class="card-title">诊断结果</div>
          <div class="card-desc mono">{{ result.url }}</div>
        </div>
        <div class="card-extra flex-center gap-8">
          <StatusTag :tone="result.status < 400 ? 'info' : 'danger'">HTTP {{ result.status }}</StatusTag>
          <StatusTag :tone="reasonTone(result.cache_reason)">{{ result.cache_reason }}</StatusTag>
          <StatusTag tone="neutral">{{ result.cache_status }}</StatusTag>
        </div>
      </div>
      <div class="card-body">
        <div class="diagnosis-advice">
          <AppIcon name="info" :size="18" />
          <span>{{ result.advice }}</span>
        </div>

        <div class="section-label">响应头</div>
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Header</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="h in result.headers" :key="h[0]">
                <td class="mono">{{ h[0] }}</td>
                <td class="mono" style="word-break: break-all">{{ h[1] }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="result.body_preview" class="section-label">响应预览</div>
        <pre v-if="result.body_preview" class="body-preview">{{ result.body_preview }}</pre>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()

const domains = ref<any[]>([])
const loading = ref(false)
const error = ref('')
const result = ref<any>(null)

const form = ref({
  domain: '',
  scheme: '',
  path: '/',
  simulate_cookie: false,
  simulate_authorization: false,
  no_store: false,
  no_cache: false,
})

async function loadDomains() {
  try {
    domains.value = (await api.get<any[]>('/api/v1/domains')) || []
  } catch {
    domains.value = []
  }
}

function reasonTone(reason: string) {
  if (reason === 'hit' || reason === 'stale') return 'success'
  if (reason === 'unknown' || reason === 'stored-or-miss') return 'info'
  return 'warning'
}

async function diagnose() {
  error.value = ''
  result.value = null
  if (!form.value.domain) {
    toast.error('请选择域名')
    return
  }
  if (!form.value.path.trim()) {
    toast.error('请填写路径')
    return
  }
  let cacheControl = ''
  if (form.value.no_store) cacheControl = 'no-store'
  else if (form.value.no_cache) cacheControl = 'no-cache'
  loading.value = true
  try {
    result.value = await api.post<any>('/api/v1/cache/diagnose', {
      domain: form.value.domain,
      path: form.value.path.trim(),
      scheme: form.value.scheme || null,
      simulate_cookie: form.value.simulate_cookie,
      simulate_authorization: form.value.simulate_authorization,
      request_cache_control: cacheControl || null,
    })
  } catch (e: any) {
    error.value = e?.data?.error || '诊断请求失败'
  } finally {
    loading.value = false
  }
}

onMounted(loadDomains)
</script>

<style scoped>
.diag-options {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.diagnosis-advice {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  padding: 14px 16px;
  background: var(--brand-bg);
  border: 1px solid var(--brand-bg-strong);
  border-radius: var(--radius-lg);
  color: var(--text-2);
  line-height: 1.7;
  font-size: 13.5px;
}

.body-preview {
  margin: 0;
  padding: 14px;
  background: #f7f8fa;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text-2);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 260px;
  overflow: auto;
}

@media (max-width: 640px) {
  .diag-options {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
