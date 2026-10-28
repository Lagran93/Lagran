<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">域名接入向导</div>
        <div class="page-desc">按步骤完成域名、源站、证书和 DNS 配置，并立即验证接入状态</div>
      </div>
      <NuxtLink to="/domains" class="btn btn-default">
        <AppIcon name="chevron-left" :size="15" />
        返回域名管理
      </NuxtLink>
    </div>

    <div class="wizard-steps">
      <div v-for="(s, i) in steps" :key="s" class="wizard-step" :class="{ active: step === i, done: step > i }">
        <span class="wizard-index">{{ step > i ? '✓' : i + 1 }}</span>
        <span>{{ s }}</span>
      </div>
    </div>

    <div class="card">
      <div class="card-body">
        <div v-if="step === 0" class="form-col">
          <div class="wizard-hero">
            <div class="wizard-icon"><AppIcon name="domain" :size="24" /></div>
            <div>
              <div class="wizard-title">要加速哪个域名？</div>
              <div class="wizard-desc">通常使用业务子域名，例如 static.example.com 或 cdn.example.com。</div>
            </div>
          </div>
          <div class="field">
            <label class="field-label">加速域名 <span class="req">*</span></label>
            <input v-model="form.name" class="input" placeholder="cdn.example.com" @keyup.enter="next" />
            <span class="field-hint">只填写主机名，不带 https:// 或路径。</span>
          </div>
        </div>

        <div v-else-if="step === 1" class="form-col">
          <div class="wizard-hero">
            <div class="wizard-icon"><AppIcon name="node" :size="24" /></div>
            <div>
              <div class="wizard-title">源站从哪里取内容？</div>
              <div class="wizard-desc">填写当前服务器或对象存储的地址。接入后会由边缘节点回源。</div>
            </div>
          </div>
          <div class="form-grid">
            <div class="field">
              <label class="field-label">源站协议</label>
              <select v-model="form.origin_proto" class="select">
                <option value="https">HTTPS</option>
                <option value="http">HTTP</option>
              </select>
            </div>
            <div class="field">
              <label class="field-label">源站端口</label>
              <input v-model.number="form.origin_port" class="input" type="number" />
            </div>
          </div>
          <div class="field">
            <label class="field-label">源站主机 <span class="req">*</span></label>
            <input v-model="form.origin_host" class="input" placeholder="origin.example.com 或 203.0.113.10" />
            <span class="field-hint">支持 IP、域名；端口需对边缘节点网络可达。</span>
          </div>
        </div>

        <div v-else-if="step === 2" class="form-col">
          <div class="wizard-hero">
            <div class="wizard-icon"><AppIcon name="cert" :size="24" /></div>
            <div>
              <div class="wizard-title">开启 HTTPS 与归属项目</div>
              <div class="wizard-desc">可选配置。开启 HTTPS 后需要为域名准备有效证书。</div>
            </div>
          </div>
          <label class="check">
            <input v-model="form.ssl_enabled" type="checkbox" />
            开启 HTTPS（HTTP 请求将 301/308 跳转到 HTTPS）
          </label>
          <div class="field">
            <label class="field-label">所属项目</label>
            <select v-model="form.project_id" class="select">
              <option value="">自动归入个人项目</option>
              <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>
          <div class="alert alert-info">
            <AppIcon name="info" :size="16" class="icon" />
            <span>创建后请到「证书管理」上传或签发证书，再执行诊断。</span>
          </div>
        </div>

        <div v-else class="form-col">
          <div class="wizard-hero">
            <div class="wizard-icon"><AppIcon name="check" :size="24" /></div>
            <div>
              <div class="wizard-title">配置 DNS 并验证接入</div>
              <div class="wizard-desc">将域名 CNAME 到任意在线边缘节点，或直接解析到节点 IP。</div>
            </div>
          </div>

          <div v-if="domainId" class="result-box">
            <div class="result-title">域名已创建</div>
            <div class="mono">{{ form.name }}</div>
            <div class="text-muted" style="font-size: 12px; margin-top: 4px">
              ID: {{ domainId }}
            </div>
          </div>

          <div class="dns-box">
            <div v-if="endpoints.cname" class="dns-row">
              <span class="dns-type">CNAME</span>
              <code>{{ form.name }}</code>
              <span class="text-muted">→</span>
              <code>{{ endpoints.cname }}</code>
              <button class="btn btn-text btn-sm" type="button" @click="copy(endpoints.cname)">复制</button>
            </div>
            <div v-else-if="nodeIps.length" class="dns-row">
              <span class="dns-type">A</span>
              <code>{{ form.name }}</code>
              <span class="text-muted">→</span>
              <code>{{ nodeIps[0] }}</code>
              <button class="btn btn-text btn-sm" type="button" @click="copy(nodeIps[0])">复制</button>
            </div>
            <div v-else class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <span>暂无在线边缘节点。请联系管理员启动节点，或配置统一边缘接入域名后再设置 DNS。</span>
            </div>
            <div v-if="nodeIps.length" class="text-muted" style="font-size: 12px; margin-top: 8px">
              可解析到任意在线节点 IP：{{ nodeIps.join(', ') }}。如果使用 CNAME，请指向管理员提供的统一边缘接入域名。
            </div>
          </div>

          <div class="flex-between">
            <span class="text-muted" style="font-size: 12px">DNS 生效后再执行诊断，通常需要几分钟。</span>
            <button class="btn btn-primary" type="button" :disabled="diagnosing" @click="diagnose">
              {{ diagnosing ? '诊断中…' : '立即诊断' }}
            </button>
          </div>

          <div v-if="diag" class="diag-grid">
            <div v-for="c in diag.checks" :key="c.key" class="diag-card" :class="{ bad: !c.ok }">
              <div class="diag-head">
                <AppIcon :name="c.ok ? 'check' : 'close'" :size="16" />
                <strong>{{ c.label }}</strong>
                <span class="text-muted">{{ c.latency_ms }} ms</span>
              </div>
              <div class="diag-detail">{{ c.detail }}</div>
            </div>
          </div>
        </div>

        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>

        <div class="wizard-foot">
          <button v-if="step > 0" class="btn btn-default" type="button" @click="step -= 1">上一步</button>
          <span class="spacer" />
          <button v-if="step < 2" class="btn btn-primary" type="button" :disabled="!canNext" @click="next">
            下一步
          </button>
          <button v-else-if="step === 2" class="btn btn-primary" type="button" :disabled="submitting" @click="createDomain">
            {{ submitting ? '创建中…' : '创建并继续' }}
          </button>
          <NuxtLink v-if="step === 3" to="/domains" class="btn btn-primary">完成，返回域名列表</NuxtLink>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()

const steps = ['选择域名', '配置源站', 'HTTPS / 项目', 'DNS 与验证']
const step = ref(0)
const submitting = ref(false)
const diagnosing = ref(false)
const error = ref('')
const projects = ref<any[]>([])
const endpoints = ref<{ cname: string; ips: string[]; nodes: any[] }>({
  cname: '',
  ips: [],
  nodes: [],
})
const domainId = ref('')
const diag = ref<any>(null)

const form = ref({
  name: '',
  origin_host: '',
  origin_port: 443,
  origin_proto: 'https',
  ssl_enabled: true,
  project_id: '',
})

const canNext = computed(() => {
  if (step.value === 0) return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(form.value.name.trim())
  if (step.value === 1) return !!form.value.origin_host.trim() && form.value.origin_port > 0
  return true
})

const nodeIps = computed(() => endpoints.value.ips)

async function next() {
  error.value = ''
  if (!canNext.value) {
    error.value = step.value === 0 ? '请输入有效的域名，例如 cdn.example.com' : '请填写源站主机和端口'
    return
  }
  step.value += 1
}

async function createDomain() {
  error.value = ''
  submitting.value = true
  try {
    const row = await api.post<any>('/api/v1/domains', {
      name: form.value.name.trim().toLowerCase(),
      origin_host: form.value.origin_host.trim(),
      origin_port: form.value.origin_port,
      origin_proto: form.value.origin_proto,
      ssl_enabled: form.value.ssl_enabled,
      project_id: form.value.project_id || undefined,
    })
    domainId.value = row.id
    step.value = 3
    await loadNodes()
  } catch (e: any) {
    error.value = e?.data?.error || '创建域名失败'
  } finally {
    submitting.value = false
  }
}

async function diagnose() {
  if (!domainId.value) return
  diagnosing.value = true
  try {
    diag.value = await api.post<any>(`/api/v1/domains/${domainId.value}/diagnose`, {})
  } catch (e: any) {
    toast.error(e?.data?.error || '诊断失败')
  } finally {
    diagnosing.value = false
  }
}

async function loadNodes() {
  try {
    const data = await api.get<any>('/api/v1/edge-endpoints')
    endpoints.value = {
      cname: data?.cname || '',
      ips: data?.ips || [],
      nodes: data?.nodes || [],
    }
  } catch {
    endpoints.value = { cname: '', ips: [], nodes: [] }
  }
}

function copy(text: string) {
  if (!import.meta.client) return
  navigator.clipboard?.writeText(text).then(() => toast.success('已复制')).catch(() => {})
}

onMounted(async () => {
  try {
    projects.value = (await api.get<any[]>('/api/v1/projects')) || []
  } catch {
    projects.value = []
  }
  await loadNodes()
})
</script>

<style scoped>
.wizard-steps {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.wizard-step {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-radius: 20px;
  background: var(--card);
  border: 1px solid var(--border);
  font-size: 13px;
  color: var(--text-3);
}

.wizard-step.active {
  border-color: var(--brand);
  color: var(--brand);
  background: var(--brand-bg);
}

.wizard-step.done {
  color: var(--success);
  border-color: var(--success-border);
}

.wizard-index {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: var(--bg);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
}

.wizard-hero {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  margin-bottom: 8px;
}

.wizard-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: var(--brand-bg);
  color: var(--brand);
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.wizard-title {
  font-size: 17px;
  font-weight: 600;
}

.wizard-desc {
  margin-top: 4px;
  font-size: 13px;
  color: var(--text-3);
}

.wizard-foot {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 20px;
  padding-top: 16px;
  border-top: 1px solid var(--divider);
}

.result-box,
.dns-box {
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg);
}

.result-title {
  font-size: 12px;
  color: var(--text-3);
  margin-bottom: 4px;
}

.dns-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.dns-type {
  background: var(--brand-bg);
  color: var(--brand);
  border-radius: 4px;
  font-size: 11px;
  padding: 3px 8px;
  font-weight: 600;
}

.diag-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin-top: 12px;
}

.diag-card {
  border: 1px solid var(--success-border);
  background: var(--success-bg);
  border-radius: var(--radius);
  padding: 12px;
}

.diag-card.bad {
  border-color: var(--danger-border);
  background: var(--danger-bg);
}

.diag-head {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
}

.diag-head .text-muted {
  margin-left: auto;
  font-size: 11px;
}

.diag-detail {
  margin-top: 6px;
  font-size: 12px;
  color: var(--text-2);
  line-height: 1.6;
  word-break: break-all;
}

@media (max-width: 640px) {
  .diag-grid {
    grid-template-columns: 1fr;
  }
}
</style>
