<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">证书管理</div>
        <div class="page-desc">为域名上传或签发 TLS 证书，边缘节点会自动热加载</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-default" type="button" @click="openIssue">
          <AppIcon name="zap" :size="15" />
          自动签发
        </button>
        <button class="btn btn-primary" type="button" @click="openUpload">
          <AppIcon name="upload" :size="15" />
          上传证书
        </button>
      </div>
    </div>

    <div class="alert alert-warning mb-16">
      <AppIcon name="alert" :size="16" class="icon" />
      <span>
        自动签发支持 Let's Encrypt（ACME v2 / HTTP-01）。生产域名请先接入并解析到边缘节点；
        首次配置可使用预发布校验，避免触发生产速率限制。
      </span>
    </div>

    <div class="card">
      <div v-if="activeJobs.length" class="issue-strip">
        <div v-for="job in activeJobs" :key="job.id" class="issue-row">
          <AppIcon name="zap" :size="14" class="icon" />
          <span class="issue-domain">{{ job.domain_name }}</span>
          <StatusTag status="warning">{{ jobStatusText(job.status) }}</StatusTag>
          <span class="issue-message text-muted">{{ job.message }}</span>
          <span class="issue-elapsed text-muted">{{ Math.round((job.elapsed_ms || 0) / 1000) }}s</span>
        </div>
      </div>

      <div class="filter-bar">
        <input v-model="keyword" class="input" placeholder="搜索域名" style="min-width: 220px" />
        <select v-model="statusFilter" class="select">
          <option value="">全部状态</option>
          <option value="active">有效</option>
          <option value="pending">待签发</option>
          <option value="error">异常</option>
        </select>
        <span class="spacer" />
        <span class="text-muted" style="font-size: 13px">{{ filtered.length }} 张证书</span>
      </div>

      <div v-if="filtered.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="min-width: 200px">域名</th>
              <th>状态</th>
              <th>签发者</th>
              <th>有效期至</th>
              <th>材料</th>
              <th class="text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in paged" :key="c.id">
              <td>
                <div class="cell-main">{{ c.domain_name }}</div>
                <div class="cell-sub">创建于 {{ formatDay(c.created_at) }}</div>
              </td>
              <td>
                <StatusTag :status="c.status">
                  {{ statusText(c.status) }}
                </StatusTag>
              </td>
              <td class="text-2">{{ c.issuer || '—' }}</td>
              <td>
                <div>{{ c.not_after ? formatDay(c.not_after) : '—' }}</div>
                <div v-if="expiryHint(c.not_after)" class="cell-sub" :class="expiryTone(c.not_after)">
                  {{ expiryHint(c.not_after) }}
                </div>
              </td>
              <td>
                <span class="material" :class="{ ok: c.has_cert }">
                  <AppIcon :name="c.has_cert ? 'check' : 'close'" :size="13" />
                  证书
                </span>
                <span class="material" :class="{ ok: c.has_key }">
                  <AppIcon :name="c.has_key ? 'check' : 'close'" :size="13" />
                  私钥
                </span>
              </td>
              <td class="text-right">
                <button class="btn btn-text btn-sm danger" type="button" @click="remove(c)">删除</button>
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
        icon="cert"
        title="还没有证书"
        text="上传 PEM 证书与私钥，或通过 Let's Encrypt 自动签发。"
      >
        <button class="btn btn-primary btn-sm" type="button" @click="openUpload">上传证书</button>
      </EmptyState>

      <div v-if="filtered.length > pageSize" class="table-footer">
        <AppPagination v-model:page="page" :total="filtered.length" :page-size="pageSize" />
      </div>
    </div>

    <BaseModal
      v-model="uploadOpen"
      title="上传证书"
      confirm-text="保存证书"
      :loading="submitting"
      @confirm="createCert"
    >
      <div class="form-col">
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">域名 <span class="req">*</span></label>
            <input v-model="uploadForm.domain_name" class="input" placeholder="cdn.example.com" />
          </div>
          <div class="field span-2">
            <label class="field-label">签发者</label>
            <input v-model="uploadForm.issuer" class="input" placeholder="例如 Let's Encrypt / 自签" />
          </div>
        </div>
        <div class="field">
          <label class="field-label">证书 PEM</label>
          <textarea
            v-model="uploadForm.cert_pem"
            class="textarea mono"
            rows="5"
            placeholder="-----BEGIN CERTIFICATE-----"
          />
        </div>
        <div class="field">
          <label class="field-label">私钥 PEM</label>
          <textarea
            v-model="uploadForm.key_pem"
            class="textarea mono"
            rows="5"
            placeholder="-----BEGIN PRIVATE KEY-----"
          />
        </div>
        <label class="check">
          <input v-model="uploadForm.auto_renew" type="checkbox" />
          自动续期（仅自动签发的 Let's Encrypt 证书）
        </label>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>

    <BaseModal
      v-model="issueOpen"
      title="自动签发证书"
      confirm-text="开始签发"
      :loading="submitting"
      @confirm="issueCert"
    >
      <div class="form-col">
        <div class="alert alert-info">
          <AppIcon name="info" :size="16" class="icon" />
          <span>提交后由控制面后台签发（ACME 订单、HTTP-01 校验与 CA 轮询可能耗时数十秒），进度显示在列表上方，无需停留在此页面。生产证书约 90 天有效，控制面会定期检查并自动续期。</span>
        </div>
        <div class="field">
          <label class="field-label">签发方式 <span class="req">*</span></label>
          <select v-model="issueForm.provider" class="select">
            <option value="letsencrypt">Let's Encrypt（生产）</option>
            <option value="letsencrypt-staging">Let's Encrypt（预发布校验）</option>
          </select>
        </div>
        <div class="field">
          <label class="field-label">域名 <span class="req">*</span></label>
          <input v-model="issueForm.domain_name" class="input" placeholder="cdn.example.com" />
          <span class="field-hint">域名需已接入并解析到边缘节点，否则 challenge 校验会失败。</span>
        </div>
        <label class="check">
          <input v-model="issueForm.push_to_edges" type="checkbox" />
          签发后推送到在线边缘节点
        </label>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

const certs = ref<any[]>([])
const loading = ref(false)
const submitting = ref(false)
const keyword = ref('')
const statusFilter = ref('')
const page = ref(1)
const pageSize = 10
const error = ref('')

const uploadOpen = ref(false)
const uploadForm = ref({
  domain_name: '',
  issuer: 'manual',
  cert_pem: '',
  key_pem: '',
  auto_renew: false,
})

const issueOpen = ref(false)
const issueForm = ref({
  domain_name: '',
  provider: 'letsencrypt',
  push_to_edges: true,
  auto_renew: true,
})

const filtered = computed(() => {
  const q = keyword.value.trim().toLowerCase()
  return certs.value.filter((c) => {
    if (statusFilter.value && c.status !== statusFilter.value) return false
    if (q && !String(c.domain_name).toLowerCase().includes(q)) return false
    return true
  })
})

const paged = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

watch([keyword, statusFilter], () => {
  page.value = 1
})

function statusText(status: string) {
  if (status === 'active') return '有效'
  if (status === 'pending') return '待签发'
  if (status === 'expired') return '已过期'
  return '异常'
}

function expiryHint(iso?: string) {
  const days = daysLeft(iso)
  if (days === null) return ''
  if (days < 0) return `已过期 ${Math.abs(days)} 天`
  if (days <= 30) return `${days} 天后到期`
  return ''
}

function expiryTone(iso?: string) {
  const days = daysLeft(iso)
  if (days === null) return ''
  return days < 0 ? 'text-danger' : days <= 30 ? 'text-danger' : ''
}

async function load() {
  loading.value = true
  try {
    certs.value = (await api.get<any[]>('/api/v1/certs')) || []
  } catch {
    certs.value = []
  } finally {
    loading.value = false
  }
}

// ------------------------------------------------------------ 异步签发任务
// Issuance runs in the control plane: the POST only queues a job. Polling the
// job keeps the progress strip live and reports the final outcome once, even if
// the operator reloaded the page in between (the active list is server-side).
const jobs = ref<any[]>([])
const pollingIds = new Set<string>()
let disposed = false

const activeJobs = computed(() =>
  jobs.value.filter((j) => j.status === 'pending' || j.status === 'running')
)

function jobStatusText(status: string) {
  if (status === 'pending') return '排队中'
  if (status === 'running') return '签发中'
  if (status === 'succeeded') return '已完成'
  return '失败'
}

function upsertJob(job: any) {
  const idx = jobs.value.findIndex((j) => j.id === job.id)
  if (idx >= 0) jobs.value[idx] = { ...jobs.value[idx], ...job }
  else jobs.value = [job, ...jobs.value]
}

async function loadJobs() {
  try {
    const res = await api.get<any>('/api/v1/certs/jobs')
    const active = res?.jobs || []
    // Keep finished jobs we already know about (their result toast already fired);
    // only reconcile the active set with what the control plane reports.
    const known = new Map(jobs.value.map((j) => [j.id, j]))
    for (const job of active) known.set(job.id, job)
    jobs.value = [...known.values()]
  } catch {
    // The active list is a nicety; the certificate table still works without it.
  }
}

/** Poll one job until it reaches a terminal state. */
async function pollJob(id: string) {
  if (pollingIds.has(id)) return
  pollingIds.add(id)
  const deadline = Date.now() + 5 * 60 * 1000
  try {
    while (!disposed && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 1500))
      if (disposed) return
      let job: any
      try {
        job = await api.get<any>(`/api/v1/certs/jobs/${id}`)
      } catch (e: any) {
        // 404 means the control plane restarted and the in-process job is gone.
        // The renewal worker still retries the certificate, so stop polling.
        if ((e?.status ?? e?.response?.status) === 404) {
          jobs.value = jobs.value.filter((j) => j.id !== id)
          toast.error('签发任务已丢失（控制面可能重启），可稍后重试')
          return
        }
        continue // a transient network error just means try again
      }
      upsertJob(job)
      if (job.status === 'succeeded') {
        toast.success(
          `已签发 ${job.domain_name}（${job.issuer || '未知签发者'}），推送到 ${job.edges_pushed ?? 0} 个边缘节点`
        )
        await load()
        return
      }
      if (job.status === 'failed') {
        toast.error(`签发失败：${job.message || '请稍后重试'}`)
        return
      }
    }
    if (!disposed) toast.error('签发耗时较长，请稍后刷新查看结果')
  } finally {
    pollingIds.delete(id)
  }
}

function openUpload() {
  error.value = ''
  uploadForm.value = {
    domain_name: '',
    issuer: 'manual',
    cert_pem: '',
    key_pem: '',
    auto_renew: false,
  }
  uploadOpen.value = true
}

async function createCert() {
  error.value = ''
  if (!uploadForm.value.domain_name.trim()) {
    error.value = '请填写域名'
    return
  }
  const hasCert = !!uploadForm.value.cert_pem.trim()
  const hasKey = !!uploadForm.value.key_pem.trim()
  if (hasCert !== hasKey) {
    error.value = '证书与私钥需要同时填写（都留空则标记为待签发）'
    return
  }
  submitting.value = true
  try {
    await api.post('/api/v1/certs', {
      domain_name: uploadForm.value.domain_name.trim(),
      issuer: uploadForm.value.issuer.trim() || 'manual',
      cert_pem: uploadForm.value.cert_pem,
      key_pem: uploadForm.value.key_pem,
      auto_renew: uploadForm.value.auto_renew,
    })
    uploadOpen.value = false
    toast.success('证书已保存，边缘节点将在 30 秒内同步')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '保存失败'
  } finally {
    submitting.value = false
  }
}

function openIssue() {
  error.value = ''
  issueForm.value = { domain_name: '', provider: 'letsencrypt', push_to_edges: true, auto_renew: true }
  issueOpen.value = true
}

async function issueCert() {
  error.value = ''
  const domain = issueForm.value.domain_name.trim()
  if (!domain) {
    error.value = '请填写域名'
    return
  }
  if (activeJobs.value.some((j) => String(j.domain_name).toLowerCase() === domain.toLowerCase())) {
    error.value = '该域名已有签发任务正在进行，请稍候'
    return
  }
  submitting.value = true
  try {
    // The endpoint answers 202 with a job id: the ACME exchange (order,
    // HTTP-01 challenge, polling the CA) runs in the background, so the browser
    // no longer waits on a request that can take minutes.
    const res = await api.post<any>('/api/v1/certs/issue', {
      domain_name: domain,
      provider: issueForm.value.provider,
      push_to_edges: issueForm.value.push_to_edges,
      auto_renew: issueForm.value.auto_renew,
    })
    issueOpen.value = false
    upsertJob({
      id: res.job_id,
      domain_name: res.domain_name,
      provider: res.provider,
      status: 'pending',
      message: res.message || '排队中',
      elapsed_ms: 0,
    })
    toast.success(res.reused ? '该域名已在签发中，正在跟踪进度' : '已提交签发任务，正在后台签发…')
    void pollJob(res.job_id)
  } catch (e: any) {
    error.value = e?.data?.error || '签发失败，请确认域名已接入'
  } finally {
    submitting.value = false
  }
}

async function remove(cert: any) {
  const ok = await ask({
    title: '删除证书',
    message: `删除 ${cert.domain_name} 的证书后，HTTPS 握手会失败，直到上传新证书。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/certs/${cert.id}`)
    toast.success('证书已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

onMounted(async () => {
  await load()
  // Re-attach to issuances that are still running, so a reload does not lose
  // the progress strip (the jobs live in the control plane, not the page).
  await loadJobs()
  for (const job of activeJobs.value) void pollJob(job.id)
})

onUnmounted(() => {
  disposed = true
})
</script>

<style scoped>
/* Progress strip for in-flight issuances; the control plane owns the job, so
   this survives a page reload (see /api/v1/certs/jobs). */
.issue-strip {
  border-bottom: 1px solid var(--border);
  background: var(--bg-subtle, rgba(250, 173, 20, 0.06));
}

.issue-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 16px;
  font-size: 13px;
}

.issue-row + .issue-row {
  border-top: 1px solid var(--border);
}

.issue-domain {
  font-weight: 600;
}

.issue-message {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.issue-elapsed {
  font-variant-numeric: tabular-nums;
}

.material {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  font-size: 12px;
  color: var(--text-4);
  margin-right: 10px;
}

.material.ok {
  color: var(--success);
}
</style>
