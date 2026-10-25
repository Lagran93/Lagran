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
        当前「自动签发」使用 rcgen 生成的开发用 CA，仅适合本地测试；生产环境请上传正式证书或接入 Let's Encrypt。
      </span>
    </div>

    <div class="card">
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
        text="上传 PEM 证书与私钥，或使用自动签发为域名生成开发用证书。"
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
          自动续期（预留）
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
          <span>签发使用开发 CA，并将 HTTP-01 challenge 下发到在线边缘节点，签发完成后证书会自动推送。</span>
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
  issueForm.value = { domain_name: '', push_to_edges: true, auto_renew: true }
  issueOpen.value = true
}

async function issueCert() {
  error.value = ''
  if (!issueForm.value.domain_name.trim()) {
    error.value = '请填写域名'
    return
  }
  submitting.value = true
  try {
    const res = await api.post<any>('/api/v1/certs/issue', {
      domain_name: issueForm.value.domain_name.trim(),
      push_to_edges: issueForm.value.push_to_edges,
      auto_renew: issueForm.value.auto_renew,
    })
    issueOpen.value = false
    toast.success(`已签发 ${res.domain_name}，推送到 ${res.edges_pushed} 个边缘节点`)
    await load()
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

onMounted(load)
</script>

<style scoped>
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
