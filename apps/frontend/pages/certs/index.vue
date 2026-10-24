<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
      <p class="muted" style="margin:0;">域名 TLS 证书（上传 PEM 或标记待签发）</p>
      <div style="display:flex;gap:0.5rem;">
        <button class="btn btn-ghost" @click="autoIssue">自动签发</button>
        <button class="btn" @click="showForm = !showForm">上传 PEM</button>
      </div>
    </div>

    <div v-if="showForm" class="card" style="margin-bottom:1.25rem;">
      <h3 style="margin-top:0;">添加 / 上传证书</h3>
      <div class="form-col">
        <input v-model="form.domain_name" placeholder="域名 cdn.example.com" />
        <input v-model="form.issuer" placeholder="签发者（可选，如 Let's Encrypt）" />
        <textarea v-model="form.cert_pem" rows="4" placeholder="-----BEGIN CERTIFICATE-----&#10;...证书 PEM（可选）"></textarea>
        <textarea v-model="form.key_pem" rows="4" placeholder="-----BEGIN PRIVATE KEY-----&#10;...私钥 PEM（可选）"></textarea>
        <label class="check">
          <input v-model="form.auto_renew" type="checkbox" /> 自动续期（预留）
        </label>
        <button class="btn" @click="createCert">保存</button>
      </div>
      <p v-if="formError" class="error">{{ formError }}</p>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>域名</th>
            <th>状态</th>
            <th>签发者</th>
            <th>有效期至</th>
            <th>证书/密钥</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in certs" :key="c.id">
            <td>{{ c.domain_name }}</td>
            <td><span :class="['badge', c.status]">{{ c.status }}</span></td>
            <td class="muted">{{ c.issuer || '—' }}</td>
            <td class="muted">{{ c.not_after ? c.not_after.slice(0, 10) : '—' }}</td>
            <td class="muted">{{ c.has_cert ? '✓' : '—' }} / {{ c.has_key ? '✓' : '—' }}</td>
            <td>
              <button class="btn btn-ghost" @click="removeCert(c.id)">删除</button>
            </td>
          </tr>
          <tr v-if="!certs.length">
            <td colspan="6" class="empty">暂无证书</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const certs = ref<any[]>([])
const showForm = ref(false)
const formError = ref('')
const form = ref({
  domain_name: '',
  issuer: 'manual',
  cert_pem: '',
  key_pem: '',
  auto_renew: false,
})

async function load() {
  try {
    certs.value = await api.get('/api/v1/certs')
  } catch {
    certs.value = []
  }
}

async function autoIssue() {
  const domain_name = prompt('要自动签发的域名', 'cdn.example.com')
  if (!domain_name) return
  try {
    const res = await api.post<any>('/api/v1/certs/issue', {
      domain_name,
      push_to_edges: true,
      auto_renew: true,
    })
    alert(`已签发 ${res.domain_name}，推送到 ${res.edges_pushed} 个边缘节点`)
    await load()
  } catch (e: any) {
    alert(e?.data?.error || e?.message || '签发失败')
  }
}

async function createCert() {
  formError.value = ''
  if (!form.value.domain_name) {
    formError.value = '请填写域名'
    return
  }
  try {
    await api.post('/api/v1/certs', form.value)
    showForm.value = false
    form.value = { domain_name: '', issuer: 'manual', cert_pem: '', key_pem: '', auto_renew: false }
    await load()
  } catch (e: any) {
    formError.value = e?.data?.error || e?.message || '保存失败'
  }
}

async function removeCert(id: string) {
  if (!confirm('确认删除该证书？')) return
  try {
    await api.del(`/api/v1/certs/${id}`)
    await load()
  } catch (e: any) {
    alert(e?.data?.error || '删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.form-col { display: flex; flex-direction: column; gap: 0.75rem; }
.form-col input, .form-col textarea {
  padding: 0.5rem 0.75rem;
  border: 1px solid #334155;
  border-radius: 6px;
  background: #0f172a;
  color: #e2e8f0;
  font-family: ui-monospace, monospace;
  font-size: 0.85rem;
}
.check { display: flex; align-items: center; gap: 0.5rem; color: #94a3b8; font-size: 0.9rem; }
.error { color: #f87171; font-size: 0.85rem; }
.badge { padding: 0.15rem 0.5rem; border-radius: 999px; background: #334155; font-size: 0.8rem; }
.badge.active { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
.badge.pending { background: rgba(234, 179, 8, 0.2); color: #facc15; }
.badge.error, .badge.expired { background: rgba(248, 113, 113, 0.2); color: #f87171; }
</style>
