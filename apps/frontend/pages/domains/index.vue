<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
      <p class="muted" style="margin:0;">接入待加速域名，每个域名可配置独立源站并归属项目</p>
      <button class="btn" @click="showForm = !showForm">接入域名</button>
    </div>

    <div v-if="showForm" class="card" style="margin-bottom:1.25rem;">
      <h3 style="margin-top:0;">接入加速域名</h3>
      <p class="muted" style="font-size:0.85rem;">
        用户 DNS 将域名 CNAME/A 到边缘节点后，须在此完成接入，否则将看到「域名未接入」提示页。
      </p>
      <div class="form-grid">
        <label>加速域名</label>
        <input v-model="form.name" placeholder="cdn.example.com" />
        <label>源站主机</label>
        <input v-model="form.origin_host" placeholder="origin.example.com" />
        <label>端口</label>
        <input v-model.number="form.origin_port" type="number" placeholder="443" />
        <label>协议</label>
        <select v-model="form.origin_proto">
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
        <label>所属项目</label>
        <select v-model="form.project_id">
          <option value="">（不关联项目）</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
      </div>
      <div style="margin-top:0.75rem;">
        <button class="btn" @click="createDomain">接入</button>
      </div>
      <p v-if="formError" class="error">{{ formError }}</p>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>加速域名</th>
            <th>源站</th>
            <th>项目</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in domains" :key="d.id">
            <td><strong>{{ d.name }}</strong></td>
            <td class="muted">{{ d.origin_proto }}://{{ d.origin_host }}:{{ d.origin_port }}</td>
            <td>
              <select
                class="proj-select"
                :value="d.project_id || ''"
                @change="onProjectChange(d, ($event.target as HTMLSelectElement).value)"
              >
                <option value="">—</option>
                <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
              </select>
            </td>
            <td><span class="badge">{{ d.status }}</span></td>
            <td>
              <button class="btn btn-ghost" @click="openSettings(d)">高级</button>
              <button class="btn btn-ghost" @click="toggleStatus(d)">
                {{ d.status === 'disabled' ? '启用' : '停用' }}
              </button>
              <button class="btn btn-ghost" @click="editOrigin(d)">改源站</button>
              <button class="btn btn-ghost" @click="removeDomain(d.id)">删除</button>
            </td>
          </tr>
          <tr v-if="!domains.length">
            <td colspan="5" class="empty">暂无已接入域名</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="settingsDomain" class="card" style="margin-top:1.25rem;">
      <h3 style="margin-top:0;">高级设置 — {{ settingsDomain.name }}</h3>
      <div class="form-col">
        <label class="check">
          <input v-model="settings.ignore_query_string" type="checkbox" /> 忽略 URL 查询串（缓存键）
        </label>
        <label>限流 RPS（0=不限）</label>
        <input v-model.number="settings.rate_limit_rps" type="number" />
        <label>限流突发</label>
        <input v-model.number="settings.rate_limit_burst" type="number" />
        <label>CORS 允许源（* 或逗号分隔）</label>
        <input v-model="settings.cors_origins" placeholder="*" />
        <label>防盗链 Referer 白名单（空=关闭）</label>
        <input v-model="settings.hotlink_allow_referers" placeholder="example.com" />
        <label>回源超时 (ms)</label>
        <input v-model.number="settings.origin_timeout_ms" type="number" />
        <label>自定义响应头（每行 Name: Value）</label>
        <textarea v-model="settings.custom_headers" rows="3" placeholder="X-CDN: lagran"></textarea>
        <div style="display:flex;gap:0.5rem;">
          <button class="btn" @click="saveSettings">保存</button>
          <button class="btn btn-ghost" @click="settingsDomain = null">关闭</button>
        </div>
        <p class="muted" style="font-size:0.8rem;">保存后边缘节点约 15 秒内自动同步，无需停用/启用。</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const domains = ref<any[]>([])
const projects = ref<any[]>([])
const showForm = ref(false)
const formError = ref('')
const form = ref({
  name: '',
  origin_host: '',
  origin_port: 443,
  origin_proto: 'https',
  project_id: '',
})

const settingsDomain = ref<any>(null)
const settings = ref<any>({
  ignore_query_string: false,
  rate_limit_rps: 0,
  rate_limit_burst: 0,
  cors_origins: '',
  hotlink_allow_referers: '',
  origin_timeout_ms: 10000,
  custom_headers: '',
})

async function load() {
  try {
    const [d, p] = await Promise.all([
      api.get('/api/v1/domains'),
      api.get('/api/v1/projects').catch(() => []),
    ])
    domains.value = d || []
    projects.value = p || []
  } catch {
    domains.value = []
  }
}

async function createDomain() {
  formError.value = ''
  if (!form.value.name.trim() || !form.value.origin_host.trim()) {
    formError.value = '请填写域名与源站'
    return
  }
  try {
    const body: any = {
      name: form.value.name.trim(),
      origin_host: form.value.origin_host.trim(),
      origin_port: form.value.origin_port || 80,
      origin_proto: form.value.origin_proto,
      ssl_enabled: form.value.origin_proto === 'https',
    }
    if (form.value.project_id) {
      body.project_id = form.value.project_id
    }
    await api.post('/api/v1/domains', body)
    form.value = {
      name: '',
      origin_host: '',
      origin_port: 443,
      origin_proto: 'https',
      project_id: '',
    }
    showForm.value = false
    await load()
  } catch (e: any) {
    formError.value = e?.data?.error || e?.message || '接入失败'
  }
}

async function onProjectChange(d: any, projectId: string) {
  try {
    await api.put(`/api/v1/domains/${d.id}`, {
      project_id: projectId || null,
    })
    await load()
  } catch (e: any) {
    alert(e?.data?.error || '更新项目归属失败')
    await load()
  }
}

async function openSettings(d: any) {
  settingsDomain.value = d
  try {
    settings.value = await api.get(`/api/v1/domains/${d.id}/settings`)
  } catch {
    /* defaults */
  }
}

async function saveSettings() {
  if (!settingsDomain.value) return
  try {
    await api.put(`/api/v1/domains/${settingsDomain.value.id}/settings`, settings.value)
    alert('已保存，边缘约 15s 内自动同步（无需停用/启用）')
    settingsDomain.value = null
  } catch (e: any) {
    alert(e?.data?.error || '保存失败')
  }
}

async function toggleStatus(d: any) {
  const next = d.status === 'disabled' ? 'active' : 'disabled'
  try {
    await api.post(`/api/v1/domains/${d.id}/status`, { status: next })
    await load()
  } catch (e: any) {
    alert(e?.data?.error || '状态更新失败')
  }
}

async function editOrigin(d: any) {
  const host = prompt('主源站主机', d.origin_host)
  if (host === null) return
  const port = prompt('源站端口', String(d.origin_port))
  if (port === null) return
  const proto = prompt('协议 http/https', d.origin_proto)
  if (proto === null) return
  try {
    const bhost = prompt('备用源站主机（可空）', '') || ''
    const bport = bhost ? prompt('备用源站端口', '80') : '0'
    const bproto = bhost ? prompt('备用协议 http/https', 'http') : 'http'
    await api.put(`/api/v1/domains/${d.id}`, {
      origin_host: host,
      origin_port: Number(port) || d.origin_port,
      origin_proto: proto,
      ssl_enabled: proto === 'https',
      backup_origin_host: bhost,
      backup_origin_port: Number(bport) || 0,
      backup_origin_proto: bproto,
    })
    await load()
  } catch (e: any) {
    alert(e?.data?.error || '更新失败')
  }
}

async function removeDomain(id: string) {
  if (!confirm('确认删除该加速域名？')) return
  try {
    await api.del(`/api/v1/domains/${id}`)
    await load()
  } catch (e: any) {
    alert(e?.data?.error || '删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.form-grid {
  display: grid;
  grid-template-columns: 100px 1fr;
  gap: 0.5rem 0.75rem;
  align-items: center;
  max-width: 560px;
}
.form-grid label { font-size: 0.85rem; color: #94a3b8; }
.form-grid input, .form-grid select {
  padding: 0.5rem 0.75rem; border: 1px solid #334155; border-radius: 6px;
  background: #0f172a; color: #e2e8f0;
}
.proj-select {
  padding: 0.25rem 0.5rem; border: 1px solid #334155; border-radius: 6px;
  background: #0f172a; color: #e2e8f0; max-width: 160px;
}
.error { color: #f87171; font-size: 0.85rem; margin-top: 0.75rem; }
.badge {
  display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px;
  background: rgba(56, 189, 248, 0.15); color: #38bdf8; font-size: 0.8rem;
}
.form-col { display: flex; flex-direction: column; gap: 0.5rem; max-width: 520px; }
.form-col label { font-size: 0.85rem; color: #94a3b8; }
.form-col input, .form-col textarea {
  padding: 0.5rem 0.75rem; border: 1px solid #334155; border-radius: 6px;
  background: #0f172a; color: #e2e8f0;
}
.check { display: flex; align-items: center; gap: 0.5rem; color: #e2e8f0; }
</style>
