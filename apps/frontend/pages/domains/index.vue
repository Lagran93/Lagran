<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
      <p class="muted" style="margin:0;">接入待加速域名，每个域名可配置独立源站</p>
      <button class="btn" @click="showForm = !showForm">接入域名</button>
    </div>

    <div v-if="showForm" class="card" style="margin-bottom:1.25rem;">
      <h3 style="margin-top:0;">接入加速域名</h3>
      <p class="muted" style="font-size:0.85rem;">用户 DNS 将域名 CNAME/A 到边缘节点后，须在此完成接入，否则将看到「域名未接入」提示页。</p>
      <div class="form-row">
        <input v-model="form.name" placeholder="加速域名 cdn.example.com" />
        <input v-model="form.origin_host" placeholder="源站 origin.example.com" />
        <input v-model.number="form.origin_port" type="number" placeholder="443" style="width:100px;" />
        <select v-model="form.origin_proto">
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
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
            <th>协议</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in domains" :key="d.id">
            <td><strong>{{ d.name }}</strong></td>
            <td class="muted">{{ d.origin_host }}:{{ d.origin_port }}</td>
            <td>{{ d.origin_proto }}</td>
            <td><span class="badge">{{ d.status }}</span></td>
            <td>
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
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const domains = ref<any[]>([])
const showForm = ref(false)
const formError = ref('')
const form = ref({
  name: '',
  origin_host: '',
  origin_port: 443,
  origin_proto: 'https',
  ssl_enabled: true,
})

async function load() {
  try {
    domains.value = await api.get('/api/v1/domains')
  } catch {
    domains.value = []
  }
}

async function createDomain() {
  formError.value = ''
  if (!form.value.name || !form.value.origin_host) {
    formError.value = '请填写加速域名与源站'
    return
  }
  try {
    await api.post('/api/v1/domains', {
      ...form.value,
      ssl_enabled: form.value.origin_proto === 'https',
    })
    showForm.value = false
    form.value = { name: '', origin_host: '', origin_port: 443, origin_proto: 'https', ssl_enabled: true }
    await load()
  } catch (e: any) {
    formError.value = e?.data?.error || e?.message || '接入失败'
  }
}

async function editOrigin(d: any) {
  const host = prompt('源站主机', d.origin_host)
  if (host === null) return
  const port = prompt('源站端口', String(d.origin_port))
  if (port === null) return
  const proto = prompt('协议 http/https', d.origin_proto)
  if (proto === null) return
  try {
    await api.put(`/api/v1/domains/${d.id}`, {
      origin_host: host,
      origin_port: Number(port) || d.origin_port,
      origin_proto: proto,
      ssl_enabled: proto === 'https',
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
.form-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: center;
}
.form-row input, .form-row select {
  flex: 1;
  min-width: 100px;
  padding: 0.5rem 0.75rem;
  border: 1px solid #334155;
  border-radius: 6px;
  background: #0f172a;
  color: #e2e8f0;
}
.error { color: #f87171; font-size: 0.85rem; margin-top: 0.75rem; }
.badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  background: rgba(56, 189, 248, 0.15);
  color: #38bdf8;
  font-size: 0.8rem;
}
</style>
