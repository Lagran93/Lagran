<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
      <p class="muted" style="margin:0;">接入域名、配置源站与 SSL</p>
      <button class="btn" @click="showForm = !showForm">添加域名</button>
    </div>

    <div v-if="showForm" class="card" style="margin-bottom:1.25rem;">
      <h3 style="margin-top:0;">添加域名</h3>
      <div class="form-row">
        <input v-model="form.name" placeholder="cdn.example.com" />
        <input v-model="form.origin_host" placeholder="源站 origin.example.com" />
        <input v-model.number="form.origin_port" type="number" placeholder="443" style="width:100px;" />
        <select v-model="form.origin_proto">
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
        <button class="btn" @click="createDomain">创建</button>
      </div>
      <p v-if="formError" class="error">{{ formError }}</p>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>域名</th>
            <th>源站</th>
            <th>SSL</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="d in domains" :key="d.id">
            <td>{{ d.name }}</td>
            <td class="muted">{{ d.origin_proto }}://{{ d.origin_host }}:{{ d.origin_port }}</td>
            <td>{{ d.ssl_enabled ? '开启' : '关闭' }}</td>
            <td>{{ d.status }}</td>
            <td style="display:flex;gap:0.5rem;">
              <button class="btn btn-ghost" @click="purgeDomain(d.name)">刷新缓存</button>
              <button class="btn btn-ghost" @click="removeDomain(d.id)">删除</button>
            </td>
          </tr>
          <tr v-if="!domains.length">
            <td colspan="5" class="empty">暂无域名，请先添加</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-if="purgeMsg" class="muted" style="margin-top:1rem;">{{ purgeMsg }}</p>
  </div>
</template>

<script setup lang="ts">
const api = useApi()

const domains = ref<any[]>([])
const showForm = ref(false)
const formError = ref('')
const purgeMsg = ref('')
const form = ref({
  name: '',
  origin_host: '',
  origin_port: 443,
  origin_proto: 'https',
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
  try {
    await api.post('/api/v1/domains', {
      ...form.value,
      ssl_enabled: form.value.origin_proto === 'https',
    })
    showForm.value = false
    form.value = { name: '', origin_host: '', origin_port: 443, origin_proto: 'https' }
    await load()
  } catch (e: any) {
    formError.value = e?.data?.error || e?.message || '创建失败'
  }
}

async function removeDomain(id: string) {
  if (!confirm('确认删除该域名？')) return
  try {
    await api.del(`/api/v1/domains/${id}`)
    await load()
  } catch (e: any) {
    alert(e?.data?.error || '删除失败')
  }
}

async function purgeDomain(name: string) {
  purgeMsg.value = '正在下发 purge…'
  try {
    const res = await api.post<any>('/api/v1/purge', {
      domain: name,
      prefixes: ['/'],
    })
    purgeMsg.value = `${res.message}（共清除 ${res.purged_count} 条，节点 ${res.nodes?.length || 0}）`
  } catch (e: any) {
    purgeMsg.value = e?.data?.error || e?.message || 'purge 失败'
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
  min-width: 120px;
  padding: 0.5rem 0.75rem;
  border: 1px solid #334155;
  border-radius: 6px;
  background: #0f172a;
  color: #e2e8f0;
}
.error { color: #f87171; font-size: 0.85rem; margin-top: 0.75rem; }
</style>
