<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
      <p class="muted" style="margin:0;">多租户项目空间，域名可归属到项目</p>
      <button class="btn" @click="showForm = !showForm">新建项目</button>
    </div>

    <div v-if="showForm" class="card" style="margin-bottom:1.25rem;">
      <div class="form-row">
        <input v-model="name" placeholder="项目名称" />
        <button class="btn" @click="create">创建</button>
      </div>
      <p v-if="error" class="error">{{ error }}</p>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>项目名称</th>
            <th>域名数</th>
            <th>创建时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in projects" :key="p.id">
            <td><strong>{{ p.name }}</strong></td>
            <td>{{ p.domain_count }}</td>
            <td class="muted">{{ p.created_at?.slice(0, 10) }}</td>
            <td>
              <button class="btn btn-ghost" @click="viewDomains(p)">域名</button>
              <button class="btn btn-ghost" @click="remove(p.id)">删除</button>
            </td>
          </tr>
          <tr v-if="!projects.length">
            <td colspan="4" class="empty">暂无项目</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="selected" class="card" style="margin-top:1.25rem;">
      <h3 style="margin-top:0;">项目「{{ selected.name }}」下的域名</h3>
      <table>
        <thead>
          <tr><th>域名</th><th>源站</th><th>状态</th></tr>
        </thead>
        <tbody>
          <tr v-for="d in projectDomains" :key="d.id">
            <td>{{ d.name }}</td>
            <td class="muted">{{ d.origin_proto }}://{{ d.origin_host }}:{{ d.origin_port }}</td>
            <td>{{ d.status }}</td>
          </tr>
          <tr v-if="!projectDomains.length">
            <td colspan="3" class="empty">该项目下暂无域名</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const projects = ref<any[]>([])
const showForm = ref(false)
const name = ref('')
const error = ref('')
const selected = ref<any>(null)
const projectDomains = ref<any[]>([])

async function load() {
  try {
    projects.value = await api.get('/api/v1/projects')
  } catch {
    projects.value = []
  }
}

async function create() {
  error.value = ''
  if (!name.value.trim()) {
    error.value = '请填写名称'
    return
  }
  try {
    await api.post('/api/v1/projects', { name: name.value.trim() })
    name.value = ''
    showForm.value = false
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || e?.message || '创建失败'
  }
}

async function remove(id: string) {
  if (!confirm('删除项目？域名不会删除，仅解除归属。')) return
  try {
    await api.del(`/api/v1/projects/${id}`)
    if (selected.value?.id === id) {
      selected.value = null
      projectDomains.value = []
    }
    await load()
  } catch (e: any) {
    alert(e?.data?.error || '删除失败')
  }
}

async function viewDomains(p: any) {
  selected.value = p
  try {
    projectDomains.value = await api.get(`/api/v1/projects/${p.id}/domains`)
  } catch {
    projectDomains.value = []
  }
}

onMounted(load)
</script>

<style scoped>
.form-row { display: flex; gap: 0.75rem; }
.form-row input {
  flex: 1; padding: 0.5rem 0.75rem; border: 1px solid #334155;
  border-radius: 6px; background: #0f172a; color: #e2e8f0;
}
.error { color: #f87171; font-size: 0.85rem; }
</style>
