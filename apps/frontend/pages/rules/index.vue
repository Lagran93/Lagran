<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
      <p class="muted" style="margin:0;">按路径配置 TTL 与优先级</p>
      <button class="btn" @click="showForm = !showForm">新建规则</button>
    </div>

    <div v-if="showForm" class="card" style="margin-bottom:1.25rem;">
      <h3 style="margin-top:0;">新建缓存规则</h3>
      <div class="form-row">
        <select v-model="form.domain_id">
          <option value="">选择域名</option>
          <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
        </select>
        <input v-model="form.path_pattern" placeholder="/static/*" />
        <input v-model.number="form.ttl_seconds" type="number" placeholder="TTL 秒" style="width:120px;" />
        <input v-model.number="form.priority" type="number" placeholder="优先级" style="width:100px;" />
        <button class="btn" @click="createRule">创建</button>
      </div>
      <p v-if="formError" class="error">{{ formError }}</p>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th>路径匹配</th>
            <th>TTL（秒）</th>
            <th>优先级</th>
            <th>域名</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in rules" :key="r.id">
            <td>{{ r.path_pattern }}</td>
            <td>{{ r.ttl_seconds }}</td>
            <td>{{ r.priority }}</td>
            <td class="muted">{{ r.domain_name }}</td>
            <td>
              <button class="btn btn-ghost" @click="removeRule(r.id)">删除</button>
            </td>
          </tr>
          <tr v-if="!rules.length">
            <td colspan="5" class="empty">暂无规则</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const rules = ref<any[]>([])
const domains = ref<any[]>([])
const showForm = ref(false)
const formError = ref('')
const form = ref({
  domain_id: '',
  path_pattern: '/*',
  ttl_seconds: 60,
  priority: 0,
})

async function load() {
  try {
    const [r, d] = await Promise.all([
      api.get<any[]>('/api/v1/rules'),
      api.get<any[]>('/api/v1/domains'),
    ])
    rules.value = r || []
    domains.value = d || []
  } catch {
    rules.value = []
  }
}

async function createRule() {
  formError.value = ''
  if (!form.value.domain_id) {
    formError.value = '请选择域名'
    return
  }
  try {
    await api.post('/api/v1/rules', form.value)
    showForm.value = false
    await load()
  } catch (e: any) {
    formError.value = e?.data?.error || e?.message || '创建失败'
  }
}

async function removeRule(id: string) {
  if (!confirm('确认删除该规则？')) return
  try {
    await api.del(`/api/v1/rules/${id}`)
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
</style>
