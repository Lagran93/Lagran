<template>
  <div>
    <p class="muted" style="margin-bottom:1.25rem;">向所有在线边缘节点下发缓存刷新指令</p>
    <div class="card">
      <div class="form-col">
        <label>域名</label>
        <select v-model="form.domain">
          <option value="">选择域名</option>
          <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
        </select>
        <label>URL 列表（每行一条，可选）</label>
        <textarea v-model="urlsText" rows="3" placeholder="/index.html&#10;/static/app.js"></textarea>
        <label>路径前缀（每行一条，可选）</label>
        <textarea v-model="prefixesText" rows="2" placeholder="/static/"></textarea>
        <label class="check">
          <input v-model="form.purge_all" type="checkbox" /> 清除该域名相关全部缓存（谨慎）
        </label>
        <button class="btn" :disabled="loading" @click="doPurge">下发刷新</button>
        <p v-if="error" class="error">{{ error }}</p>
      </div>
    </div>
    <div v-if="result" class="card" style="margin-top:1.25rem;">
      <h3 style="margin-top:0;">结果：{{ result.success ? '成功' : '部分失败' }}</h3>
      <p class="muted">{{ result.message }} · 共清理约 {{ result.purged_count }} 条</p>
      <table>
        <thead>
          <tr><th>节点</th><th>状态</th><th>数量</th><th>说明</th></tr>
        </thead>
        <tbody>
          <tr v-for="n in result.nodes" :key="n.node">
            <td>{{ n.node }}</td>
            <td>{{ n.success ? 'OK' : 'FAIL' }}</td>
            <td>{{ n.purged_count }}</td>
            <td class="muted">{{ n.message }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const domains = ref<any[]>([])
const loading = ref(false)
const error = ref('')
const result = ref<any>(null)
const urlsText = ref('')
const prefixesText = ref('')
const form = ref({ domain: '', purge_all: false })

onMounted(async () => {
  try {
    domains.value = await api.get('/api/v1/domains')
  } catch {
    domains.value = []
  }
})

async function doPurge() {
  error.value = ''
  result.value = null
  if (!form.value.domain) {
    error.value = '请选择域名'
    return
  }
  loading.value = true
  try {
    const urls = urlsText.value.split('\n').map(s => s.trim()).filter(Boolean)
    const prefixes = prefixesText.value.split('\n').map(s => s.trim()).filter(Boolean)
    result.value = await api.post('/api/v1/purge', {
      domain: form.value.domain,
      urls: urls.length ? urls : undefined,
      prefixes: prefixes.length ? prefixes : undefined,
      purge_all: form.value.purge_all,
    })
  } catch (e: any) {
    error.value = e?.data?.error || e?.message || '刷新失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.form-col { display: flex; flex-direction: column; gap: 0.6rem; max-width: 560px; }
.form-col label { font-size: 0.85rem; color: #94a3b8; }
.form-col input, .form-col select, .form-col textarea {
  padding: 0.5rem 0.75rem; border: 1px solid #334155; border-radius: 6px;
  background: #0f172a; color: #e2e8f0;
}
.check { display: flex; align-items: center; gap: 0.5rem; color: #e2e8f0; }
.error { color: #f87171; }
</style>
