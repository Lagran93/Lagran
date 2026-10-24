<template>
  <div>
    <p class="muted" style="margin-bottom:1.25rem;">控制面关键操作记录（域名启停、缓存刷新等）</p>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>操作者</th>
            <th>动作</th>
            <th>资源</th>
            <th>详情</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="a in logs" :key="a.id">
            <td class="muted">{{ a.created_at?.slice(0, 19).replace('T', ' ') }}</td>
            <td>{{ a.actor }}</td>
            <td><span class="badge">{{ a.action }}</span></td>
            <td>{{ a.resource }}</td>
            <td class="muted">{{ a.detail }}</td>
          </tr>
          <tr v-if="!logs.length">
            <td colspan="5" class="empty">暂无审计记录</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const logs = ref<any[]>([])
onMounted(async () => {
  try {
    logs.value = await api.get('/api/v1/audit')
  } catch {
    logs.value = []
  }
})
</script>

<style scoped>
.badge {
  display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px;
  background: rgba(56, 189, 248, 0.15); color: #38bdf8; font-size: 0.8rem;
}
</style>
