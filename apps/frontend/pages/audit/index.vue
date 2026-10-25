<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">操作审计</div>
        <div class="page-desc">记录控制面的关键操作，便于追溯变更（仅管理员可见）</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
      </div>
    </div>

    <div v-if="!auth.isAdmin" class="alert alert-warning mb-16">
      <AppIcon name="alert" :size="16" class="icon" />
      <span>当前账号没有审计日志权限，仅管理员可查看。</span>
    </div>

    <div class="card">
      <div class="filter-bar">
        <input
          v-model="keyword"
          class="input"
          placeholder="搜索操作者、资源或动作"
          style="min-width: 260px"
        />
        <span class="spacer" />
        <span class="text-muted" style="font-size: 13px">最近 {{ filtered.length }} 条记录</span>
      </div>

      <div v-if="filtered.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="min-width: 160px">时间</th>
              <th>操作者</th>
              <th>动作</th>
              <th>资源</th>
              <th>详情</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in paged" :key="a.id">
              <td class="text-muted nowrap">{{ formatDateTime(a.created_at) }}</td>
              <td>{{ a.actor }}</td>
              <td><StatusTag :tone="actionTone(a.action)">{{ a.action }}</StatusTag></td>
              <td class="cell-main">{{ a.resource || '—' }}</td>
              <td class="text-muted">{{ a.detail || '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="loading" class="card-body">
        <div class="skeleton" style="height: 34px; width: 100%" />
      </div>

      <EmptyState
        v-else
        icon="audit"
        :title="logs.length ? '没有匹配的记录' : '暂无审计记录'"
        :text="logs.length ? '试试其他关键词。' : '域名启停、规则变更、缓存刷新等操作会自动记录在这里。'"
      />

      <div v-if="filtered.length > pageSize" class="table-footer">
        <AppPagination v-model:page="page" :total="filtered.length" :page-size="pageSize" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()

const logs = ref<any[]>([])
const keyword = ref('')
const loading = ref(false)
const page = ref(1)
const pageSize = 20

const filtered = computed(() => {
  const q = keyword.value.trim().toLowerCase()
  if (!q) return logs.value
  return logs.value.filter((a) =>
    [a.actor, a.action, a.resource, a.detail]
      .map((v) => String(v || '').toLowerCase())
      .some((v) => v.includes(q)),
  )
})

const paged = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

watch(keyword, () => {
  page.value = 1
})

function actionTone(action: string) {
  if (!action) return 'neutral'
  if (action.includes('delete') || action.includes('remove')) return 'danger'
  if (action.includes('create') || action.includes('add')) return 'success'
  if (action.includes('status') || action.includes('purge')) return 'warning'
  return 'info'
}

async function load() {
  if (!auth.isAdmin) {
    logs.value = []
    return
  }
  loading.value = true
  try {
    logs.value = (await api.get<any[]>('/api/v1/audit')) || []
  } catch {
    logs.value = []
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
