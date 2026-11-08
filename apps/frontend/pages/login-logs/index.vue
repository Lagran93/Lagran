<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">登录日志</div>
        <div class="page-desc">记录账号登录成功与失败、来源 IP 和客户端信息；管理员可查看全部账号，普通用户仅显示自己的记录</div>
      </div>
      <div class="page-actions">
        <select v-model.number="limit" class="select" @change="load">
          <option :value="100">最近 100 条</option>
          <option :value="200">最近 200 条</option>
          <option :value="500">最近 500 条</option>
        </select>
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
      </div>
    </div>

    <div class="card">
      <div class="filter-bar">
        <input
          v-model="keyword"
          class="input"
          placeholder="搜索邮箱、IP、User-Agent 或失败原因"
          style="min-width: 280px"
        />
        <select v-model="resultFilter" class="select">
          <option value="">全部结果</option>
          <option value="success">仅成功</option>
          <option value="failed">仅失败</option>
        </select>
        <span class="spacer" />
        <span class="text-muted" style="font-size: 13px">
          {{ auth.isAdmin ? '全部账号' : '仅本人记录' }} · {{ filtered.length }} 条
        </span>
      </div>

      <div v-if="filtered.length" class="table-wrap">
        <table class="table table-fixed login-table">
          <colgroup>
            <col style="width: var(--col-time)" />
            <col style="width: var(--col-result)" />
            <col style="width: var(--col-email)" />
            <col style="width: var(--col-ip)" />
            <col style="width: var(--col-reason)" />
            <col />
          </colgroup>
          <thead>
            <tr>
              <th>时间</th>
              <th>结果</th>
              <th>账号</th>
              <th>来源 IP</th>
              <th>原因</th>
              <th>User-Agent</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in paged" :key="row.id">
              <td class="time-cell text-muted nowrap">{{ formatDateTime(row.created_at) }}</td>
              <td>
                <StatusTag :tone="row.success ? 'success' : 'danger'" dot>
                  {{ row.success ? '成功' : '失败' }}
                </StatusTag>
              </td>
              <td>
                <span class="cell-ellipsis cell-main" :title="row.email || '—'">{{ row.email || '—' }}</span>
              </td>
              <td class="mono">
                <span class="cell-ellipsis" :title="row.client_ip || '—'">{{ row.client_ip || '—' }}</span>
              </td>
              <td>
                <StatusTag :tone="reasonTone(row.success, row.reason)">
                  {{ reasonLabel(row.reason) }}
                </StatusTag>
              </td>
              <td class="ua-cell text-muted">
                <span class="cell-ellipsis" :title="row.user_agent || '—'">{{ row.user_agent || '—' }}</span>
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
        icon="shield"
        :title="logs.length ? '没有匹配的登录记录' : '暂无登录记录'"
        :text="logs.length ? '试试调整搜索条件。' : '账号登录成功或失败后，记录会自动出现在这里。'"
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
const resultFilter = ref('')
const limit = ref(200)
const loading = ref(false)
const page = ref(1)
const pageSize = 20

const filtered = computed(() => {
  const q = keyword.value.trim().toLowerCase()
  return logs.value.filter((row) => {
    if (resultFilter.value === 'success' && !row.success) return false
    if (resultFilter.value === 'failed' && row.success) return false
    if (!q) return true
    return [row.email, row.client_ip, row.user_agent, reasonLabel(row.reason)]
      .map((value) => String(value || '').toLowerCase())
      .some((value) => value.includes(q))
  })
})

const paged = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

watch([keyword, resultFilter], () => {
  page.value = 1
})

function reasonLabel(reason: string) {
  const labels: Record<string, string> = {
    success: '正常登录',
    register: '注册并登录',
    invalid_credentials: '账号或密码错误',
    invalid_password: '密码错误',
    account_disabled: '账号已禁用',
    captcha_failed: '验证码错误',
    rate_limited: '尝试过于频繁',
    db_error: '系统错误',
    token_error: '令牌签发失败',
  }
  return labels[reason] || reason || '未知原因'
}

function reasonTone(success: boolean, reason: string) {
  if (success) return 'success'
  if (reason === 'rate_limited') return 'warning'
  if (reason === 'captcha_failed') return 'warning'
  if (reason === 'db_error' || reason === 'token_error') return 'neutral'
  return 'danger'
}

async function load() {
  loading.value = true
  page.value = 1
  try {
    logs.value = (await api.get<any[]>(`/api/v1/login-logs?limit=${limit.value}`)) || []
  } catch {
    logs.value = []
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.login-table {
  --col-time: 166px;
  --col-result: 92px;
  --col-email: 224px;
  --col-ip: 148px;
  --col-reason: 164px;
  min-width: 1080px;
  font-size: 13px;
}

.login-table th {
  padding: 10px 14px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.055em;
  text-transform: uppercase;
  color: var(--text-3);
}

.login-table td {
  padding: 11px 14px;
  font-size: 13px;
  line-height: 1.5;
}

.login-table .cell-ellipsis {
  font-size: 13px;
  line-height: 1.5;
}

.login-table .time-cell {
  font-size: 12.5px;
  font-variant-numeric: tabular-nums;
  color: var(--text-3);
}

.login-table td.mono .cell-ellipsis {
  font-size: 12.5px;
}

.login-table .ua-cell .cell-ellipsis {
  font-size: 12.5px;
  color: var(--text-3);
}

@media (min-width: 1920px) {
  .login-table {
    --col-time: 184px;
    --col-result: 100px;
    --col-email: 260px;
    --col-ip: 170px;
    --col-reason: 184px;
  }
}

@media (min-width: 2560px) {
  .login-table {
    --col-time: 220px;
    --col-result: 110px;
    --col-email: 320px;
    --col-ip: 200px;
    --col-reason: 220px;
    font-size: 14px;
  }

  .login-table th,
  .login-table td {
    padding: 12px 18px;
  }

  .login-table td,
  .login-table .cell-ellipsis {
    font-size: 14px;
  }

  .login-table .time-cell,
  .login-table td.mono .cell-ellipsis,
  .login-table .ua-cell .cell-ellipsis {
    font-size: 13px;
  }
}

@media (min-width: 3200px) {
  .login-table {
    --col-time: 240px;
    --col-result: 120px;
    --col-email: 360px;
    --col-ip: 220px;
    --col-reason: 240px;
  }
}
</style>
