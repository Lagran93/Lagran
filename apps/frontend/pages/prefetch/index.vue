<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">缓存预热</div>
        <div class="page-desc">提前把源站内容拉取到边缘缓存，支持手动任务与定时预热</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-primary" type="button" @click="openCreateSchedule">
          <AppIcon name="plus" :size="15" />
          新建定时任务
        </button>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">手动预热</div>
            <div class="card-desc">立即创建一个预热任务，由后台分发到在线边缘节点</div>
          </div>
        </div>
        <div class="card-body">
          <div class="field">
            <label class="field-label">域名 <span class="req">*</span></label>
            <select v-model="manual.domain" class="select">
              <option value="">请选择域名</option>
              <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">路径列表 <span class="req">*</span></label>
            <textarea
              v-model="manual.paths"
              class="textarea"
              rows="5"
              placeholder="/index.html&#10;/static/app.js&#10;/images/logo.png"
            />
            <span class="field-hint">每行一个路径；任务会在约 15 秒内被后台执行。</span>
          </div>
          <div class="flex-between">
            <span class="text-muted" style="font-size: 12px">预热请求经过真实边缘节点</span>
            <button class="btn btn-primary" type="button" :disabled="submitting" @click="createManual">
              {{ submitting ? '创建中…' : '创建预热任务' }}
            </button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="card-title">执行概览</div>
        </div>
        <div class="card-body">
          <div class="mini-stats">
            <div>
              <div class="mini-num">{{ tasks.filter((t) => t.status === 'pending' || t.status === 'running').length }}</div>
              <div class="mini-label">等待 / 执行中</div>
            </div>
            <div>
              <div class="mini-num text-success">{{ tasks.filter((t) => t.status === 'done').length }}</div>
              <div class="mini-label">已完成</div>
            </div>
            <div>
              <div class="mini-num text-danger">{{ tasks.filter((t) => t.status === 'failed').length }}</div>
              <div class="mini-label">失败</div>
            </div>
            <div>
              <div class="mini-num">{{ schedules.filter((s) => s.enabled).length }}</div>
              <div class="mini-label">启用的定时任务</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card mt-16">
      <div class="card-head">
        <div>
          <div class="card-title">定时预热</div>
          <div class="card-desc">按固定间隔自动创建预热任务</div>
        </div>
      </div>
      <div class="card-body tight">
        <div v-if="schedules.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>域名</th>
                <th>路径</th>
                <th>间隔</th>
                <th>状态</th>
                <th>上次执行</th>
                <th>下次执行</th>
                <th class="text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in pagedSchedules" :key="s.id">
                <td class="cell-main">{{ s.domain }}</td>
                <td>
                  <span class="mono text-2 truncate" style="display: inline-block; max-width: 260px">
                    {{ s.paths.join(', ') }}
                  </span>
                  <div class="cell-sub">{{ s.paths.length }} 个路径</div>
                </td>
                <td>{{ s.interval_minutes }} 分钟</td>
                <td>
                  <StatusTag :tone="s.enabled ? 'success' : 'neutral'" dot>
                    {{ s.enabled ? '启用' : '停用' }}
                  </StatusTag>
                </td>
                <td class="text-2">{{ s.last_run_at ? formatTime(s.last_run_at) : '—' }}</td>
                <td class="text-2">{{ formatTime(s.next_run_at) }}</td>
                <td class="text-right">
                  <button class="btn btn-text btn-sm" type="button" @click="openEditSchedule(s)">编辑</button>
                  <button class="btn btn-text btn-sm danger" type="button" @click="removeSchedule(s)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="clock"
          title="暂无定时预热"
          text="创建定时任务后，控制面会按间隔自动预热指定路径。"
        >
          <button class="btn btn-primary btn-sm" type="button" @click="openCreateSchedule">新建定时任务</button>
        </EmptyState>
      </div>
      <div v-if="schedules.length > schedulePageSize" class="table-footer">
        <AppPagination v-model:page="schedulePage" :total="schedules.length" :page-size="schedulePageSize" />
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">预热任务</div>
          <div class="card-desc">最近 100 条任务，包含手动与定时产生的任务</div>
        </div>
      </div>
      <div class="card-body tight">
        <div v-if="tasks.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>时间</th>
                <th>域名</th>
                <th>路径</th>
                <th>来源</th>
                <th>状态</th>
                <th>结果</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="t in pagedTasks" :key="t.id">
                <td class="text-2">{{ formatTime(t.created_at) }}</td>
                <td class="cell-main">{{ t.domain }}</td>
                <td class="mono text-2">{{ t.url_path }}</td>
                <td>
                  <StatusTag :tone="t.source === 'schedule' ? 'info' : 'neutral'">
                    {{ t.source === 'schedule' ? '定时' : '手动' }}
                  </StatusTag>
                </td>
                <td>
                  <StatusTag :tone="taskTone(t.status)" dot>{{ taskLabel(t.status) }}</StatusTag>
                </td>
                <td class="text-2 truncate" style="max-width: 360px">{{ t.message || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState v-else icon="upload" title="还没有预热任务" text="创建手动或定时任务后，这里会显示执行结果。" />
      </div>
      <div v-if="tasks.length > taskPageSize" class="table-footer">
        <AppPagination v-model:page="taskPage" :total="tasks.length" :page-size="taskPageSize" />
      </div>
    </div>

    <BaseModal
      v-model="scheduleOpen"
      :title="editingSchedule ? '编辑定时预热' : '新建定时预热'"
      width="680px"
      confirm-text="保存"
      :loading="submitting"
      @confirm="saveSchedule"
    >
      <div class="form-col">
        <div class="form-grid">
          <div class="field">
            <label class="field-label">域名 <span class="req">*</span></label>
            <select v-model="scheduleForm.domain" class="select">
              <option value="">请选择域名</option>
              <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">间隔（分钟）</label>
            <input v-model.number="scheduleForm.interval_minutes" class="input" type="number" min="5" max="10080" />
          </div>
        </div>
        <div class="field">
          <label class="field-label">路径列表 <span class="req">*</span></label>
          <textarea v-model="scheduleForm.paths" class="textarea" rows="6" placeholder="/index.html&#10;/static/app.js" />
        </div>
        <label class="check">
          <input v-model="scheduleForm.enabled" type="checkbox" />
          启用定时预热
        </label>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

const domains = ref<any[]>([])
const tasks = ref<any[]>([])
const schedules = ref<any[]>([])
const taskPage = ref(1)
const schedulePage = ref(1)
const taskPageSize = 10
const schedulePageSize = 8
const pagedTasks = computed(() => {
  const start = (taskPage.value - 1) * taskPageSize
  return tasks.value.slice(start, start + taskPageSize)
})
const pagedSchedules = computed(() => {
  const start = (schedulePage.value - 1) * schedulePageSize
  return schedules.value.slice(start, start + schedulePageSize)
})
watch(
  () => tasks.value.length,
  (total) => {
    taskPage.value = Math.min(taskPage.value, Math.max(1, Math.ceil(total / taskPageSize)))
  },
)
watch(
  () => schedules.value.length,
  (total) => {
    schedulePage.value = Math.min(schedulePage.value, Math.max(1, Math.ceil(total / schedulePageSize)))
  },
)
const loading = ref(false)
const submitting = ref(false)
const error = ref('')

const manual = ref({ domain: '', paths: '' })

const scheduleOpen = ref(false)
const editingSchedule = ref<any>(null)
const scheduleForm = ref({
  domain: '',
  paths: '',
  interval_minutes: 60,
  enabled: true,
})

async function load() {
  loading.value = true
  try {
    const [d, t, s] = await Promise.all([
      api.get<any[]>('/api/v1/domains').catch(() => []),
      api.get<any[]>('/api/v1/prefetch/tasks').catch(() => []),
      api.get<any[]>('/api/v1/prefetch/schedules').catch(() => []),
    ])
    domains.value = d || []
    tasks.value = t || []
    schedules.value = s || []
  } finally {
    loading.value = false
  }
}

function taskTone(status: string) {
  if (status === 'done') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'running') return 'info'
  return 'warning'
}

function taskLabel(status: string) {
  return { pending: '等待中', running: '执行中', done: '已完成', failed: '失败' }[status] || status
}

function formatTime(value: string) {
  if (!value) return '—'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

async function createManual() {
  if (!manual.value.domain) {
    toast.error('请选择域名')
    return
  }
  const paths = manual.value.paths
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  if (!paths.length) {
    toast.error('请至少填写一个路径')
    return
  }
  submitting.value = true
  try {
    const res = await api.post<any>('/api/v1/prefetch', {
      domain: manual.value.domain,
      paths,
    })
    toast.success(`已创建 ${res.created} 个预热任务`)
    manual.value.paths = ''
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '创建失败')
  } finally {
    submitting.value = false
  }
}

function openCreateSchedule() {
  error.value = ''
  editingSchedule.value = null
  scheduleForm.value = { domain: '', paths: '', interval_minutes: 60, enabled: true }
  scheduleOpen.value = true
}

function openEditSchedule(s: any) {
  error.value = ''
  editingSchedule.value = s
  scheduleForm.value = {
    domain: s.domain,
    paths: (s.paths || []).join('\n'),
    interval_minutes: s.interval_minutes || 60,
    enabled: !!s.enabled,
  }
  scheduleOpen.value = true
}

async function saveSchedule() {
  error.value = ''
  if (!scheduleForm.value.domain) {
    error.value = '请选择域名'
    return
  }
  const paths = scheduleForm.value.paths
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  if (!paths.length) {
    error.value = '请至少填写一个路径'
    return
  }
  submitting.value = true
  try {
    const body = {
      domain: scheduleForm.value.domain,
      paths,
      interval_minutes: Math.max(5, Number(scheduleForm.value.interval_minutes) || 60),
      enabled: scheduleForm.value.enabled,
    }
    if (editingSchedule.value) {
      await api.put(`/api/v1/prefetch/schedules/${editingSchedule.value.id}`, body)
    } else {
      await api.post('/api/v1/prefetch/schedules', body)
    }
    scheduleOpen.value = false
    toast.success('定时预热已保存')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '保存失败'
  } finally {
    submitting.value = false
  }
}

async function removeSchedule(s: any) {
  const ok = await ask({
    title: '删除定时预热',
    message: `确认删除 ${s.domain} 的定时预热任务？`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/prefetch/schedules/${s.id}`)
    toast.success('定时预热已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.mini-stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.mini-num {
  font-size: 26px;
  font-weight: 600;
  color: var(--text);
}

.mini-label {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-3);
}

@media (max-width: 640px) {
  .mini-stats {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
