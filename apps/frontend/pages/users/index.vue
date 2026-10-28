<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">用户管理</div>
        <div class="page-desc">管理账号、角色与启用状态；普通用户只能访问所属项目</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" @click="exportUsers">
          <AppIcon name="upload" :size="15" />
          导出 CSV
        </button>
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          新建用户
        </button>
      </div>
    </div>

    <div class="user-stats">
      <div class="stat-card">
        <div class="stat-num">{{ users.length }}</div>
        <div class="stat-label">全部用户</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ activeCount }}</div>
        <div class="stat-label">已启用</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ adminCount }}</div>
        <div class="stat-label">全局管理员</div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">账号列表</div>
        <input v-model="keyword" class="input search" placeholder="搜索邮箱或名称" />
      </div>
      <div class="card-body">
        <div v-if="loading" class="skeleton" style="height: 180px" />
        <div v-else-if="filtered.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>用户</th>
                <th>全局角色</th>
                <th>状态</th>
                <th>项目</th>
                <th>最近登录</th>
                <th class="text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="u in pagedUsers" :key="u.id">
                <td>
                  <div class="user-cell">
                    <span class="user-avatar">{{ (u.name || u.email).slice(0, 1).toUpperCase() }}</span>
                    <div>
                      <div class="cell-main">
                        {{ u.name || '未命名' }}
                        <span v-if="u.id === auth.user?.id" class="tag tag-info">我</span>
                      </div>
                      <div class="cell-sub">{{ u.email }}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <StatusTag :tone="u.role === 'admin' ? 'info' : 'neutral'">
                    {{ u.role === 'admin' ? '管理员' : '普通用户' }}
                  </StatusTag>
                </td>
                <td>
                  <StatusTag :tone="u.is_active ? 'success' : 'danger'" dot>
                    {{ u.is_active ? '启用' : '已禁用' }}
                  </StatusTag>
                </td>
                <td>{{ u.project_count }}</td>
                <td class="text-2">{{ formatTime(u.last_login_at) }}</td>
                <td class="text-right">
                  <button class="btn btn-text btn-sm" type="button" @click="openEdit(u)">编辑</button>
                  <button
                    v-if="u.id !== auth.user?.id"
                    class="btn btn-text btn-sm danger"
                    type="button"
                    @click="removeUser(u)"
                  >
                    删除
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="users"
          title="暂无用户"
          text="创建账号后，可将用户加入项目并分配只读或管理权限。"
        />
        <div v-if="filtered.length > pageSize" class="table-footer">
          <AppPagination v-model:page="page" :total="filtered.length" :page-size="pageSize" />
        </div>
      </div>
    </div>

    <BaseModal
      v-model="createOpen"
      title="新建用户"
      confirm-text="创建"
      :loading="submitting"
      @confirm="createUser"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">邮箱 <span class="req">*</span></label>
          <input v-model="form.email" class="input" type="email" placeholder="user@example.com" />
        </div>
        <div class="field">
          <label class="field-label">名称</label>
          <input v-model="form.name" class="input" placeholder="显示名称" />
        </div>
        <div class="field">
          <label class="field-label">初始密码 <span class="req">*</span></label>
          <input v-model="form.password" class="input" type="password" placeholder="至少 8 位，含字母和数字" />
        </div>
        <div class="field">
          <label class="field-label">全局角色</label>
          <select v-model="form.role" class="select">
            <option value="user">普通用户</option>
            <option value="admin">管理员</option>
          </select>
        </div>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>

    <BaseModal
      v-model="editOpen"
      title="编辑用户"
      confirm-text="保存"
      :loading="submitting"
      @confirm="updateUser"
    >
      <div v-if="editing" class="form-col">
        <div class="field">
          <label class="field-label">邮箱</label>
          <input class="input" :value="editing.email" readonly />
        </div>
        <div class="field">
          <label class="field-label">名称</label>
          <input v-model="form.name" class="input" />
        </div>
        <div class="field">
          <label class="field-label">全局角色</label>
          <select v-model="form.role" class="select" :disabled="editing.id === auth.user?.id">
            <option value="user">普通用户</option>
            <option value="admin">管理员</option>
          </select>
        </div>
        <label class="check">
          <input
            v-model="form.is_active"
            type="checkbox"
            :disabled="editing.id === auth.user?.id"
          />
          启用该账号
        </label>
        <div v-if="editing.id !== auth.user?.id" class="field">
          <label class="field-label">重置密码（可选）</label>
          <input v-model="form.password" class="input" type="password" placeholder="留空则不修改" />
        </div>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { ask } = useConfirm()

const users = ref<any[]>([])
const loading = ref(false)
const keyword = ref('')
const createOpen = ref(false)
const editOpen = ref(false)
const editing = ref<any>(null)
const submitting = ref(false)
const error = ref('')
const form = ref({
  email: '',
  name: '',
  password: '',
  role: 'user',
  is_active: true,
})

const filtered = computed(() => {
  const q = keyword.value.trim().toLowerCase()
  if (!q) return users.value
  return users.value.filter(
    (u) => String(u.email).toLowerCase().includes(q) || String(u.name).toLowerCase().includes(q),
  )
})
const pageSize = 10
const page = ref(1)
const pagedUsers = computed(() => {
  const start = (page.value - 1) * pageSize
  return filtered.value.slice(start, start + pageSize)
})

function exportUsers() {
  exportCsv(`lagran-users-${new Date().toISOString().slice(0, 10)}`, filtered.value, [
    { key: 'email', label: '邮箱' },
    { key: 'name', label: '名称' },
    { key: 'role', label: '角色' },
    { key: 'is_active', label: '启用' },
    { key: 'project_count', label: '项目数' },
    { key: 'last_login_at', label: '最近登录' },
    { key: 'created_at', label: '创建时间' },
  ])
}
watch(keyword, () => {
  page.value = 1
})
watch(
  () => filtered.value.length,
  (total) => {
    page.value = Math.min(page.value, Math.max(1, Math.ceil(total / pageSize)))
  },
)
const activeCount = computed(() => users.value.filter((u) => u.is_active).length)
const adminCount = computed(() => users.value.filter((u) => u.role === 'admin' && u.is_active).length)

function formatTime(value: string | null) {
  if (!value) return '—'
  return new Date(value).toLocaleString('zh-CN', { hour12: false })
}

function resetForm() {
  form.value = { email: '', name: '', password: '', role: 'user', is_active: true }
  error.value = ''
}

function openCreate() {
  resetForm()
  createOpen.value = true
}

function openEdit(user: any) {
  resetForm()
  editing.value = user
  form.value = {
    email: user.email,
    name: user.name || '',
    password: '',
    role: user.role,
    is_active: !!user.is_active,
  }
  editOpen.value = true
}

async function load() {
  loading.value = true
  try {
    users.value = (await api.get<any[]>('/api/v1/users')) || []
  } catch (e: any) {
    toast.error(e?.data?.error || '加载用户失败')
  } finally {
    loading.value = false
  }
}

async function createUser() {
  error.value = ''
  submitting.value = true
  try {
    await api.post('/api/v1/users', {
      email: form.value.email.trim(),
      password: form.value.password,
      name: form.value.name.trim(),
      role: form.value.role,
    })
    createOpen.value = false
    toast.success('用户已创建')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '创建失败'
  } finally {
    submitting.value = false
  }
}

async function updateUser() {
  if (!editing.value) return
  error.value = ''
  submitting.value = true
  try {
    await api.put(`/api/v1/users/${editing.value.id}`, {
      name: form.value.name.trim(),
      role: form.value.role,
      is_active: form.value.is_active,
      password: form.value.password || undefined,
    })
    editOpen.value = false
    toast.success('用户已更新')
    await load()
    await auth.refresh()
  } catch (e: any) {
    error.value = e?.data?.error || '保存失败'
  } finally {
    submitting.value = false
  }
}

async function removeUser(user: any) {
  const ok = await ask({
    title: '删除用户',
    message: `确定删除 ${user.email}？该用户拥有的项目会一并删除。`,
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/users/${user.id}`)
    toast.success('用户已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

onMounted(() => {
  auth.hydrate()
  if (!auth.isAdmin) {
    navigateTo('/')
    return
  }
  load()
})
</script>

<style scoped>
.user-stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 16px;
}

.stat-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px 18px;
}

.stat-num {
  font-size: 24px;
  font-weight: 700;
  color: var(--text);
}

.stat-label {
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-3);
}

.search {
  width: 240px;
}

.user-cell {
  display: flex;
  align-items: center;
  gap: 10px;
}

.user-avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--brand-bg);
  color: var(--brand);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  flex: none;
}

@media (max-width: 800px) {
  .user-stats {
    grid-template-columns: 1fr;
  }
  .search {
    width: 100%;
  }
}

@media (max-width: 640px) {
  .card-head .search {
    width: 100%;
  }

  .table {
    min-width: 680px;
  }
}

@media (min-width: 1920px) {
  .stat-card {
    padding: 22px;
  }

  .stat-num {
    font-size: 32px;
  }
}

@media (min-width: 2560px) {
  .stat-card {
    padding: 26px;
  }

  .stat-num {
    font-size: 38px;
  }
}
</style>
