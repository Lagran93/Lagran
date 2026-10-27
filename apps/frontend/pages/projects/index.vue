<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">项目管理</div>
        <div class="page-desc">用项目隔离不同业务线的域名与成员权限</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          新建项目
        </button>
      </div>
    </div>

    <div v-if="projects.length" class="project-grid">
      <div v-for="p in projects" :key="p.id" class="project-card">
        <div class="project-head">
          <div class="project-mark">{{ p.name.slice(0, 1) }}</div>
          <div class="flex-1" style="min-width: 0">
            <div class="project-name truncate">{{ p.name }}</div>
            <div class="project-meta">创建于 {{ formatDay(p.created_at) }}</div>
          </div>
          <StatusTag :tone="isOwner(p) ? 'info' : 'neutral'">
            {{ isOwner(p) ? '拥有者' : '成员' }}
          </StatusTag>
        </div>

        <div class="project-stats">
          <div>
            <div class="project-num">{{ p.domain_count }}</div>
            <div class="project-label">域名</div>
          </div>
          <div>
            <div class="project-num">{{ memberCount(p.id) }}</div>
            <div class="project-label">成员</div>
          </div>
          <div>
            <div class="project-num">{{ p.id.slice(0, 6) }}</div>
            <div class="project-label">项目 ID</div>
          </div>
        </div>

        <div class="project-foot">
          <button class="btn btn-text btn-sm" type="button" @click="openDrawer(p, 'domains')">
            <AppIcon name="domain" :size="14" />
            域名
          </button>
          <button class="btn btn-text btn-sm" type="button" @click="openDrawer(p, 'members')">
            <AppIcon name="users" :size="14" />
            成员
          </button>
          <span class="spacer" />
          <button class="btn btn-text btn-sm danger" type="button" @click="remove(p)">删除</button>
        </div>
      </div>
    </div>

    <div v-else-if="loading" class="card">
      <div class="card-body">
        <div class="skeleton" style="height: 120px; width: 100%" />
      </div>
    </div>

    <div v-else class="card">
      <EmptyState
        icon="project"
        title="还没有项目"
        text="项目用于隔离域名与成员权限。也可以不建项目，直接接入域名（域名会归入你的 Default 项目）。"
      >
        <button class="btn btn-primary btn-sm" type="button" @click="openCreate">新建项目</button>
      </EmptyState>
    </div>

    <BaseModal
      v-model="createOpen"
      title="新建项目"
      confirm-text="创建项目"
      :loading="submitting"
      @confirm="createProject"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">项目名称 <span class="req">*</span></label>
          <input v-model="name" class="input" placeholder="例如 官网静态资源" />
          <span class="field-hint">创建后你自动成为项目拥有者，可邀请成员协作。</span>
        </div>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>

    <BaseDrawer v-model="drawerOpen" :title="`项目 · ${activeProject?.name || ''}`">
      <template #footer>
        <button class="btn btn-default" type="button" @click="drawerOpen = false">关闭</button>
      </template>

      <div class="segmented mb-16">
        <button type="button" :class="{ active: tab === 'domains' }" @click="switchTab('domains')">
          域名（{{ projectDomains.length }}）
        </button>
        <button type="button" :class="{ active: tab === 'members' }" @click="switchTab('members')">
          成员（{{ members.length }}）
        </button>
      </div>

      <div v-if="tab === 'domains'">
        <div v-if="projectDomains.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>域名</th>
                <th>源站</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="d in projectDomains" :key="d.id">
                <td>
                  <NuxtLink :to="`/domains/${d.id}`" class="cell-main">{{ d.name }}</NuxtLink>
                </td>
                <td class="mono text-2">{{ d.origin_proto }}://{{ d.origin_host }}:{{ d.origin_port }}</td>
                <td>
                  <StatusTag :status="d.status" dot>
                    {{ d.status === 'active' ? '启用' : '停用' }}
                  </StatusTag>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="domain"
          title="项目下暂无域名"
          text="在「域名管理」把域名的所属项目设为该项目即可。"
        />
      </div>

      <div v-else>
        <div class="add-member">
          <input v-model="memberEmail" class="input" placeholder="成员邮箱（需已注册）" />
          <select v-model="memberRole" class="select" style="width: 110px">
            <option value="member">只读成员</option>
            <option value="admin">管理员</option>
          </select>
          <button class="btn btn-primary" type="button" :disabled="adding" @click="addMember">
            {{ adding ? '添加中…' : '添加' }}
          </button>
        </div>

        <div v-if="members.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>成员</th>
                <th>角色</th>
                <th class="text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in members" :key="m.user_id">
                <td>
                  <div class="cell-main">{{ m.name || m.email }}</div>
                  <div class="cell-sub">{{ m.email }}</div>
                </td>
                <td>
                  <StatusTag :tone="m.role === 'owner' ? 'info' : m.role === 'admin' ? 'success' : 'neutral'">
                    {{ roleText(m.role) }}
                  </StatusTag>
                </td>
                <td class="text-right">
                  <button
                    v-if="m.role === 'member'"
                    class="btn btn-text btn-sm"
                    type="button"
                    @click="setMemberRole(m, 'admin')"
                  >
                    设为管理员
                  </button>
                  <button
                    v-else-if="m.role === 'admin'"
                    class="btn btn-text btn-sm"
                    type="button"
                    @click="setMemberRole(m, 'member')"
                  >
                    设为只读
                  </button>
                  <button
                    v-if="m.role !== 'owner'"
                    class="btn btn-text btn-sm danger"
                    type="button"
                    @click="removeMember(m)"
                  >
                    移除
                  </button>
                  <span v-else class="text-muted" style="font-size: 12px">—</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="users"
          title="暂无成员"
          text="添加成员后，对方可以在自己的控制台看到该项目下的域名。"
        />
      </div>
    </BaseDrawer>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { ask } = useConfirm()

interface MemberCount {
  [projectId: string]: number
}

const projects = ref<any[]>([])
const loading = ref(false)
const submitting = ref(false)

const createOpen = ref(false)
const name = ref('')
const error = ref('')

const drawerOpen = ref(false)
const activeProject = ref<any>(null)
const tab = ref<'domains' | 'members'>('domains')
const projectDomains = ref<any[]>([])
const members = ref<any[]>([])
const memberCounts = ref<MemberCount>({})
const memberEmail = ref('')
const memberRole = ref('member')
const adding = ref(false)

function isOwner(p: any) {
  return !!auth.user && p.owner_id === auth.user.id
}

function memberCount(projectId: string) {
  return memberCounts.value[projectId] ?? '—'
}

function roleText(role: string) {
  if (role === 'owner') return '拥有者'
  if (role === 'admin') return '管理员'
  return '只读成员'
}

async function load() {
  loading.value = true
  try {
    projects.value = (await api.get<any[]>('/api/v1/projects')) || []
    // Preload member counts for the cards that are visible.
    const counts: MemberCount = {}
    await Promise.all(
      projects.value.map(async (p) => {
        try {
          const list = await api.get<any[]>(`/api/v1/projects/${p.id}/members`)
          counts[p.id] = (list || []).length
        } catch {
          counts[p.id] = 0
        }
      }),
    )
    memberCounts.value = counts
  } finally {
    loading.value = false
  }
}

function openCreate() {
  error.value = ''
  name.value = ''
  createOpen.value = true
}

async function createProject() {
  error.value = ''
  if (!name.value.trim()) {
    error.value = '请填写项目名称'
    return
  }
  submitting.value = true
  try {
    await api.post('/api/v1/projects', { name: name.value.trim() })
    createOpen.value = false
    toast.success('项目已创建')
    await load()
  } catch (e: any) {
    error.value = e?.data?.error || '创建失败'
  } finally {
    submitting.value = false
  }
}

async function remove(p: any) {
  const ok = await ask({
    title: '删除项目',
    message: `删除「${p.name}」后，项目下的域名会解除归属，但不会被删除。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/projects/${p.id}`)
    toast.success('项目已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败（仅拥有者可删除）')
  }
}

async function openDrawer(p: any, nextTab: 'domains' | 'members') {
  activeProject.value = p
  drawerOpen.value = true
  await switchTab(nextTab)
}

async function switchTab(next: 'domains' | 'members') {
  tab.value = next
  if (!activeProject.value) return
  if (next === 'domains') {
    try {
      projectDomains.value = (await api.get<any[]>(`/api/v1/projects/${activeProject.value.id}/domains`)) || []
    } catch {
      projectDomains.value = []
    }
  } else {
    await loadMembers()
  }
}

async function loadMembers() {
  if (!activeProject.value) return
  try {
    members.value = (await api.get<any[]>(`/api/v1/projects/${activeProject.value.id}/members`)) || []
  } catch {
    members.value = []
  }
}

async function addMember() {
  if (!activeProject.value) return
  const email = memberEmail.value.trim()
  if (!email) {
    toast.error('请输入成员邮箱')
    return
  }
  adding.value = true
  try {
    await api.post(`/api/v1/projects/${activeProject.value.id}/members`, {
      email,
      role: memberRole.value,
    })
    memberEmail.value = ''
    toast.success('成员已添加')
    await loadMembers()
    memberCounts.value = {
      ...memberCounts.value,
      [activeProject.value.id]: members.value.length,
    }
  } catch (e: any) {
    toast.error(e?.data?.error || '添加失败，请确认邮箱已注册且你有管理权限')
  } finally {
    adding.value = false
  }
}

async function setMemberRole(m: any, role: 'member' | 'admin') {
  if (!activeProject.value) return
  try {
    await api.put(`/api/v1/projects/${activeProject.value.id}/members/${m.user_id}`, { role })
    toast.success(role === 'admin' ? '已设为项目管理员' : '已设为只读成员')
    await loadMembers()
  } catch (e: any) {
    toast.error(e?.data?.error || '修改角色失败')
  }
}

async function removeMember(m: any) {
  if (!activeProject.value) return
  const ok = await ask({
    title: '移除成员',
    message: `确认将 ${m.email} 从项目「${activeProject.value.name}」中移除？`,
    confirmText: '移除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/projects/${activeProject.value.id}/members/${m.user_id}`)
    toast.success('成员已移除')
    await loadMembers()
    memberCounts.value = {
      ...memberCounts.value,
      [activeProject.value.id]: members.value.length,
    }
  } catch (e: any) {
    toast.error(e?.data?.error || '移除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.project-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}

.project-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px;
  box-shadow: var(--shadow-sm);
  display: flex;
  flex-direction: column;
  transition: box-shadow 0.15s ease, border-color 0.15s ease;
}

.project-card:hover {
  border-color: #bedaff;
  box-shadow: var(--shadow);
}

.project-head {
  display: flex;
  align-items: center;
  gap: 12px;
}

.project-mark {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: var(--brand-bg);
  color: var(--brand);
  font-weight: 600;
  font-size: 17px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.project-name {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
}

.project-meta {
  font-size: 12px;
  color: var(--text-3);
  margin-top: 2px;
}

.project-stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
  margin: 16px 0;
  padding: 12px 0;
  border-top: 1px solid var(--divider);
  border-bottom: 1px solid var(--divider);
}

.project-num {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  font-variant-numeric: tabular-nums;
}

.project-label {
  font-size: 12px;
  color: var(--text-3);
  margin-top: 2px;
}

.project-foot {
  display: flex;
  align-items: center;
  gap: 2px;
}

.add-member {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
}

.add-member .input {
  flex: 1;
}
</style>
