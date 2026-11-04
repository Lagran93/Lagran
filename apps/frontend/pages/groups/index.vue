<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">用户组</div>
        <div class="page-desc">按模块授予权限；项目/域名仍受项目成员范围限制</div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          新建用户组
        </button>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">权限组</div>
        <span class="text-muted" style="font-size: 13px">未加入任何用户组的用户沿用原有项目角色权限</span>
      </div>
      <div class="card-body">
        <div v-if="loading" class="skeleton" style="height: 180px" />
        <div v-else-if="groups.length" class="group-list">
          <div v-for="g in groups" :key="g.id" class="group-card">
            <div class="group-head">
              <div>
                <div class="group-name">{{ g.name }}</div>
                <div class="group-desc">{{ g.description || '未填写说明' }}</div>
              </div>
              <div class="group-actions">
                <button class="btn btn-text btn-sm" type="button" @click="openMembers(g)">
                  成员 {{ g.member_count }}
                </button>
                <button class="btn btn-text btn-sm" type="button" @click="openEdit(g)">编辑</button>
                <button class="btn btn-text btn-sm danger" type="button" @click="removeGroup(g)">删除</button>
              </div>
            </div>
            <div class="perm-list">
              <span v-for="p in g.permissions" :key="p" class="perm-pill">
                {{ permissionLabel(p) }}
              </span>
              <span v-if="!g.permissions.length" class="text-muted" style="font-size: 12px">未授予任何模块权限</span>
            </div>
          </div>
        </div>
        <EmptyState v-else icon="users" title="暂无用户组" text="创建用户组后，可为组分配模块权限并添加成员。" />
      </div>
    </div>

    <BaseModal v-model="editOpen" :title="editing ? '编辑用户组' : '新建用户组'" confirm-text="保存"
      :loading="submitting" @confirm="saveGroup">
      <div class="form-col">
        <div class="field">
          <label class="field-label">名称 <span class="req">*</span></label>
          <input v-model="form.name" class="input" placeholder="例如：只读运维" />
        </div>
        <div class="field">
          <label class="field-label">说明</label>
          <input v-model="form.description" class="input" placeholder="这个组负责什么？" />
        </div>
        <div class="field">
          <label class="field-label">模块权限</label>
          <div class="permission-grid">
            <label v-for="p in PERMISSIONS" :key="p.value" class="permission-item">
              <input v-model="form.permissions" type="checkbox" :value="p.value" />
              <span>{{ p.label }}<small>{{ p.value }}</small></span>
            </label>
          </div>
        </div>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>

    <BaseModal v-model="membersOpen" :title="`成员 · ${memberGroup?.name || ''}`" confirm-text="保存成员"
      :loading="submitting" @confirm="saveMembers">
      <div class="form-col">
        <p class="field-hint" style="margin: 0">勾选属于该用户组的账号。成员的项目/域名范围仍由项目成员关系决定。</p>
        <div class="member-list">
          <label v-for="u in users" :key="u.id" class="member-item">
            <input v-model="memberIds" type="checkbox" :value="u.id" />
            <span class="user-avatar">{{ (u.name || u.email).slice(0, 1).toUpperCase() }}</span>
            <span>
              <b>{{ u.name || '未命名' }}</b>
              <small>{{ u.email }}</small>
            </span>
          </label>
        </div>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { friendlyErrorMessage } from '~/utils/friendlyError'

const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

const PERMISSIONS = [
  { value: 'domain:read', label: '查看域名' },
  { value: 'domain:write', label: '管理域名' },
  { value: 'cache:read', label: '查看缓存' },
  { value: 'cache:write', label: '管理缓存规则/刷新/预热' },
  { value: 'waf:read', label: '查看 WAF/CC' },
  { value: 'waf:write', label: '管理 WAF/CC/封禁' },
  { value: 'cert:read', label: '查看证书' },
  { value: 'cert:write', label: '管理证书' },
  { value: 'prefetch:read', label: '查看预热' },
  { value: 'prefetch:write', label: '管理预热' },
  { value: 'project:read', label: '查看项目' },
  { value: 'project:write', label: '管理项目与成员' },
  { value: 'node:read', label: '查看节点' },
  { value: 'node:write', label: '管理节点' },
  { value: 'analytics:read', label: '查看统计与访问日志' },
  { value: 'config:read', label: '查看配置发布' },
  { value: 'config:write', label: '管理配置发布' },
  { value: 'alert:read', label: '查看告警' },
  { value: 'alert:write', label: '管理告警' },
  { value: 'audit:read', label: '查看操作审计' },
  { value: 'settings:read', label: '查看系统设置' },
  { value: 'settings:write', label: '修改系统设置' },
  { value: 'user:read', label: '查看用户' },
  { value: 'user:write', label: '管理用户组' },
]

const loading = ref(false)
const submitting = ref(false)
const groups = ref<any[]>([])
const users = ref<any[]>([])
const editOpen = ref(false)
const editing = ref<any>(null)
const error = ref('')
const form = ref({ name: '', description: '', permissions: [] as string[] })

const membersOpen = ref(false)
const memberGroup = ref<any>(null)
const memberIds = ref<string[]>([])

function permissionLabel(value: string) {
  return PERMISSIONS.find((p) => p.value === value)?.label || value
}

async function load() {
  loading.value = true
  try {
    const [g, u] = await Promise.all([
      api.get<any[]>('/api/v1/groups'),
      api.get<any[]>('/api/v1/users').catch(() => []),
    ])
    groups.value = g || []
    users.value = u || []
  } catch (e: any) {
    toast.error(friendlyErrorMessage(e?.data?.error, '加载用户组失败'))
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  error.value = ''
  form.value = { name: '', description: '', permissions: [] }
  editOpen.value = true
}

function openEdit(group: any) {
  editing.value = group
  error.value = ''
  form.value = {
    name: group.name,
    description: group.description || '',
    permissions: [...(group.permissions || [])],
  }
  editOpen.value = true
}

async function saveGroup() {
  error.value = ''
  if (!form.value.name.trim()) {
    error.value = '请填写用户组名称'
    return
  }
  if (!form.value.permissions.length) {
    error.value = '至少选择一个模块权限'
    return
  }
  submitting.value = true
  try {
    const body = {
      name: form.value.name.trim(),
      description: form.value.description.trim(),
      permissions: form.value.permissions,
    }
    if (editing.value) {
      await api.put(`/api/v1/groups/${editing.value.id}`, body)
      toast.success('用户组已更新')
    } else {
      await api.post('/api/v1/groups', body)
      toast.success('用户组已创建')
    }
    editOpen.value = false
    await load()
  } catch (e: any) {
    error.value = friendlyErrorMessage(e?.data?.error, '保存失败')
  } finally {
    submitting.value = false
  }
}

async function removeGroup(group: any) {
  const ok = await ask({
    title: '删除用户组',
    message: `删除「${group.name}」后，组成员将失去该组授予的权限。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/groups/${group.id}`)
    toast.success('用户组已删除')
    await load()
  } catch (e: any) {
    toast.error(friendlyErrorMessage(e?.data?.error, '删除失败'))
  }
}

function openMembers(group: any) {
  memberGroup.value = group
  memberIds.value = [...(group.member_ids || [])]
  error.value = ''
  membersOpen.value = true
}

async function saveMembers() {
  if (!memberGroup.value) return
  error.value = ''
  submitting.value = true
  try {
    await api.put(`/api/v1/groups/${memberGroup.value.id}/members`, {
      user_ids: memberIds.value,
    })
    membersOpen.value = false
    toast.success('组成员已保存')
    await load()
  } catch (e: any) {
    error.value = friendlyErrorMessage(e?.data?.error, '保存成员失败')
  } finally {
    submitting.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.group-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.group-card {
  border: 1px solid var(--divider);
  border-radius: 12px;
  background: #fff;
  padding: 14px 16px;
}

.group-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.group-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-1);
}

.group-desc {
  margin-top: 3px;
  color: var(--text-3);
  font-size: 12px;
}

.group-actions {
  display: flex;
  gap: 2px;
  flex: none;
}

.perm-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 12px;
}

.perm-pill {
  padding: 3px 8px;
  border-radius: 999px;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 11px;
}

.permission-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
  max-height: 360px;
  overflow: auto;
  padding: 8px;
  border: 1px solid var(--divider);
  border-radius: 10px;
  background: #fafbfc;
}

.permission-item {
  display: flex;
  align-items: flex-start;
  gap: 7px;
  padding: 5px 6px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 12px;
}

.permission-item:hover {
  background: #fff;
}

.permission-item span {
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.permission-item small {
  color: var(--text-3);
  font-size: 10px;
}

.member-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
  max-height: 360px;
  overflow: auto;
}

.user-avatar {
  width: 26px;
  height: 26px;
  border-radius: 50%;
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 11px;
  font-weight: 600;
}

.member-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 8px;
  border: 1px solid var(--divider);
  border-radius: 8px;
  font-size: 12px;
  cursor: pointer;
}

.member-item > span:last-child {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.member-item b {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 500;
}

.member-item small {
  color: var(--text-3);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 720px) {
  .permission-grid,
  .member-list {
    grid-template-columns: 1fr;
  }

  .group-head {
    flex-direction: column;
  }
}
</style>
