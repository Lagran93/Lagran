<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">Shield 节点</div>
        <div class="page-desc">管理员维护可选的 Origin Shield 地址；域名只能从此列表选择</div>
      </div>
      <div v-if="auth.isAdmin" class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          新增 Shield
        </button>
      </div>
    </div>

    <div v-if="!auth.isAdmin" class="alert alert-warning">
      <AppIcon name="shield" :size="16" class="icon" />
      <span>只有管理员可以维护 Shield 节点。</span>
    </div>

    <div v-else class="card">
      <div class="card-head">
        <div class="card-title">Shield 地址白名单</div>
        <span class="text-muted" style="font-size: 13px">
          普通用户只能选择启用的条目；使用中的节点不能停用或删除
        </span>
      </div>
      <div class="card-body">
        <div v-if="loading" class="skeleton" style="height: 180px" />
        <div v-else-if="nodes.length" class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>名称</th>
                <th>URL</th>
                <th>状态</th>
                <th style="width: 160px">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="node in nodes" :key="node.id">
                <td>{{ node.name }}</td>
                <td class="mono">{{ node.url }}</td>
                <td>
                  <StatusTag :tone="node.enabled ? 'success' : 'neutral'" dot>
                    {{ node.enabled ? '已启用' : '已停用' }}
                  </StatusTag>
                </td>
                <td>
                  <div class="flex gap-8">
                    <button class="btn btn-text btn-sm" type="button" @click="openEdit(node)">
                      编辑
                    </button>
                    <button
                      class="btn btn-text btn-sm danger"
                      type="button"
                      @click="removeNode(node)"
                    >
                      删除
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="shield"
          title="还没有 Shield 节点"
          text="新增一个或多个管理员信任的 Shield 地址；域名高级设置会从这里生成下拉列表。"
        />
      </div>
    </div>

    <BaseModal
      v-model="editOpen"
      :title="editing ? '编辑 Shield 节点' : '新增 Shield 节点'"
      confirm-text="保存"
      :loading="submitting"
      @confirm="save"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">名称 <span class="req">*</span></label>
          <input v-model="form.name" class="input" placeholder="例如：华东 Shield" />
        </div>
        <div class="field">
          <label class="field-label">Shield URL <span class="req">*</span></label>
          <input
            v-model="form.url"
            class="input mono"
            placeholder="https://shield-s1.example.com"
          />
          <span class="field-hint">
            只接受 http(s) origin，不能带路径、查询串或账号密码。普通用户不能直接输入 URL。
          </span>
        </div>
        <label class="check-row">
          <input v-model="form.enabled" type="checkbox" />
          <span>启用（普通域名下拉列表可见）</span>
        </label>
        <p v-if="error" class="text-danger" style="font-size: 13px">{{ error }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { friendlyErrorMessage } from '~/utils/friendlyError'

const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { ask } = useConfirm()

interface ShieldNode {
  id: string
  name: string
  url: string
  enabled: boolean
}

const nodes = ref<ShieldNode[]>([])
const loading = ref(false)
const editOpen = ref(false)
const submitting = ref(false)
const editing = ref<ShieldNode | null>(null)
const error = ref('')
const form = reactive({
  name: '',
  url: '',
  enabled: true,
})

async function load() {
  if (!auth.isAdmin) return
  loading.value = true
  try {
    nodes.value = await api.get<ShieldNode[]>('/api/v1/shield-nodes')
  } catch (e: any) {
    toast.error(friendlyErrorMessage(e?.data?.error || e?.message || e, '读取 Shield 节点失败'))
  } finally {
    loading.value = false
  }
}

function resetForm() {
  form.name = ''
  form.url = ''
  form.enabled = true
  error.value = ''
}

function openCreate() {
  editing.value = null
  resetForm()
  editOpen.value = true
}

function openEdit(node: ShieldNode) {
  editing.value = node
  form.name = node.name
  form.url = node.url
  form.enabled = node.enabled
  error.value = ''
  editOpen.value = true
}

async function save() {
  error.value = ''
  submitting.value = true
  try {
    if (editing.value) {
      await api.put(`/api/v1/shield-nodes/${editing.value.id}`, {
        name: form.name,
        url: form.url,
        enabled: form.enabled,
      })
      toast.success('Shield 节点已更新')
    } else {
      await api.post('/api/v1/shield-nodes', {
        name: form.name,
        url: form.url,
        enabled: form.enabled,
      })
      toast.success('Shield 节点已创建')
    }
    editOpen.value = false
    await load()
  } catch (e: any) {
    error.value = friendlyErrorMessage(e?.data?.error || e?.message || e, '保存 Shield 节点失败')
  } finally {
    submitting.value = false
  }
}

async function removeNode(node: ShieldNode) {
  if (!(await ask({
    title: '删除 Shield 节点',
    message: `确认删除「${node.name}」？如果仍有域名使用该地址，控制面会拒绝删除。`,
    confirmText: '删除',
    danger: true,
  }))) {
    return
  }
  try {
    await api.del(`/api/v1/shield-nodes/${node.id}`)
    toast.success('Shield 节点已删除')
    await load()
  } catch (e: any) {
    toast.error(friendlyErrorMessage(e?.data?.error || e?.message || e, '删除 Shield 节点失败'))
  }
}

onMounted(load)
</script>
