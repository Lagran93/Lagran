<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">缓存刷新</div>
        <div class="page-desc">向所有在线边缘节点下发刷新指令，让变更立即生效</div>
      </div>
      <div class="page-actions">
        <NuxtLink to="/rules" class="btn btn-default">
          <AppIcon name="rules" :size="15" />
          缓存规则
        </NuxtLink>
      </div>
    </div>

    <div class="grid grid-main-side">
      <div>
        <div class="card">
          <div class="card-head">
            <div class="card-title">刷新配置</div>
          </div>
          <div class="card-body">
            <div class="form-col">
              <div class="field">
                <label class="field-label">目标域名 <span class="req">*</span></label>
                <select v-model="form.domain" class="select">
                  <option value="">请选择域名</option>
                  <option v-for="d in domains" :key="d.id" :value="d.name">{{ d.name }}</option>
                </select>
              </div>

              <div class="field">
                <label class="field-label">刷新方式</label>
                <div class="segmented">
                  <button
                    v-for="opt in modes"
                    :key="opt.value"
                    type="button"
                    :class="{ active: mode === opt.value }"
                    @click="mode = opt.value"
                  >
                    {{ opt.label }}
                  </button>
                </div>
              </div>

              <div v-if="mode === 'url'" class="field">
                <label class="field-label">URL 列表</label>
                <textarea
                  v-model="urlsText"
                  class="textarea"
                  rows="5"
                  placeholder="/index.html&#10;/static/app.js"
                />
                <span class="field-hint">每行一个 URL 或路径，按完整地址精确匹配。</span>
              </div>

              <div v-else-if="mode === 'prefix'" class="field">
                <label class="field-label">路径前缀</label>
                <textarea
                  v-model="prefixesText"
                  class="textarea"
                  rows="5"
                  placeholder="/static/&#10;/images/"
                />
                <span class="field-hint">每行一个前缀，匹配该目录下的所有缓存。</span>
              </div>

              <div v-else class="alert alert-danger">
                <AppIcon name="alert" :size="16" class="icon" />
                <span>全站刷新会清除该域名在全部节点的缓存，可能造成回源压力，请谨慎使用。</span>
              </div>

              <div class="flex-between">
                <span class="text-muted" style="font-size: 12px">
                  刷新为异步下发，结果以各节点回执为准
                </span>
                <button class="btn btn-primary" type="button" :disabled="loading" @click="doPurge">
                  <AppIcon name="purge" :size="15" />
                  {{ loading ? '下发中…' : '下发刷新' }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <div v-if="result" class="card">
          <div class="card-head">
            <div>
              <div class="card-title">刷新结果</div>
              <div class="card-desc">
                {{ result.message }} · 共清理约 {{ result.purged_count }} 条缓存
              </div>
            </div>
            <div class="card-extra">
              <StatusTag :tone="result.success ? 'success' : 'warning'" dot>
                {{ result.success ? '全部成功' : '部分失败' }}
              </StatusTag>
            </div>
          </div>
          <div v-if="result.nodes?.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>节点</th>
                  <th>状态</th>
                  <th>清理数量</th>
                  <th>回执</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="n in result.nodes" :key="n.node">
                  <td>
                    <div class="cell-main">{{ n.node }}</div>
                    <div class="cell-sub mono">{{ n.agent_url }}</div>
                  </td>
                  <td>
                    <StatusTag :tone="n.success ? 'success' : 'danger'" dot>
                      {{ n.success ? '成功' : '失败' }}
                    </StatusTag>
                  </td>
                  <td class="num">{{ n.purged_count }}</td>
                  <td class="text-muted">{{ n.message }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState
            v-else
            icon="info"
            title="没有在线边缘节点"
            text="当前没有可接收刷新指令的在线节点，指令未下发。"
          />
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-head">
            <div class="card-title">刷新说明</div>
          </div>
          <div class="card-body tips">
            <div class="tip-row">
              <span class="tip-index">1</span>
              <span>刷新只清除缓存，不会修改源站内容。</span>
            </div>
            <div class="tip-row">
              <span class="tip-index">2</span>
              <span>URL 方式按完整路径匹配缓存键，适合单文件更新。</span>
            </div>
            <div class="tip-row">
              <span class="tip-index">3</span>
              <span>目录方式适合静态资源整体发布，注意回源压力。</span>
            </div>
            <div class="tip-row">
              <span class="tip-index">4</span>
              <span>边缘节点离线时收不到指令，恢复后请再次刷新。</span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <div class="card-title">当前域名</div>
          </div>
          <div class="card-body">
            <div v-if="domains.length" class="flex-col gap-8">
              <div v-for="d in domains.slice(0, 6)" :key="d.id" class="flex-between">
                <span class="truncate" style="font-size: 13px">{{ d.name }}</span>
                <StatusTag :status="d.status" dot>
                  {{ d.status === 'active' ? '启用' : '停用' }}
                </StatusTag>
              </div>
            </div>
            <p v-else class="text-muted" style="font-size: 13px">暂无域名</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

const domains = ref<any[]>([])
const mode = ref<'url' | 'prefix' | 'all'>('url')
const urlsText = ref('')
const prefixesText = ref('')
const loading = ref(false)
const result = ref<any>(null)
const form = ref({ domain: '' })

const modes = [
  { value: 'url', label: '按 URL' },
  { value: 'prefix', label: '按目录' },
  { value: 'all', label: '全站刷新' },
]

async function loadDomains() {
  try {
    domains.value = (await api.get<any[]>('/api/v1/domains')) || []
  } catch {
    domains.value = []
  }
}

async function doPurge() {
  result.value = null
  if (!form.value.domain) {
    toast.error('请先选择要刷新的域名')
    return
  }
  const urls = urlsText.value
    .split('\n')
    .map(s => s.trim())
    .filter(Boolean)
  const prefixes = prefixesText.value
    .split('\n')
    .map(s => s.trim())
    .filter(Boolean)

  if (mode.value === 'url' && !urls.length) {
    toast.error('请至少填写一个 URL')
    return
  }
  if (mode.value === 'prefix' && !prefixes.length) {
    toast.error('请至少填写一个路径前缀')
    return
  }
  if (mode.value === 'all') {
    const ok = await ask({
      title: '全站刷新确认',
      message: `将清除 ${form.value.domain} 在全部边缘节点的缓存，可能带来回源压力。`,
      confirmText: '确认刷新',
      danger: true,
    })
    if (!ok) return
  }

  loading.value = true
  try {
    result.value = await api.post('/api/v1/purge', {
      domain: form.value.domain,
      urls: mode.value === 'url' ? urls : undefined,
      prefixes: mode.value === 'prefix' ? prefixes : undefined,
      purge_all: mode.value === 'all',
    })
    if (result.value?.success) toast.success('刷新指令已下发')
    else toast.info('刷新指令已下发，部分节点返回失败')
  } catch (e: any) {
    toast.error(e?.data?.error || '刷新失败，请确认权限与节点状态')
  } finally {
    loading.value = false
  }
}

onMounted(loadDomains)
</script>

<style scoped>
.tips {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.tip-row {
  display: flex;
  gap: 10px;
  font-size: 13px;
  color: var(--text-2);
  line-height: 1.6;
}

.tip-index {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
  margin-top: 1px;
}
</style>
