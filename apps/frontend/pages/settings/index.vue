<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">系统设置</div>
        <div class="page-desc">账号信息、接口地址与运行状态</div>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="card-head">
          <div class="card-title">个人资料</div>
        </div>
        <div class="card-body">
          <div class="profile">
            <div class="profile-avatar">{{ initial }}</div>
            <div class="flex-1">
              <div class="profile-name">{{ auth.user?.name || '未命名用户' }}</div>
              <div class="profile-mail">{{ auth.user?.email }}</div>
            </div>
            <StatusTag :tone="auth.isAdmin ? 'info' : 'neutral'">
              {{ auth.isAdmin ? '管理员' : '普通用户' }}
            </StatusTag>
          </div>
          <div class="kv-list mt-16">
            <div class="kv">
              <span class="kv-key">用户 ID</span>
              <span class="kv-val mono">{{ auth.user?.id || '—' }}</span>
            </div>
            <div class="kv">
              <span class="kv-key">登录方式</span>
              <span class="kv-val">邮箱 + 密码（JWT）</span>
            </div>
            <div class="kv">
              <span class="kv-key">权限范围</span>
              <span class="kv-val">
                {{ auth.isAdmin ? '全部项目与域名、节点与审计' : '所属项目内的域名与配置' }}
              </span>
            </div>
          </div>
          <p class="text-muted mt-16" style="font-size: 12px">
            账号由控制面数据库管理；如需新增用户，可调用 <code class="mono">POST /api/v1/auth/register</code>。
          </p>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div class="card-title">接口配置</div>
        </div>
        <div class="card-body">
          <div class="field">
            <label class="field-label">控制端 API 地址</label>
            <div class="copy-row">
              <input class="input mono" :value="apiBase" readonly />
              <button class="btn btn-default" type="button" @click="copy(apiBase, 'API 地址')">
                <AppIcon name="copy" :size="15" />
                复制
              </button>
            </div>
            <span class="field-hint">
              前端通过 <code class="mono">NUXT_PUBLIC_API_BASE</code> 注入，修改后需重新构建前端。
            </span>
          </div>

          <div class="field mt-16">
            <label class="field-label">控制面连通性</label>
            <div class="flex-center gap-12">
              <button class="btn btn-default" type="button" :disabled="checking" @click="checkHealth">
                <AppIcon name="activity" :size="15" />
                {{ checking ? '检测中…' : '检测' }}
              </button>
              <StatusTag v-if="healthStatus" :tone="healthStatus.ok ? 'success' : 'danger'" dot>
                {{ healthStatus.ok ? '连接正常' : '连接失败' }}
              </StatusTag>
              <span v-if="healthStatus?.at" class="text-muted" style="font-size: 12px">
                {{ healthStatus.at }}
              </span>
            </div>
            <span v-if="healthStatus && !healthStatus.ok" class="field-hint text-danger">
              {{ healthStatus.message }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">系统信息</div>
      </div>
      <div class="card-body">
        <div class="info-grid">
          <div class="info-item">
            <div class="info-label">控制台版本</div>
            <div class="info-value">Lagran CDN v0.1.0</div>
          </div>
          <div class="info-item">
            <div class="info-label">前端框架</div>
            <div class="info-value">Nuxt 4 · Vue 3 · Pinia</div>
          </div>
          <div class="info-item">
            <div class="info-label">控制面</div>
            <div class="info-value">Rust · Axum · PostgreSQL</div>
          </div>
          <div class="info-item">
            <div class="info-label">边缘节点</div>
            <div class="info-value">Rust · Hyper · rustls</div>
          </div>
        </div>
      </div>
    </div>

    <div class="alert alert-warning mt-16">
      <AppIcon name="shield" :size="16" class="icon" />
      <span>
        生产环境请修改默认管理员密码、JWT_SECRET 与 AGENT_TOKEN，并通过 HTTPS 暴露控制台；不要将 8080 端口直接开放到公网。
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()
const toast = useToast()

const config = useRuntimeConfig()
const apiBase = config.public.apiBase as string

const checking = ref(false)
const healthStatus = ref<{ ok: boolean; at: string; message?: string } | null>(null)

const initial = computed(() => (auth.user?.name || auth.user?.email || 'L').slice(0, 1).toUpperCase())

async function copy(text: string, label: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.success(`${label}已复制`)
  } catch {
    toast.error('复制失败，请手动选择文本')
  }
}

async function checkHealth() {
  checking.value = true
  try {
    const res = await fetch(`${apiBase}/health`)
    const text = await res.text()
    healthStatus.value = {
      ok: res.ok,
      at: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      message: res.ok ? undefined : `HTTP ${res.status} ${text.slice(0, 80)}`,
    }
  } catch (e: any) {
    healthStatus.value = {
      ok: false,
      at: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      message: e?.message || 'network error',
    }
  } finally {
    checking.value = false
  }
}

onMounted(() => {
  auth.hydrate()
})
</script>

<style scoped>
.profile {
  display: flex;
  align-items: center;
  gap: 14px;
}

.profile-avatar {
  width: 52px;
  height: 52px;
  border-radius: 50%;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 20px;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.profile-name {
  font-size: 16px;
  font-weight: 600;
}

.profile-mail {
  font-size: 13px;
  color: var(--text-3);
  margin-top: 2px;
}

.kv-list {
  border-top: 1px solid var(--divider);
  padding-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.kv {
  display: flex;
  gap: 16px;
  font-size: 13px;
}

.kv-key {
  width: 84px;
  flex: none;
  color: var(--text-3);
}

.kv-val {
  color: var(--text-2);
  word-break: break-all;
}

.copy-row {
  display: flex;
  gap: 8px;
}

.copy-row .input {
  flex: 1;
  font-size: 13px;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}

.info-label {
  font-size: 12px;
  color: var(--text-3);
}

.info-value {
  margin-top: 4px;
  font-size: 14px;
  color: var(--text);
}

@media (max-width: 900px) {
  .info-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
