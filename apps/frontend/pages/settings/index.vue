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
          <div class="flex gap-8 mt-16">
            <button class="btn btn-default btn-sm" type="button" @click="openProfile">
              编辑资料
            </button>
            <button class="btn btn-default btn-sm" type="button" @click="openPassword">
              修改密码
            </button>
          </div>
          <p class="text-muted mt-16" style="font-size: 12px">
            账号由系统管理员统一管理。
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
              <input class="input mono" :value="effectiveApiBase" readonly />
              <button class="btn btn-default" type="button" @click="copy(effectiveApiBase, 'API 地址')">
                <AppIcon name="copy" :size="15" />
                复制
              </button>
            </div>
            <span class="field-hint">
              未单独配置时使用当前站点同源地址，由反向代理转发到控制面。
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
            <div class="info-label">控制台</div>
            <div class="info-value">Lagran CDN</div>
          </div>
          <div class="info-item">
            <div class="info-label">控制面版本</div>
            <div class="info-value mono">{{ controlVersion || '—' }}</div>
          </div>
          <div class="info-item">
            <div class="info-label">开源许可</div>
            <div class="info-value">
              <a
                href="https://github.com/Lagran93/Lagran"
                target="_blank"
                rel="noopener"
                style="color: var(--brand)"
              >
                AGPL-3.0-only · 源代码
              </a>
            </div>
          </div>
          <div class="info-item">
            <div class="info-label">当前角色</div>
            <div class="info-value">{{ auth.isAdmin ? '系统管理员' : '普通用户' }}</div>
          </div>
          <div class="info-item">
            <div class="info-label">会话策略</div>
            <div class="info-value">密码修改后旧会话立即失效</div>
          </div>
          <div class="info-item">
            <div class="info-label">接入方式</div>
            <div class="info-value">同源 API + 边缘节点</div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="auth.isAdmin" class="card mt-16">
      <div class="card-head">
        <div>
          <div class="card-title">系统升级</div>
          <div class="card-desc">从 GitHub Release 检测并安装新版本</div>
        </div>
        <StatusTag
          v-if="updateInfo && !updateInfo.error"
          :tone="updateInfo.update_available ? 'warning' : 'success'"
          dot
        >
          {{ updateInfo.update_available ? '有新版本' : '已是最新' }}
        </StatusTag>
      </div>
      <div class="card-body">
        <div class="update-grid">
          <div class="update-metric">
            <div class="info-label">当前版本</div>
            <div class="info-value mono">{{ updateInfo?.current_version || controlVersion || '—' }}</div>
          </div>
          <div class="update-metric">
            <div class="info-label">GitHub 最新版本</div>
            <div class="info-value mono">{{ updateInfo?.latest_version || '—' }}</div>
          </div>
          <div class="update-metric">
            <div class="info-label">更新组件</div>
            <div class="info-value">控制面 / Edge / DNS / Web</div>
          </div>
        </div>

        <div v-if="updateInfo?.update_available" class="update-banner">
          <AppIcon name="upload" :size="16" />
          <span>
            检测到新版本 <b>{{ updateInfo.latest_version }}</b>，更新过程中控制面会短暂重启。
          </span>
        </div>
        <div v-else-if="updateInfo?.error" class="field-hint text-danger mt-12">
          {{ updateInfo.error }}
        </div>

        <div class="flex gap-8 mt-16" style="flex-wrap: wrap">
          <button class="btn btn-default btn-sm" type="button" :disabled="updateChecking" @click="checkUpdate">
            <AppIcon name="refresh" :size="15" />
            {{ updateChecking ? '检测中…' : '检测更新' }}
          </button>
          <button
            v-if="updateInfo?.update_available"
            class="btn btn-primary btn-sm"
            type="button"
            :disabled="updateApplying || !updateInfo.updater_available"
            @click="applyUpdate"
          >
            <AppIcon name="upload" :size="15" />
            {{ updateApplying ? '更新中…' : '立即更新' }}
          </button>
          <a
            v-if="updateInfo?.release_url"
            class="btn btn-default btn-sm"
            :href="updateInfo.release_url"
            target="_blank"
            rel="noopener"
          >
            查看 Release
          </a>
        </div>
        <p v-if="updateInfo && !updateInfo.updater_available" class="field-hint text-warning mt-12">
          当前安装未配置 root 更新助手，请重新执行 <code>install.sh control</code>。
        </p>
        <p v-if="updateMessage" class="field-hint mt-12">{{ updateMessage }}</p>
        <p v-if="updateStatusInfo?.message" class="field-hint mt-8">
          更新状态：{{ updateStatusInfo.state }} · {{ updateStatusInfo.message }}
        </p>
      </div>
    </div>

    <div class="card mt-16">
      <div class="card-head">
        <div>
          <div class="card-title">加密货币捐赠</div>
          <div class="card-desc">支持 Lagran CDN 的持续开发与节点运维</div>
        </div>
      </div>
      <div class="card-body">
        <p class="donation-intro">
          捐赠完全自愿，不影响软件许可，也不附带服务等级或商业承诺。
        </p>
        <div v-if="donations.length" class="donation-grid">
          <div v-for="item in donations" :key="item.asset" class="donation-item">
            <div class="donation-head">
              <span class="donation-network">{{ item.network }}</span>
              <span class="donation-asset">{{ item.asset }}</span>
            </div>
            <div class="donation-address mono">{{ item.address }}</div>
            <button class="btn btn-default btn-sm mt-8" type="button" @click="copy(item.address, item.asset + ' 地址')">
              <AppIcon name="copy" :size="14" />
              复制地址
            </button>
          </div>
        </div>
        <div v-else class="donation-empty">
          <AppIcon name="activity" :size="18" />
          <span>捐赠地址由控制面内置，当前未返回可展示地址。</span>
        </div>
        <p v-if="donationNotice" class="field-hint mt-12">{{ donationNotice }}</p>
      </div>
    </div>

    <div class="alert alert-warning mt-16">
      <AppIcon name="shield" :size="16" class="icon" />
      <span>如遇访问异常，请联系系统管理员。</span>
    </div>

    <BaseModal
      v-model="profileOpen"
      title="编辑个人资料"
      confirm-text="保存"
      :loading="saving"
      @confirm="saveProfile"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">显示名称</label>
          <input v-model="profileName" class="input" />
        </div>
        <p v-if="profileError" class="text-danger" style="font-size: 13px">{{ profileError }}</p>
      </div>
    </BaseModal>

    <BaseModal
      v-model="passwordOpen"
      title="修改密码"
      confirm-text="修改"
      :loading="saving"
      @confirm="savePassword"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">当前密码</label>
          <input v-model="currentPassword" class="input" type="password" />
        </div>
        <div class="field">
          <label class="field-label">新密码</label>
          <input v-model="newPassword" class="input" type="password" placeholder="至少 8 位，含字母和数字" />
        </div>
        <p v-if="passwordError" class="text-danger" style="font-size: 13px">{{ passwordError }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
const api = useApi()
const auth = useAuthStore()
const toast = useToast()

const config = useRuntimeConfig()
const apiBase = config.public.apiBase as string
const effectiveApiBase = computed(() => {
  const configured = (apiBase || '').trim().replace(/\/+$/, '')
  if (configured) return configured
  return import.meta.client ? window.location.origin : ''
})

const checking = ref(false)
const healthStatus = ref<{ ok: boolean; at: string; message?: string } | null>(null)
const controlVersion = ref('')

interface DonationEntry {
  network: string
  asset: string
  address: string
}
const donations = ref<DonationEntry[]>([])
const donationNotice = ref('')

interface UpdateInfo {
  current_version: string
  latest_version: string | null
  update_available: boolean
  release_url: string | null
  published_at: string | null
  notes: string | null
  updater_available: boolean
  error: string | null
}
const updateInfo = ref<UpdateInfo | null>(null)
const updateChecking = ref(false)
const updateApplying = ref(false)
const updateMessage = ref('')
const updateStatusInfo = ref<{ state: string; message: string | null } | null>(null)

async function loadDonations() {
  try {
    const res = await api.get<{ entries: DonationEntry[]; notice: string }>(
      '/api/v1/system/donation',
    )
    donations.value = res.entries || []
    donationNotice.value = res.notice || ''
  } catch {
    donations.value = []
  }
}

async function checkUpdate() {
  if (!auth.isAdmin) return
  updateChecking.value = true
  updateMessage.value = ''
  try {
    const res = await api.get<UpdateInfo>('/api/v1/system/update')
    updateInfo.value = res
    if (res.current_version) controlVersion.value = res.current_version
    if (res.error) updateMessage.value = res.error
  } catch (e: any) {
    updateMessage.value = e?.data?.error || e?.message || '检测更新失败'
  } finally {
    updateChecking.value = false
  }
}

async function loadUpdateStatus() {
  if (!auth.isAdmin) return
  try {
    const res = await api.get<{ state: string; message: string | null }>(
      '/api/v1/system/update/status',
    )
    updateStatusInfo.value = res
    if (res.state === 'failed' || res.state === 'success') {
      updateApplying.value = false
    }
  } catch {
    // The control plane restarts during an update; the next poll can recover.
  }
}

async function applyUpdate() {
  if (!updateInfo.value?.latest_version) return
  if (!window.confirm(`确定更新到 ${updateInfo.value.latest_version}？控制面会短暂重启。`)) {
    return
  }
  updateApplying.value = true
  updateMessage.value = '更新任务已提交，正在下载并校验 Release…'
  try {
    const res = await api.post<{ queued: boolean; version: string; message: string }>(
      '/api/v1/system/update',
      { version: updateInfo.value.latest_version },
    )
    updateMessage.value = res.message || '更新任务已排队'
    toast.success('更新任务已提交')
    for (const delay of [3000, 8000, 15000]) {
      window.setTimeout(() => {
        loadUpdateStatus()
        checkUpdate()
      }, delay)
    }
  } catch (e: any) {
    updateApplying.value = false
    updateMessage.value = e?.data?.error || e?.message || '提交更新失败'
    toast.error(updateMessage.value)
  }
}

const profileOpen = ref(false)
const profileName = ref('')
const profileError = ref('')
const passwordOpen = ref(false)
const currentPassword = ref('')
const newPassword = ref('')
const passwordError = ref('')
const saving = ref(false)

function openProfile() {
  profileName.value = auth.user?.name || ''
  profileError.value = ''
  profileOpen.value = true
}

function openPassword() {
  currentPassword.value = ''
  newPassword.value = ''
  passwordError.value = ''
  passwordOpen.value = true
}

async function saveProfile() {
  profileError.value = ''
  saving.value = true
  try {
    const user = await api.put<any>('/api/v1/auth/me', {
      name: profileName.value.trim(),
    })
    auth.setSession(auth.token!, user)
    profileOpen.value = false
    toast.success('资料已更新')
  } catch (e: any) {
    profileError.value = e?.data?.error || '保存失败'
  } finally {
    saving.value = false
  }
}

async function savePassword() {
  passwordError.value = ''
  saving.value = true
  try {
    const res = await api.put<{ success: boolean; token: string }>(
      '/api/v1/auth/me/password',
      {
        current_password: currentPassword.value,
        new_password: newPassword.value,
      },
    )
    if (res.token && auth.user) {
      // The old JWT is revoked by the token-version bump. Keep the current
      // session alive with the newly issued token.
      auth.setSession(res.token, auth.user)
    }
    passwordOpen.value = false
    currentPassword.value = ''
    newPassword.value = ''
    toast.success('密码已修改')
  } catch (e: any) {
    passwordError.value = e?.data?.error || '修改失败'
  } finally {
    saving.value = false
  }
}

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
    const res = await fetch(`${effectiveApiBase.value}/health`)
    const text = await res.text()
    if (res.ok) {
      try {
        const data = JSON.parse(text)
        if (data.version) controlVersion.value = data.version
      } catch {
        // Health may be served by a non-JSON proxy; keep the version blank.
      }
    }
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
  loadDonations()
  if (auth.isAdmin) {
    checkUpdate()
    loadUpdateStatus()
  }
  fetch(`${effectiveApiBase.value}/health`)
    .then((res) => (res.ok ? res.json() : null))
    .then((data) => {
      if (data?.version) controlVersion.value = data.version
    })
    .catch(() => {})
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

.update-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}

.update-metric {
  padding: 12px 14px;
  border: 1px solid var(--divider);
  border-radius: var(--radius);
  background: var(--bg);
}

.update-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 16px;
  padding: 10px 12px;
  border: 1px solid var(--warning-border);
  border-radius: var(--radius);
  background: var(--warning-bg);
  color: var(--warning);
  font-size: 13px;
}

.donation-intro {
  margin-bottom: 14px;
  color: var(--text-2);
  font-size: 13px;
  line-height: 1.7;
}

.donation-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.donation-item {
  min-width: 0;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg);
}

.donation-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
}

.donation-network {
  color: var(--text);
  font-size: 14px;
  font-weight: 600;
}

.donation-asset {
  color: var(--text-3);
  font-size: 11px;
}

.donation-address {
  margin-top: 8px;
  color: var(--text-2);
  word-break: break-all;
  line-height: 1.6;
}

.donation-empty {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 18px;
  color: var(--text-3);
  font-size: 13px;
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
}

@media (max-width: 900px) {
  .info-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .update-grid,
  .donation-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (max-width: 640px) {
  .profile {
    flex-wrap: wrap;
  }

  .profile .flex-1 {
    min-width: 0;
  }

  .kv {
    flex-wrap: wrap;
    gap: 4px 12px;
  }

  .kv-key {
    width: auto;
    min-width: 72px;
  }

  .copy-row {
    flex-direction: column;
    align-items: stretch;
  }

  .copy-row .input {
    width: 100%;
    min-width: 0;
  }

  .copy-row .btn {
    width: 100%;
  }

  .flex.gap-8 {
    flex-wrap: wrap;
  }

  .info-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .info-value {
    word-break: break-word;
  }
}
</style>
