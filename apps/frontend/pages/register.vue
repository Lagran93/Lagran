<template>
  <div class="register-card card">
    <div class="register-head">
      <div class="register-brand-row">
        <div class="brand-mark">L</div>
        <div>
          <div class="register-brand-name">Lagran CDN</div>
          <div class="register-brand-sub">边缘加速 · 管理控制台</div>
        </div>
      </div>
      <div class="register-eyebrow">
        <span class="status-dot" />
        CREATE WORKSPACE
      </div>
      <div class="register-title">创建账号</div>
      <div class="register-sub">注册后即可创建项目、接入域名并配置缓存与安全策略。</div>
      <div class="register-perks">
        <span>多域名接入</span>
        <span>边缘缓存</span>
        <span>可观测</span>
      </div>
    </div>

    <div v-if="checking" class="text-muted">正在检查注册配置…</div>
    <div v-else-if="!allowRegister" class="alert alert-warning">
      管理员已关闭公开注册，请联系系统管理员创建账号。
    </div>

    <form v-else class="register-form" @submit.prevent="submit">
      <div class="register-grid">
        <div class="field">
          <label class="field-label" for="name">显示名称</label>
          <input id="name" v-model="name" class="input" placeholder="例如 张三" autocomplete="name" />
        </div>
        <div class="field">
          <label class="field-label" for="email">邮箱 <span class="req">*</span></label>
          <input id="email" v-model="email" class="input" type="email" placeholder="you@example.com"
            autocomplete="username" required />
        </div>
      </div>
      <div class="register-grid">
        <div class="field">
          <label class="field-label" for="password">密码 <span class="req">*</span></label>
          <div class="password-wrap">
            <input id="password" v-model="password" class="input" :type="showPassword ? 'text' : 'password'"
              placeholder="至少 8 位，包含字母和数字" autocomplete="new-password" required />
            <button tabindex="-1" class="password-toggle" type="button" :aria-label="showPassword ? '隐藏密码' : '显示密码'"
              @click="showPassword = !showPassword">
              <AppIcon :name="showPassword ? 'eye-off' : 'eye'" :size="15" />
            </button>
          </div>
        </div>
        <div class="field">
          <label class="field-label" for="confirm">确认密码 <span class="req">*</span></label>
          <div class="password-wrap">
            <input id="confirm" v-model="confirm" class="input" :type="showConfirm ? 'text' : 'password'"
              placeholder="再次输入密码" autocomplete="new-password" required />
            <button tabindex="-1" class="password-toggle" type="button" :aria-label="showConfirm ? '隐藏密码' : '显示密码'"
              @click="showConfirm = !showConfirm">
              <AppIcon :name="showConfirm ? 'eye-off' : 'eye'" :size="15" />
            </button>
          </div>
        </div>
      </div>

      <div v-if="captchaEnabled" class="field">
        <label class="field-label" for="captcha">验证码</label>
        <div class="captcha-row">
          <input id="captcha" v-model="captchaCode" class="input" maxlength="5" autocomplete="off"
            placeholder="请输入右侧 5 位验证码" required />
          <button tabindex="-1" class="captcha-image" type="button" title="刷新验证码" @click="loadCaptcha">
            <img v-if="captchaImage" :src="captchaImage" alt="验证码" />
            <span v-else>加载中…</span>
          </button>
          <button tabindex="-1" class="captcha-refresh" type="button" aria-label="刷新验证码" @click="loadCaptcha">
            <AppIcon name="refresh" :size="16" />
          </button>
        </div>
      </div>

      <div v-if="error" class="alert alert-danger">{{ error }}</div>

      <button class="btn btn-primary btn-lg w-full" type="submit" :disabled="loading">
        {{ loading ? '注册中…' : '注册并登录' }}
      </button>
    </form>

    <p class="register-foot">
      已有账号？<NuxtLink to="/login">返回登录</NuxtLink>
    </p>
  </div>
</template>

<script setup lang="ts">
import { friendlyErrorMessage } from '~/utils/friendlyError'

definePageMeta({ layout: 'auth' })

const config = useRuntimeConfig()
const apiBase = config.public.apiBase as string
const auth = useAuthStore()
const toast = useToast()

const checking = ref(true)
const allowRegister = ref(false)
const name = ref('')
const email = ref('')
const password = ref('')
const confirm = ref('')
const showPassword = ref(false)
const showConfirm = ref(false)
const captchaEnabled = ref(false)
const captchaId = ref('')
const captchaCode = ref('')
const captchaImage = ref('')
const loading = ref(false)
const error = ref('')

async function loadCaptcha() {
  captchaCode.value = ''
  captchaImage.value = ''
  try {
    const res = await $fetch<{ captcha_id: string; image_svg: string }>(
      `${apiBase}/api/v1/auth/captcha`,
    )
    captchaId.value = res.captcha_id
    captchaImage.value = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(res.image_svg)}`
  } catch {
    captchaId.value = ''
    captchaImage.value = ''
  }
}

async function submit() {
  error.value = ''
  if (!email.value.trim() || !password.value) {
    error.value = '请输入邮箱和密码'
    return
  }
  if (password.value.length < 8) {
    error.value = '密码至少需要 8 个字符'
    return
  }
  if (!/[A-Za-z]/.test(password.value) || !/\d/.test(password.value)) {
    error.value = '密码必须同时包含字母和数字'
    return
  }
  if (password.value !== confirm.value) {
    error.value = '两次输入的密码不一致'
    return
  }
  if (captchaEnabled.value && !captchaCode.value.trim()) {
    error.value = '请输入验证码'
    return
  }
  loading.value = true
  try {
    const res = await $fetch<{
      token: string
      user: { id: string; email: string; name: string; role?: string }
    }>(`${apiBase}/api/v1/auth/register`, {
      method: 'POST',
      body: {
        email: email.value.trim(),
        password: password.value,
        name: name.value.trim() || undefined,
        captcha_id: captchaId.value,
        captcha_code: captchaCode.value.trim(),
      },
    })
    auth.setSession(res.token, res.user)
    toast.success('注册成功')
    await navigateTo('/')
  } catch (e: any) {
    error.value = friendlyErrorMessage(
      e?.data?.error || e?.message,
      '注册失败，请稍后重试'
    )
    if (captchaEnabled.value) await loadCaptcha()
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  auth.hydrate()
  if (auth.isAuthenticated) {
    navigateTo('/')
    return
  }
  try {
    const cfg = await $fetch<{ allow_register: boolean; captcha_enabled?: boolean }>(
      `${apiBase}/api/v1/auth/config`,
    )
    allowRegister.value = !!cfg.allow_register
    captchaEnabled.value = cfg.captcha_enabled !== false
    if (allowRegister.value && captchaEnabled.value) await loadCaptcha()
  } catch {
    allowRegister.value = false
  } finally {
    checking.value = false
  }
})
</script>

<style scoped>
.register-card {
  width: min(440px, calc(100vw - 32px));
  padding: 28px;
}

.register-head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 22px;
}

.brand-mark {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  background: var(--brand);
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 18px;
}

.register-title {
  font-size: 20px;
  font-weight: 700;
}

.register-sub {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-3);
}

.register-form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.register-foot {
  margin-top: 18px;
  text-align: center;
  font-size: 13px;
  color: var(--text-3);
}

.register-foot a {
  color: var(--brand);
  font-weight: 600;
  margin-left: 4px;
}

.captcha-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.captcha-row .input {
  flex: 1;
  min-width: 0;
}

.captcha-image {
  height: 34px;
  min-width: 110px;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: #f3f7ff;
  overflow: hidden;
  cursor: pointer;
  flex: none;
}

.captcha-image img {
  display: block;
  width: 110px;
  height: 34px;
}

.captcha-refresh {
  width: 34px;
  height: 34px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--card);
  color: var(--text-3);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.captcha-refresh:hover {
  color: var(--brand);
  border-color: var(--brand);
}

/* ---------------------------------------------------------------
   Register refresh + dark theme
   --------------------------------------------------------------- */

.register-card {
  position: relative;
  z-index: 1;
  width: min(540px, calc(100vw - 32px));
  padding: 32px;
  border-radius: 20px;
  background: var(--card);
  border-color: var(--border);
  box-shadow:
    0 2px 6px rgba(15, 23, 42, 0.04),
    0 30px 90px rgba(15, 23, 42, 0.14);
}

.register-head {
  display: block;
  margin-bottom: 24px;
}

.register-brand-row {
  display: flex;
  align-items: center;
  gap: 11px;
  margin-bottom: 22px;
}

.brand-mark {
  width: 38px;
  height: 38px;
  border-radius: 11px;
  background: linear-gradient(135deg, #3b82f6, #2563eb 58%, #1d4ed8);
  box-shadow: 0 8px 18px rgba(37, 99, 235, 0.22);
  font-size: 17px;
}

.register-brand-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  line-height: 1.25;
}

.register-brand-sub {
  margin-top: 2px;
  font-size: 11.5px;
  color: var(--text-3);
}

.register-eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 13px;
  padding: 4px 9px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--bg);
  color: var(--text-3);
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.08em;
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--success);
  box-shadow: 0 0 0 3px rgba(0, 185, 42, 0.1);
}

.register-title {
  font-size: 28px;
  letter-spacing: -0.03em;
  color: var(--text);
}

.register-sub {
  margin-top: 7px;
  font-size: 13px;
  line-height: 1.65;
  color: var(--text-3);
}

.register-perks {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  margin-top: 16px;
}

.register-perks span {
  padding: 3px 9px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--bg);
  color: var(--text-2);
  font-size: 11px;
}

.register-form {
  margin-top: 22px;
  gap: 16px;
}

.register-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.password-wrap {
  position: relative;
}

.password-wrap .input {
  padding-right: 38px;
}

.password-toggle {
  position: absolute;
  right: 4px;
  top: 3px;
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  color: var(--text-3);
  border-radius: var(--radius);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
}

.password-toggle:hover {
  color: var(--text);
  background: var(--bg);
}

.captcha-image {
  background: var(--bg);
}

.register-trust {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  margin-top: 18px;
  color: var(--text-4);
  font-size: 11.5px;
  text-align: center;
}

.register-foot {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--divider);
  font-size: 12.5px;
  color: var(--text-3);
}

.register-foot a {
  color: var(--brand);
}

:global(html[data-theme='dark']) .register-card {
  border-color: var(--border);
  box-shadow:
    0 2px 8px rgba(0, 0, 0, 0.35),
    0 34px 100px rgba(0, 0, 0, 0.5);
}

:global(html[data-theme='dark']) .register-eyebrow {
  background: var(--bg);
  border-color: var(--border);
  color: var(--text-3);
}

:global(html[data-theme='dark']) .status-dot {
  box-shadow: 0 0 0 3px rgba(61, 220, 132, 0.12);
}

:global(html[data-theme='dark']) .captcha-image {
  background: #0b1420;
}

:global(html[data-theme='dark']) .password-toggle:hover {
  background: var(--bg);
  color: var(--text);
}

@media (max-width: 640px) {
  .register-card {
    width: min(100%, calc(100vw - 24px));
    padding: 24px 18px;
    border-radius: 18px;
  }

  .register-title {
    font-size: 25px;
  }

  .register-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .register-brand-row {
    margin-bottom: 18px;
  }
}

/* The captcha SVG already has its own rounded background. Keep the button
   chrome transparent so dark mode does not show a second frame around it. */
.captcha-image {
  padding: 0;
  border: 0;
  border-radius: 6px;
  background: transparent;
  line-height: 0;
  box-shadow: none;
  appearance: none;
}

.captcha-image img {
  display: block;
  width: 100%;
  height: 100%;
  border: 0;
  border-radius: 6px;
  object-fit: cover;
}
</style>
