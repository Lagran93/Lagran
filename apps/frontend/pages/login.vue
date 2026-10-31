<template>
  <div class="login-shell">
    <section class="login-brand">
      <div class="brand-row">
        <div class="brand-logo">L</div>
        <div>
          <div class="brand-name">Lagran CDN</div>
          <div class="brand-sub">边缘加速 · 管理控制台</div>
        </div>
      </div>

      <div class="brand-copy">
        <h1>让内容触达<br />每一位用户</h1>
        <p>多域名接入、精细化缓存策略、边缘节点实时监控，一套控制台完成全部配置。</p>
      </div>

      <ul class="brand-points">
        <li>
          <span class="point-icon">
            <AppIcon name="zap" :size="16" />
          </span>
          <div>
            <strong>边缘加速</strong>
            <span>多节点分布式缓存，命中即返回</span>
          </div>
        </li>
        <li>
          <span class="point-icon">
            <AppIcon name="rules" :size="16" />
          </span>
          <div>
            <strong>灵活策略</strong>
            <span>按路径配置 TTL、绕过与 SWR</span>
          </div>
        </li>
        <li>
          <span class="point-icon">
            <AppIcon name="users" :size="16" />
          </span>
          <div>
            <strong>多租户隔离</strong>
            <span>项目成员按角色分配权限</span>
          </div>
        </li>
        <li>
          <span class="point-icon">
            <AppIcon name="stats" :size="16" />
          </span>
          <div>
            <strong>可观测</strong>
            <span>命中率、访问日志与源站健康</span>
          </div>
        </li>
      </ul>

      <div class="brand-foot">
        © 2026 Lagran · 自托管 CDN 系统 ·
        <a
          href="https://github.com/Lagran93/Lagran"
          target="_blank"
          rel="noopener"
          style="color: inherit; text-decoration: underline"
        >
          AGPL-3.0 源代码
        </a>
      </div>
    </section>

    <section class="login-panel">
      <div class="login-card">
        <h2>登录控制台</h2>
        <p class="login-sub">使用账号登录，管理域名、缓存与边缘节点</p>

        <form class="login-form" @submit.prevent="onSubmit">
          <div class="field">
            <label class="field-label" for="email">邮箱</label>
            <input id="email" v-model="email" class="input" type="email" autocomplete="username" placeholder="请输入邮箱地址"
              required />
          </div>

          <div class="field">
            <label class="field-label" for="password">密码</label>
            <div class="password-wrap">
              <input id="password" v-model="password" class="input" :type="showPassword ? 'text' : 'password'"
                autocomplete="current-password" placeholder="请输入密码" required />
              <button class="password-toggle" type="button" :aria-label="showPassword ? '隐藏密码' : '显示密码'"
                @click="showPassword = !showPassword">
                <AppIcon :name="showPassword ? 'eye-off' : 'eye'" :size="16" />
              </button>
            </div>
          </div>

          <div v-if="captchaEnabled" class="field">
            <label class="field-label" for="captcha">验证码</label>
            <div class="captcha-row">
              <input id="captcha" v-model="captchaCode" class="input" maxlength="5" autocomplete="off"
                placeholder="请输入右侧 5 位验证码" required />
              <button class="captcha-image" type="button" title="刷新验证码" @click="loadCaptcha">
                <img v-if="captchaImage" :src="captchaImage" alt="验证码" />
                <span v-else>加载中…</span>
              </button>
              <button class="captcha-refresh" type="button" aria-label="刷新验证码" @click="loadCaptcha">
                <AppIcon name="refresh" :size="16" />
              </button>
            </div>
          </div>

          <div class="login-options">
            <label class="check">
              <input v-model="remember" type="checkbox" />
              记住邮箱
            </label>
            <span class="text-muted" style="font-size: 12px">忘记密码请联系系统管理员</span>
          </div>

          <div v-if="error" class="alert alert-danger login-error">
            <AppIcon name="alert" :size="16" class="icon" />
            <span>{{ error }}</span>
          </div>

          <button class="btn btn-primary btn-lg w-full" type="submit" :disabled="loading">
            {{ loading ? '登录中…' : '登 录' }}
          </button>
        </form>

        <p v-if="allowRegister" class="register-link">
          还没有账号？<NuxtLink to="/register">注册新用户</NuxtLink>
        </p>
        <p class="login-foot">请妥善保管账号信息，勿与他人共享。</p>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
definePageMeta({ layout: 'auth' })

const config = useRuntimeConfig()
const apiBase = config.public.apiBase as string
const auth = useAuthStore()
const toast = useToast()

const email = ref('')
const password = ref('')
const remember = ref(true)
const showPassword = ref(false)
const allowRegister = ref(false)
const captchaEnabled = ref(false)
const captchaId = ref('')
const captchaCode = ref('')
const captchaImage = ref('')
const loading = ref(false)
const error = ref('')

const REMEMBER_KEY = 'lagran_last_email'

async function loadCaptcha() {
  captchaCode.value = ''
  captchaImage.value = ''
  try {
    const res = await $fetch<{ captcha_id: string; image_svg: string; expires_in: number }>(
      `${apiBase}/api/v1/auth/captcha`,
    )
    captchaId.value = res.captcha_id
    captchaImage.value = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(res.image_svg)}`
  } catch {
    captchaId.value = ''
    captchaImage.value = ''
  }
}

async function onSubmit() {
  error.value = ''
  if (!email.value.trim() || !password.value) {
    error.value = '请输入邮箱与密码'
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
    }>(`${apiBase}/api/v1/auth/login`, {
      method: 'POST',
      body: {
        email: email.value.trim(),
        password: password.value,
        captcha_id: captchaId.value,
        captcha_code: captchaCode.value.trim(),
      },
    })
    auth.setSession(res.token, res.user)
    if (import.meta.client) {
      if (remember.value) localStorage.setItem(REMEMBER_KEY, email.value.trim())
      else localStorage.removeItem(REMEMBER_KEY)
    }
    toast.success('登录成功，正在进入控制台')
    await navigateTo('/')
  } catch (e: any) {
    error.value =
      e?.data?.error ||
      e?.message ||
      '登录失败，请稍后重试'
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
  if (import.meta.client) {
    const saved = localStorage.getItem(REMEMBER_KEY)
    if (saved) email.value = saved
  }
  try {
    const cfg = await $fetch<{ allow_register: boolean; captcha_enabled?: boolean }>(
      `${apiBase}/api/v1/auth/config`,
    )
    allowRegister.value = !!cfg.allow_register
    captchaEnabled.value = cfg.captcha_enabled !== false
    if (captchaEnabled.value) await loadCaptcha()
  } catch {
    allowRegister.value = false
    captchaEnabled.value = true
    await loadCaptcha()
  }
})
</script>

<style scoped>
.login-shell {
  width: min(1040px, 100%);
  min-height: 620px;
  display: grid;
  grid-template-columns: 1.05fr 1fr;
  background: var(--card);
  border-radius: 16px;
  overflow: hidden;
  box-shadow: 0 24px 70px rgba(22, 119, 255, 0.16);
  border: 1px solid rgba(22, 119, 255, 0.08);
}

.login-brand {
  background: linear-gradient(150deg, #1677ff 0%, #2f7cf6 45%, #0e5fd8 100%);
  color: #fff;
  padding: 40px 40px 28px;
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
}

.login-brand::after {
  content: '';
  position: absolute;
  width: 420px;
  height: 420px;
  right: -160px;
  bottom: -180px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.08);
}

.login-brand::before {
  content: '';
  position: absolute;
  width: 240px;
  height: 240px;
  right: 40px;
  top: -120px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.07);
}

.brand-row {
  display: flex;
  align-items: center;
  gap: 12px;
  position: relative;
  z-index: 1;
}

.brand-logo {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.18);
  border: 1px solid rgba(255, 255, 255, 0.3);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 17px;
}

.brand-name {
  font-size: 17px;
  font-weight: 600;
  line-height: 1.2;
}

.brand-sub {
  font-size: 12px;
  opacity: 0.78;
}

.brand-copy {
  margin-top: 44px;
  position: relative;
  z-index: 1;
}

.brand-copy h1 {
  font-size: 34px;
  line-height: 1.35;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.brand-copy p {
  margin-top: 14px;
  font-size: 14px;
  line-height: 1.8;
  opacity: 0.86;
  max-width: 360px;
}

.brand-points {
  list-style: none;
  margin: 30px 0 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 14px;
  position: relative;
  z-index: 1;
}

.brand-points li {
  display: flex;
  align-items: flex-start;
  gap: 12px;
}

.point-icon {
  width: 30px;
  height: 30px;
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.16);
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.brand-points strong {
  display: block;
  font-size: 14px;
  font-weight: 500;
}

.brand-points span {
  display: block;
  font-size: 12.5px;
  opacity: 0.78;
  margin-top: 1px;
}

.brand-foot {
  margin-top: auto;
  padding-top: 24px;
  font-size: 12px;
  opacity: 0.66;
  position: relative;
  z-index: 1;
}

.login-panel {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 40px 44px;
  background: #fff;
}

.login-card {
  width: 100%;
  max-width: 360px;
}

.login-card h2 {
  font-size: 24px;
  font-weight: 600;
  color: var(--text);
}

.login-sub {
  margin-top: 8px;
  font-size: 13px;
  color: var(--text-3);
}

.login-form {
  margin-top: 28px;
  display: flex;
  flex-direction: column;
  gap: 18px;
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
  background: #f2f3f5;
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
  min-width: 132px;
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
  width: 132px;
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

.login-options {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.login-error {
  margin: 0;
}

.login-foot {
  margin-top: 18px;
  font-size: 12px;
  color: var(--text-4);
  line-height: 1.7;
  text-align: center;
}

.register-link {
  margin-top: 14px;
  text-align: center;
  font-size: 13px;
  color: var(--text-3);
}

.register-link a {
  color: var(--brand);
  font-weight: 600;
  margin-left: 4px;
}

@media (max-width: 900px) {
  .login-shell {
    grid-template-columns: 1fr;
    min-height: 0;
  }

  .login-brand {
    display: none;
  }

  .login-panel {
    padding: 32px 24px;
  }
}

@media (min-width: 1920px) {
  .login-shell {
    width: min(1240px, 90vw);
    min-height: 700px;
  }

  .login-brand {
    padding: 52px 52px 36px;
  }

  .login-card {
    width: 100%;
    max-width: 360px;
  }
}

@media (min-width: 2560px) {
  .login-shell {
    width: min(1480px, 86vw);
    min-height: 820px;
  }

  .login-brand {
    padding: 64px 64px 44px;
  }

  .login-card {
    width: 100%;
    max-width: 360px;
  }
}
</style>
