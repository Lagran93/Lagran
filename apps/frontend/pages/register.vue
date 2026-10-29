<template>
  <div class="register-card card">
    <div class="register-head">
      <div class="brand-mark">L</div>
      <div>
        <div class="register-title">创建账号</div>
        <div class="register-sub">注册后即可创建项目、接入域名</div>
      </div>
    </div>

    <div v-if="checking" class="text-muted">正在检查注册配置…</div>
    <div v-else-if="!allowRegister" class="alert alert-warning">
      管理员已关闭公开注册，请联系系统管理员创建账号。
    </div>

    <form v-else class="register-form" @submit.prevent="submit">
      <div class="field">
        <label class="field-label" for="name">显示名称</label>
        <input id="name" v-model="name" class="input" placeholder="例如 张三" autocomplete="name" />
      </div>
      <div class="field">
        <label class="field-label" for="email">邮箱</label>
        <input
          id="email"
          v-model="email"
          class="input"
          type="email"
          placeholder="you@example.com"
          autocomplete="username"
          required
        />
      </div>
      <div class="field">
        <label class="field-label" for="password">密码</label>
        <input
          id="password"
          v-model="password"
          class="input"
          type="password"
          placeholder="至少 8 位，包含字母和数字"
          autocomplete="new-password"
          required
        />
      </div>
      <div class="field">
        <label class="field-label" for="confirm">确认密码</label>
        <input
          id="confirm"
          v-model="confirm"
          class="input"
          type="password"
          placeholder="再次输入密码"
          autocomplete="new-password"
          required
        />
      </div>

      <div v-if="captchaEnabled" class="field">
        <label class="field-label" for="captcha">验证码</label>
        <div class="captcha-row">
          <input
            id="captcha"
            v-model="captchaCode"
            class="input"
            maxlength="5"
            autocomplete="off"
            placeholder="请输入右侧 5 位验证码"
            required
          />
          <button class="captcha-image" type="button" title="刷新验证码" @click="loadCaptcha">
            <img v-if="captchaImage" :src="captchaImage" alt="验证码" />
            <span v-else>加载中…</span>
          </button>
          <button class="captcha-refresh" type="button" aria-label="刷新验证码" @click="loadCaptcha">
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
    error.value = e?.data?.error || e?.message || '注册失败，请稍后重试'
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
  height: 44px;
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
  height: 44px;
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
</style>
