<template>
  <div class="login-card">
    <h1>Lagran CDN</h1>
    <p class="muted">管理控制台登录</p>
    <form @submit.prevent="onSubmit">
      <label>
        邮箱
        <input v-model="email" type="email" placeholder="demo@lagran.dev" required />
      </label>
      <label>
        密码
        <input v-model="password" type="password" placeholder="demo123" required />
      </label>
      <button class="btn" type="submit" :disabled="loading">
        {{ loading ? '登录中…' : '登录' }}
      </button>
    </form>
    <p v-if="error" class="error">{{ error }}</p>
    <p class="hint">演示账号：demo@lagran.dev / demo123</p>
  </div>
</template>

<script setup lang="ts">
definePageMeta({ layout: 'auth' })

const config = useRuntimeConfig()
const apiBase = config.public.apiBase as string
const auth = useAuthStore()

const email = ref('demo@lagran.dev')
const password = ref('demo123')
const loading = ref(false)
const error = ref('')

async function onSubmit() {
  loading.value = true
  error.value = ''
  try {
    const res = await $fetch<{
      token: string
      user: { id: string; email: string; name: string }
    }>(`${apiBase}/api/v1/auth/login`, {
      method: 'POST',
      body: { email: email.value, password: password.value },
    })
    auth.setSession(res.token, res.user)
    await navigateTo('/')
  } catch (e: any) {
    const msg =
      e?.data?.error ||
      e?.message ||
      '登录失败，请确认控制端与数据库已启动'
    error.value = msg
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  auth.hydrate()
  if (auth.isAuthenticated) navigateTo('/')
})
</script>

<style scoped>
.login-card {
  width: 360px;
  padding: 2rem;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 12px;
}
h1 { margin: 0 0 0.25rem; color: #38bdf8; }
.muted { color: #94a3b8; margin: 0 0 1.5rem; }
label {
  display: block;
  margin-bottom: 1rem;
  font-size: 0.85rem;
  color: #94a3b8;
}
input {
  display: block;
  width: 100%;
  margin-top: 0.35rem;
  padding: 0.6rem 0.75rem;
  border: 1px solid #334155;
  border-radius: 6px;
  background: #0f172a;
  color: #e2e8f0;
  font-size: 0.95rem;
}
.btn {
  width: 100%;
  margin-top: 0.5rem;
  padding: 0.65rem;
  background: #38bdf8;
  color: #0f172a;
  border: none;
  border-radius: 6px;
  font-weight: 600;
  cursor: pointer;
}
.btn:disabled { opacity: 0.6; cursor: not-allowed; }
.error { color: #f87171; font-size: 0.85rem; margin-top: 1rem; }
.hint { color: #64748b; font-size: 0.75rem; margin-top: 1.25rem; text-align: center; }
</style>
