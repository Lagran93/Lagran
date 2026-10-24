<template>
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <NuxtLink to="/">Lagran CDN</NuxtLink>
      </div>
      <nav>
        <NuxtLink to="/">仪表盘</NuxtLink>
        <NuxtLink to="/projects">项目</NuxtLink>
        <NuxtLink to="/domains">域名</NuxtLink>
        <NuxtLink to="/rules">缓存规则</NuxtLink>
        <NuxtLink to="/nodes">边缘节点</NuxtLink>
        <NuxtLink to="/stats">统计分析</NuxtLink>
        <NuxtLink to="/certs">证书</NuxtLink>
        <NuxtLink to="/settings">设置</NuxtLink>
      </nav>
      <div class="sidebar-footer">
        <div v-if="auth.user" class="user">{{ auth.user.name || auth.user.email }}</div>
        <a href="#" @click.prevent="onLogout">退出登录</a>
      </div>
    </aside>
    <div class="main">
      <header class="topbar">
        <span class="page-title">{{ pageTitle }}</span>
      </header>
      <main class="content">
        <slot />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
const route = useRoute()
const auth = useAuthStore()

onMounted(() => auth.hydrate())

const pageTitle = computed(() => {
  const map: Record<string, string> = {
    '/': '仪表盘',
    '/projects': '项目管理',
    '/domains': '域名管理',
    '/rules': '缓存规则',
    '/nodes': '边缘节点',
    '/stats': '统计分析',
    '/certs': '证书管理',
    '/settings': '系统设置',
  }
  return map[route.path] || 'Lagran CDN'
})

function onLogout() {
  auth.logout()
  navigateTo('/login')
}
</script>

<style>
:root {
  --sidebar-w: 220px;
  --bg: #0f172a;
  --sidebar-bg: #1e293b;
  --border: #334155;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --card: #1e293b;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
}
a { color: inherit; text-decoration: none; }
.layout { display: flex; min-height: 100vh; }
.sidebar {
  width: var(--sidebar-w);
  background: var(--sidebar-bg);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  padding: 1rem 0;
  position: fixed;
  height: 100vh;
}
.brand {
  padding: 0.5rem 1.25rem 1.5rem;
  font-weight: 700;
  font-size: 1.15rem;
  color: var(--accent);
}
.sidebar nav {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  flex: 1;
}
.sidebar nav a {
  padding: 0.6rem 1.25rem;
  color: var(--muted);
  border-left: 3px solid transparent;
}
.sidebar nav a:hover { color: var(--text); background: rgba(255,255,255,0.03); }
.sidebar nav a.router-link-active {
  color: var(--accent);
  border-left-color: var(--accent);
  background: rgba(56, 189, 248, 0.08);
}
.sidebar-footer {
  padding: 1rem 1.25rem;
  border-top: 1px solid var(--border);
  font-size: 0.875rem;
  color: var(--muted);
}
.sidebar-footer .user {
  margin-bottom: 0.5rem;
  color: var(--text);
  font-size: 0.8rem;
}
.main {
  margin-left: var(--sidebar-w);
  flex: 1;
  display: flex;
  flex-direction: column;
}
.topbar {
  padding: 1rem 1.75rem;
  border-bottom: 1px solid var(--border);
  background: var(--sidebar-bg);
}
.page-title { font-weight: 600; font-size: 1.05rem; }
.content { padding: 1.75rem; flex: 1; }
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.25rem;
}
.grid { display: grid; gap: 1rem; }
.grid-4 { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
.stat-value { font-size: 1.75rem; font-weight: 700; color: var(--accent); }
.stat-label { font-size: 0.85rem; color: var(--muted); margin-top: 0.25rem; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 500; font-size: 0.85rem; }
.btn {
  display: inline-block;
  padding: 0.5rem 1rem;
  background: var(--accent);
  color: #0f172a;
  border: none;
  border-radius: 6px;
  font-weight: 600;
  cursor: pointer;
  font-size: 0.9rem;
}
.btn:hover { filter: brightness(1.1); }
.btn-ghost {
  background: transparent;
  color: var(--muted);
  border: 1px solid var(--border);
}
.muted { color: var(--muted); }
.empty { text-align: center; padding: 3rem; color: var(--muted); }
</style>
