<script setup lang="ts">
interface MenuItem {
  label: string
  to: string
  icon: string
  admin?: boolean
}

interface MenuGroup {
  title: string
  items: MenuItem[]
}

const MENU: MenuGroup[] = [
  {
    title: '概览',
    items: [{ label: '仪表盘', to: '/', icon: 'dashboard' }],
  },
  {
    title: '加速服务',
    items: [
      { label: '域名管理', to: '/domains', icon: 'domain' },
      { label: '缓存规则', to: '/rules', icon: 'rules' },
      { label: '缓存诊断', to: '/cache-debug', icon: 'search' },
      { label: 'WAF 防护', to: '/waf', icon: 'shield' },
      { label: '证书管理', to: '/certs', icon: 'cert' },
      { label: '缓存刷新', to: '/purge', icon: 'purge' },
      { label: '缓存预热', to: '/prefetch', icon: 'upload' },
      { label: '配置发布', to: '/config-releases', icon: 'upload', admin: true },
    ],
  },
  {
    title: '运维监控',
    items: [
      { label: '边缘节点', to: '/nodes', icon: 'node', admin: true },
      { label: '统计分析', to: '/stats', icon: 'stats' },
      { label: '告警中心', to: '/alerts', icon: 'alert', admin: true },
      { label: '访问日志', to: '/access-logs', icon: 'logs' },
      { label: '操作审计', to: '/audit', icon: 'audit', admin: true },
    ],
  },
  {
    title: '系统',
    items: [
      { label: '项目管理', to: '/projects', icon: 'project' },
      { label: '用户管理', to: '/users', icon: 'users', admin: true },
      { label: '系统设置', to: '/settings', icon: 'settings' },
    ],
  },
]

const route = useRoute()
const auth = useAuthStore()

const sidebarOpen = ref(false)
const userMenuOpen = ref(false)

const groups = computed<MenuGroup[]>(() =>
  MENU.map(group => ({
    ...group,
    items: group.items.filter(item => !item.admin || auth.isAdmin),
  })).filter(group => group.items.length > 0),
)

function isActive(to: string): boolean {
  if (to === '/') return route.path === '/'
  return route.path === to || route.path.startsWith(`${to}/`)
}

const current = computed<{ group: string; label: string }>(() => {
  if (route.path === '/') return { group: '概览', label: '仪表盘' }
  if (route.path.startsWith('/domains/')) return { group: '加速服务', label: '域名详情' }
  for (const group of MENU) {
    for (const item of group.items) {
      if (isActive(item.to)) return { group: group.title, label: item.label }
    }
  }
  return { group: '控制台', label: '页面' }
})

useHead(() => ({ title: `${current.value.label} · Lagran CDN 控制台` }))

const displayName = computed(() => auth.user?.name || auth.user?.email || '未登录')
const initial = computed(() => (displayName.value || 'L').slice(0, 1).toUpperCase())

function closeSidebar() {
  sidebarOpen.value = false
}

function logout() {
  auth.logout()
  userMenuOpen.value = false
  navigateTo('/login')
}

watch(
  () => route.path,
  () => {
    sidebarOpen.value = false
    userMenuOpen.value = false
  },
)

onMounted(async () => {
  auth.hydrate()
  await auth.refresh()
})
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar" :class="{ open: sidebarOpen }">
      <div class="sidebar-brand">
        <div class="brand-mark">L</div>
        <div class="brand-text">
          <span class="brand-name">Lagran CDN</span>
          <span class="brand-sub">管理控制台</span>
        </div>
      </div>

      <nav class="sidebar-nav">
        <div v-for="group in groups" :key="group.title" class="menu-group">
          <div class="menu-title">{{ group.title }}</div>
          <NuxtLink
            v-for="item in group.items"
            :key="item.to"
            :to="item.to"
            class="menu-item"
            :class="{ active: isActive(item.to) }"
            @click="closeSidebar"
          >
            <AppIcon :name="item.icon" :size="18" class="icon" />
            <span>{{ item.label }}</span>
          </NuxtLink>
        </div>
      </nav>

      <div class="sidebar-foot">
        <span class="dot" style="background: var(--success)" />
        <span>控制面已连接</span>
      </div>
    </aside>

    <div v-if="sidebarOpen" class="sidebar-mask" @click="closeSidebar" />

    <div class="main">
      <header class="topbar">
        <button
          class="btn btn-icon btn-default topbar-menu-btn"
          type="button"
          aria-label="打开导航"
          @click="sidebarOpen = !sidebarOpen"
        >
          <AppIcon name="menu" :size="18" />
        </button>

        <div class="crumbs">
          <span>控制台</span>
          <AppIcon name="chevron-right" :size="12" class="sep" />
          <span>{{ current.group }}</span>
          <AppIcon name="chevron-right" :size="12" class="sep" />
          <span class="current">{{ current.label }}</span>
        </div>

        <div class="topbar-right">
          <span class="env-chip">
            <span class="env-dot" />
            服务运行中
          </span>

          <div class="user-chip" @click.stop="userMenuOpen = !userMenuOpen">
            <span class="avatar">{{ initial }}</span>
            <span class="user-name">{{ displayName }}</span>
            <AppIcon name="chevron-down" :size="14" />
          </div>

          <div v-if="userMenuOpen" class="user-dropdown" @click.stop>
            <div class="dropdown-head">
              <div class="dropdown-name">
                {{ displayName }}
                <span class="tag" :class="auth.isAdmin ? 'tag-info' : 'tag-neutral'" style="margin-left: 6px">
                  {{ auth.isAdmin ? '管理员' : '普通用户' }}
                </span>
              </div>
              <div class="dropdown-mail">{{ auth.user?.email }}</div>
            </div>
            <div class="dropdown-item" @click="navigateTo('/settings')">
              <AppIcon name="settings" :size="16" />
              个人设置
            </div>
            <div class="dropdown-item danger" @click="logout">
              <AppIcon name="logout" :size="16" />
              退出登录
            </div>
          </div>
        </div>
      </header>

      <div v-if="userMenuOpen" class="dropdown-backdrop" @click="userMenuOpen = false" />

      <main class="content">
        <slot />
      </main>
    </div>

    <ToastHost />
    <ConfirmHost />
  </div>
</template>

<style scoped>
.dropdown-backdrop {
  position: fixed;
  inset: 0;
  z-index: 10;
}
</style>
