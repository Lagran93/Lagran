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
      { label: '接入向导', to: '/domains/onboard', icon: 'plus' },
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
      { label: '大屏监控', to: '/monitor', icon: 'activity' },
      { label: '告警中心', to: '/alerts', icon: 'alert' },
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
const theme = useTheme()
const i18n = useLocale()

const NAV_KEYS: Record<string, string> = {
  '/': 'nav.dashboard',
  '/domains': 'nav.domains',
  '/domains/onboard': 'nav.onboard',
  '/rules': 'nav.rules',
  '/cache-debug': 'nav.cacheDebug',
  '/waf': 'nav.waf',
  '/certs': 'nav.certs',
  '/purge': 'nav.purge',
  '/prefetch': 'nav.prefetch',
  '/config-releases': 'nav.releases',
  '/nodes': 'nav.nodes',
  '/stats': 'nav.stats',
  '/monitor': 'nav.monitor',
  '/alerts': 'nav.alerts',
  '/access-logs': 'nav.logs',
  '/audit': 'nav.audit',
  '/projects': 'nav.projects',
  '/users': 'nav.users',
  '/settings': 'nav.settings',
}
const GROUP_KEYS: Record<string, string> = {
  概览: 'group.overview',
  加速服务: 'group.edge',
  运维监控: 'group.observe',
  系统: 'group.system',
}

const sidebarOpen = ref(false)
const userMenuOpen = ref(false)

const groups = computed<MenuGroup[]>(() =>
  MENU.map((group) => ({
    ...group,
    title: i18n.t(GROUP_KEYS[group.title] || group.title),
    items: group.items
      .filter((item) => !item.admin || auth.isAdmin)
      .map((item) => ({ ...item, label: i18n.t(NAV_KEYS[item.to] || item.label) })),
  })).filter((group) => group.items.length > 0),
)

function isActive(to: string): boolean {
  if (to === '/') return route.path === '/'
  if (to === '/domains') {
    return route.path === '/domains' || (route.path.startsWith('/domains/') && route.path !== '/domains/onboard')
  }
  return route.path === to || route.path.startsWith(`${to}/`)
}

const current = computed<{ group: string; label: string }>(() => {
  if (route.path === '/') return { group: i18n.t('group.overview'), label: i18n.t('nav.dashboard') }
  if (route.path === '/domains/onboard') {
    return { group: i18n.t('group.edge'), label: i18n.t('nav.onboard') }
  }
  if (route.path.startsWith('/domains/')) {
    return { group: i18n.t('group.edge'), label: i18n.t('nav.domains') }
  }
  for (const group of MENU) {
    for (const item of group.items) {
      if (isActive(item.to)) {
        return {
          group: i18n.t(GROUP_KEYS[group.title] || group.title),
          label: i18n.t(NAV_KEYS[item.to] || item.label),
        }
      }
    }
  }
  return { group: i18n.t('group.overview'), label: 'Lagran' }
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

let authRefreshTimer: ReturnType<typeof setInterval> | undefined

onMounted(async () => {
  auth.hydrate()
  await auth.refresh()
  // Detect revocations/expiry even when the user is idle on one page.
  authRefreshTimer = setInterval(() => {
    void auth.refresh()
  }, 60_000)
})

onUnmounted(() => {
  if (authRefreshTimer) clearInterval(authRefreshTimer)
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
        <span>{{ i18n.locale.value === 'zh' ? '控制面已连接' : 'Control plane connected' }}</span>
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
          <button
            class="btn btn-icon btn-default"
            type="button"
            :title="i18n.t('common.theme')"
            @click="theme.toggle()"
          >
            <AppIcon :name="theme.mode.value === 'dark' ? 'sun' : 'moon'" :size="16" />
          </button>
          <button class="btn btn-default btn-sm locale-btn" type="button" @click="i18n.toggle()">
            {{ i18n.locale.value === 'zh' ? 'EN' : '中文' }}
          </button>

          <span class="env-chip">
            <span class="env-dot" />
            {{ i18n.locale.value === 'zh' ? '服务运行中' : 'Running' }}
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
              {{ i18n.t('common.logout') }}
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
