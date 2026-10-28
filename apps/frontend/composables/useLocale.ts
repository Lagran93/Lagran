type Locale = 'zh' | 'en'

const DICT: Record<string, { zh: string; en: string }> = {
  'group.overview': { zh: '概览', en: 'Overview' },
  'group.edge': { zh: '加速服务', en: 'Edge Services' },
  'group.observe': { zh: '观测', en: 'Observability' },
  'group.system': { zh: '系统', en: 'System' },
  'nav.dashboard': { zh: '仪表盘', en: 'Dashboard' },
  'nav.domains': { zh: '域名管理', en: 'Domains' },
  'nav.onboard': { zh: '接入向导', en: 'Onboarding' },
  'nav.rules': { zh: '缓存规则', en: 'Cache Rules' },
  'nav.cacheDebug': { zh: '缓存诊断', en: 'Cache Debug' },
  'nav.waf': { zh: 'WAF 防护', en: 'WAF' },
  'nav.certs': { zh: '证书管理', en: 'Certificates' },
  'nav.purge': { zh: '缓存刷新', en: 'Purge' },
  'nav.prefetch': { zh: '缓存预热', en: 'Prefetch' },
  'nav.releases': { zh: '配置发布', en: 'Releases' },
  'nav.nodes': { zh: '边缘节点', en: 'Edge Nodes' },
  'nav.stats': { zh: '统计分析', en: 'Analytics' },
  'nav.monitor': { zh: '大屏监控', en: 'Monitor Wall' },
  'nav.alerts': { zh: '告警中心', en: 'Alerts' },
  'nav.logs': { zh: '访问日志', en: 'Access Logs' },
  'nav.audit': { zh: '操作审计', en: 'Audit Log' },
  'nav.projects': { zh: '项目管理', en: 'Projects' },
  'nav.users': { zh: '用户管理', en: 'Users' },
  'nav.settings': { zh: '系统设置', en: 'Settings' },
  'nav.config': { zh: '配置发布', en: 'Config Releases' },
  'common.refresh': { zh: '刷新', en: 'Refresh' },
  'common.export': { zh: '导出 CSV', en: 'Export CSV' },
  'common.logout': { zh: '退出登录', en: 'Sign out' },
  'common.profile': { zh: '个人设置', en: 'Profile' },
  'common.language': { zh: 'English', en: '简体中文' },
  'common.theme': { zh: '切换深色模式', en: 'Toggle dark mode' },
  'common.online': { zh: '在线', en: 'Online' },
  'common.offline': { zh: '离线', en: 'Offline' },
  'diag.title': { zh: '域名诊断', en: 'Domain Diagnostics' },
  'diag.run': { zh: '开始诊断', en: 'Run diagnostics' },
  'diag.dns': { zh: 'DNS 是否正确', en: 'DNS' },
  'diag.cert': { zh: '证书是否有效', en: 'Certificate' },
  'diag.origin': { zh: '回源是否可达', en: 'Origin reachability' },
  'diag.cache': { zh: '缓存是否命中', en: 'Cache status' },
}

/** Small shell-level i18n dictionary (navigation and global controls). */
export function useLocale() {
  const locale = useState<Locale>('lagran_locale', () => 'zh')

  function t(key: string): string {
    const entry = DICT[key]
    if (!entry) return key
    return entry[locale.value]
  }

  function apply(next: Locale) {
    locale.value = next
    if (!import.meta.client) return
    document.documentElement.lang = next === 'zh' ? 'zh-CN' : 'en'
    try {
      localStorage.setItem('lagran_locale', next)
    } catch {
      // ignore
    }
  }

  function init() {
    if (!import.meta.client) return
    let saved: string | null = null
    try {
      saved = localStorage.getItem('lagran_locale')
    } catch {
      saved = null
    }
    apply(saved === 'en' ? 'en' : 'zh')
  }

  function toggle() {
    apply(locale.value === 'zh' ? 'en' : 'zh')
  }

  return { locale, t, apply, init, toggle }
}
