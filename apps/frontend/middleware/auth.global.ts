/**
 * Route guard. The console is a static SPA, so this is UX only: every API call
 * is still authorised by the control plane. It must nevertheless mirror the
 * backend's module permissions, otherwise a user sees pages whose data calls all
 * fail with 403.
 */
const ROUTE_PERMISSIONS: Array<[string, string]> = [
  ['/users', 'user:read'],
  ['/groups', 'user:read'],
  ['/nodes', 'node:read'],
  ['/audit', 'audit:read'],
  ['/settings', 'settings:read'],
  ['/config-releases', 'config:read'],
  ['/access-logs', 'analytics:read'],
  ['/login-logs', 'analytics:read'],
  ['/stats', 'analytics:read'],
  ['/monitor', 'analytics:read'],
  ['/waf', 'waf:read'],
  ['/alerts', 'alert:read'],
  ['/rules', 'cache:read'],
  ['/cache-debug', 'cache:read'],
  ['/prefetch', 'prefetch:read'],
  ['/purge', 'cache:write'],
  ['/certs', 'cert:read'],
  ['/domains', 'domain:read'],
  ['/projects', 'project:read'],
]

export default defineNuxtRouteMiddleware((to) => {
  // Skip on server during SSR for client-stored token
  if (import.meta.server) return

  const auth = useAuthStore()
  if (!auth.hydrated) auth.hydrate()

  const publicPaths = ['/login', '/register']
  if (publicPaths.includes(to.path)) {
    if (auth.isAuthenticated) {
      return navigateTo('/')
    }
    return
  }

  if (!auth.isAuthenticated) {
    return navigateTo('/login')
  }

  const required = ROUTE_PERMISSIONS.find(
    ([prefix]) => to.path === prefix || to.path.startsWith(`${prefix}/`),
  )
  if (required && !auth.can(required[1])) {
    return navigateTo('/')
  }
})
