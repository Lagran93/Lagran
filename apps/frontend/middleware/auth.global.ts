export default defineNuxtRouteMiddleware((to) => {
  // Skip on server during SSR for client-stored token
  if (import.meta.server) return

  const auth = useAuthStore()
  if (!auth.hydrated) auth.hydrate()

  const publicPaths = ['/login']
  if (publicPaths.includes(to.path)) {
    if (auth.isAuthenticated && to.path === '/login') {
      return navigateTo('/')
    }
    return
  }

  if (!auth.isAuthenticated) {
    return navigateTo('/login')
  }
})
