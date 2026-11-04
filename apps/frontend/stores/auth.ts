import { defineStore } from 'pinia'

export interface AuthUser {
  id: string
  email: string
  name: string
  role?: 'admin' | 'user' | string
  permissions?: string[]
  is_active?: boolean
  created_at?: string
  last_login_at?: string | null
}

const TOKEN_KEY = 'lagran_token'
const USER_KEY = 'lagran_user'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: null as string | null,
    user: null as AuthUser | null,
    hydrated: false,
  }),
  getters: {
    isAuthenticated: (s) => !!s.token,
    isAdmin: (s) => s.user?.role === 'admin',
    can: (s) => (permission: string) => {
      if (s.user?.role === 'admin') return true
      const permissions = s.user?.permissions || []
      // No groups keeps the legacy project-role behaviour.
      if (!permissions.length) return true
      return permissions.some(
        (p) => p === '*' || p === permission || (p.endsWith(':*') && permission.startsWith(p.slice(0, -1))),
      )
    },
  },
  actions: {
    hydrate() {
      if (import.meta.client) {
        this.token = localStorage.getItem(TOKEN_KEY)
        const raw = localStorage.getItem(USER_KEY)
        this.user = raw ? JSON.parse(raw) : null
      }
      this.hydrated = true
    },
    setSession(token: string, user: AuthUser) {
      this.token = token
      this.user = user
      if (import.meta.client) {
        localStorage.setItem(TOKEN_KEY, token)
        localStorage.setItem(USER_KEY, JSON.stringify(user))
      }
    },
    /** Refresh the profile (and therefore the role) from the API. */
    async refresh() {
      if (!this.token) return
      try {
        const config = useRuntimeConfig()
        const me = await $fetch<AuthUser>(`${config.public.apiBase}/api/v1/auth/me`, {
          headers: { Authorization: `Bearer ${this.token}` },
        })
        this.setSession(this.token, me)
      } catch {
        // Token expired/invalid. Clear it immediately so route guards and the
        // API client do not keep using a dead JWT.
        this.logout()
        if (
          import.meta.client &&
          window.location.pathname !== '/login' &&
          window.location.pathname !== '/register'
        ) {
          window.location.replace('/login?expired=1')
        }
      }
    },
    logout() {
      this.token = null
      this.user = null
      if (import.meta.client) {
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(USER_KEY)
      }
    },
  },
})
