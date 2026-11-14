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

/**
 * One session object instead of two independent keys.
 *
 * The previous layout (`lagran_token` + `lagran_user`) could be left in a
 * mixed state by two tabs: an old admin tab refreshing in the background could
 * write its token after a different account had just logged in, and a reload
 * then hydrated the administrator session. Keeping token and user in one
 * value makes the pair atomic, and `epoch` lets a tab notice that another tab
 * started a newer session instead of overwriting it.
 */
const SESSION_KEY = 'lagran_session_v2'
const LEGACY_TOKEN_KEY = 'lagran_token'
const LEGACY_USER_KEY = 'lagran_user'

interface StoredSession {
  token: string
  user: AuthUser
  epoch: string
}

function newEpoch(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`
}

/** JWT subject, used to reject a token/profile pair from different accounts. */
function tokenSubject(token: string): string | null {
  try {
    const part = token.split('.')[1]
    if (!part) return null
    const padded = part + '='.repeat((4 - (part.length % 4)) % 4)
    const payload = JSON.parse(atob(padded.replace(/-/g, '+').replace(/_/g, '/')))
    return typeof payload?.sub === 'string' ? payload.sub : null
  } catch {
    return null
  }
}

function readStored(): StoredSession | null {
  if (!import.meta.client) return null
  try {
    const raw = localStorage.getItem(SESSION_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<StoredSession>
    if (
      typeof parsed?.token === 'string' &&
      parsed.user &&
      typeof parsed.user === 'object' &&
      typeof parsed.user.id === 'string' &&
      typeof parsed.epoch === 'string'
    ) {
      return parsed as StoredSession
    }
  } catch {
    // A corrupted value must not leave a half-parsed session behind.
  }
  return null
}

function writeStored(session: StoredSession) {
  if (!import.meta.client) return
  localStorage.setItem(SESSION_KEY, JSON.stringify(session))
  // Legacy keys are never read again, but an old tab may still write them;
  // remove them so they cannot linger.
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  localStorage.removeItem(LEGACY_USER_KEY)
}

function removeStored() {
  if (!import.meta.client) return
  localStorage.removeItem(SESSION_KEY)
  localStorage.removeItem(LEGACY_TOKEN_KEY)
  localStorage.removeItem(LEGACY_USER_KEY)
}

let storageBound = false

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: null as string | null,
    user: null as AuthUser | null,
    epoch: null as string | null,
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
      if (this.hydrated && this.token) return
      const session = readStored()
      this.token = session?.token ?? null
      // Never render a cached profile whose id does not match the token. A
      // mixed pair used to show the administrator in the sidebar even though
      // every API call still carried the ordinary token.
      const sub = session?.token ? tokenSubject(session.token) : null
      this.user = session && (!sub || session.user.id === sub) ? session.user : null
      this.epoch = session?.epoch ?? null
      this.hydrated = true
    },

    /**
     * Keep tabs from fighting over the same localStorage slot.
     *
     * A tab that still holds an administrator token must not silently restore
     * it after another tab has logged in as a normal user. When the stored
     * epoch changes, this tab adopts the newer session (and reloads) instead of
     * letting its 60 s `refresh()` write the old token back.
     */
    initCrossTab() {
      if (!import.meta.client || storageBound) return
      storageBound = true
      window.addEventListener('storage', (event) => {
        if (event.key !== SESSION_KEY) return
        const next = readStored()
        if (!next) {
          this.clearLocal()
          const path = window.location.pathname
          if (path !== '/login' && path !== '/register') {
            window.location.replace('/login?expired=1')
          }
          return
        }
        if (next.epoch !== this.epoch) {
          this.token = next.token
          this.user = next.user
          this.epoch = next.epoch
          window.location.reload()
        }
      })
    },

    setSession(token: string, user: AuthUser, epoch?: string) {
      const nextEpoch = epoch ?? this.epoch ?? newEpoch()
      this.token = token
      this.user = user
      this.epoch = nextEpoch
      writeStored({ token, user, epoch: nextEpoch })
    },

    /** Refresh the profile (and therefore the role) from the API. */
    async refresh() {
      const token = this.token
      if (!token) return

      // A login/logout in another tab wins over this tab's timer.
      const stored = readStored()
      if (!stored || stored.token !== token || stored.epoch !== this.epoch) {
        this.clearLocal()
        return
      }

      try {
        const config = useRuntimeConfig()
        const me = await $fetch<AuthUser>(`${config.public.apiBase}/api/v1/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        })

        // Re-check after the await: the user may have logged out or another
        // tab may have started a new session while the request was in flight.
        const current = readStored()
        if (!current || current.token !== token || current.epoch !== this.epoch) {
          this.clearLocal()
          return
        }
        const sub = tokenSubject(token)
        if (sub && me.id !== sub) {
          // Never adopt a profile that does not belong to this token.
          this.clearLocal()
          return
        }
        this.setSession(token, me)
      } catch {
        // Token expired/invalid. Clear it immediately so route guards and the
        // API client do not keep using a dead JWT.
        this.clearLocal()
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
      const token = this.token
      // Clear the UI first so in-flight 401 handlers do not recurse into
      // another logout while the revocation request is on its way.
      this.clearLocal()
      if (!token || !import.meta.client) return
      try {
        const config = useRuntimeConfig()
        // JWTs are stateless; only the server can revoke the old credential.
        // `keepalive` lets the request finish even though the caller navigates
        // to /login immediately. Failure is non-fatal: the token still expires.
        void $fetch(`${config.public.apiBase}/api/v1/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
          keepalive: true,
        }).catch(() => {})
      } catch {
        // No Nuxt context (e.g. unit test); local logout is still complete.
      }
    },

    clearLocal() {
      this.token = null
      this.user = null
      this.epoch = null
      removeStored()
    },
  },
})
