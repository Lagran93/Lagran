export function useApi() {
  const config = useRuntimeConfig()
  const base = config.public.apiBase as string
  const auth = useAuthStore()

  let redirecting = false

  function headers(extra?: HeadersInit): HeadersInit {
    const h: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (auth.token) {
      h['Authorization'] = `Bearer ${auth.token}`
    }
    return { ...h, ...(extra as Record<string, string>) }
  }

  function handleUnauthorized(path: string, error: any) {
    const status = error?.response?.status ?? error?.status
    if (status !== 401) return
    // A wrong password on the login form is a normal 401, not an expired
    // session. Never redirect from the auth endpoints themselves.
    if (path.startsWith('/api/v1/auth/login') || path.startsWith('/api/v1/auth/captcha')) {
      return
    }
    if (!auth.token || redirecting) return

    redirecting = true
    auth.logout()
    if (import.meta.client) {
      const current = window.location.pathname
      if (current !== '/login' && current !== '/register') {
        window.location.replace('/login?expired=1')
      }
    }
  }

  async function request<T>(path: string, options: Record<string, any> = {}): Promise<T> {
    try {
      return await $fetch<T>(`${base}${path}`, options)
    } catch (error) {
      handleUnauthorized(path, error)
      throw error
    }
  }

  async function get<T>(path: string): Promise<T> {
    return await request<T>(path, { headers: headers() })
  }

  async function post<T>(path: string, body?: unknown): Promise<T> {
    return await request<T>(path, {
      method: 'POST',
      headers: headers(),
      body,
    })
  }

  async function put<T>(path: string, body?: unknown): Promise<T> {
    return await request<T>(path, {
      method: 'PUT',
      headers: headers(),
      body,
    })
  }

  async function del<T>(path: string): Promise<T> {
    return await request<T>(path, {
      method: 'DELETE',
      headers: headers(),
    })
  }

  return { base, get, post, put, del, headers }
}
