export function useApi() {
  const config = useRuntimeConfig()
  const base = config.public.apiBase as string
  const auth = useAuthStore()

  function headers(extra?: HeadersInit): HeadersInit {
    const h: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (auth.token) {
      h['Authorization'] = `Bearer ${auth.token}`
    }
    return { ...h, ...(extra as Record<string, string>) }
  }

  async function get<T>(path: string): Promise<T> {
    return await $fetch<T>(`${base}${path}`, { headers: headers() })
  }

  async function post<T>(path: string, body?: unknown): Promise<T> {
    return await $fetch<T>(`${base}${path}`, {
      method: 'POST',
      headers: headers(),
      body,
    })
  }

  async function put<T>(path: string, body?: unknown): Promise<T> {
    return await $fetch<T>(`${base}${path}`, {
      method: 'PUT',
      headers: headers(),
      body,
    })
  }

  async function del<T>(path: string): Promise<T> {
    return await $fetch<T>(`${base}${path}`, {
      method: 'DELETE',
      headers: headers(),
    })
  }

  return { base, get, post, put, del, headers }
}
