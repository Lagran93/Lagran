type ThemeMode = 'light' | 'dark'

/** Persisted light/dark theme, applied to <html data-theme>. */
export function useTheme() {
  const mode = useState<ThemeMode>('lagran_theme', () => 'light')

  function apply(next: ThemeMode) {
    mode.value = next
    if (!import.meta.client) return
    document.documentElement.dataset.theme = next
    document.documentElement.style.colorScheme = next
    try {
      localStorage.setItem('lagran_theme', next)
    } catch {
      // storage can be unavailable in private mode
    }
    const meta = document.querySelector('meta[name="theme-color"]')
    if (meta) meta.setAttribute('content', next === 'dark' ? '#0b0e14' : '#1677ff')
  }

  function init() {
    if (!import.meta.client) return
    let saved: string | null = null
    try {
      saved = localStorage.getItem('lagran_theme')
    } catch {
      saved = null
    }
    const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches
    apply(saved === 'dark' || (!saved && prefersDark) ? 'dark' : 'light')
  }

  function toggle() {
    apply(mode.value === 'dark' ? 'light' : 'dark')
  }

  return { mode, init, apply, toggle }
}
