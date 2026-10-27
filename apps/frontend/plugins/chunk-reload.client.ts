export default defineNuxtPlugin(() => {
  // A deploy replaces hashed chunks. Mobile browsers can keep an old HTML shell
  // alive in bfcache, so a dynamic import may reference a chunk that no longer
  // exists and Nuxt renders "500 importing a module script failed". Reload once
  // to fetch the new HTML shell; the edge/backend sends HTML with no-cache.
  const key = 'lagran-chunk-reload'
  const isChunkError = (value: unknown) => {
    const text = String(value ?? '').toLowerCase()
    return (
      text.includes('dynamically imported module') ||
      text.includes('importing a module script failed') ||
      text.includes('error loading dynamically imported module')
    )
  }
  const reloadOnce = () => {
    try {
      if (sessionStorage.getItem(key)) return
      sessionStorage.setItem(key, '1')
      window.setTimeout(() => sessionStorage.removeItem(key), 10_000)
    } catch {
      // sessionStorage can be unavailable in private/embedded browsers.
    }
    window.location.reload()
  }

  useRouter().onError((error) => {
    if (isChunkError(error)) reloadOnce()
  })
  window.addEventListener('unhandledrejection', (event) => {
    if (isChunkError(event.reason)) reloadOnce()
  })
  window.addEventListener('error', (event) => {
    if (event.target instanceof HTMLScriptElement && isChunkError(event.message)) {
      reloadOnce()
    }
  })
})
