export default defineNuxtPlugin(() => {
  if (import.meta.dev) return
  if (!import.meta.client || !('serviceWorker' in navigator)) return
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {
      // PWA support is an enhancement; ignore registration failures.
    })
  })
})
