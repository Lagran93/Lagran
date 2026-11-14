export default defineNuxtPlugin(() => {
  const auth = useAuthStore()
  auth.hydrate()
  auth.initCrossTab()
})
