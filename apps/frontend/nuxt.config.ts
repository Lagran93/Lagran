// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2026-10-23',
  future: {
    compatibilityVersion: 4,
  },
  devtools: { enabled: true },
  modules: ['@pinia/nuxt'],
  css: [],
  runtimeConfig: {
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE || 'http://localhost:8080',
    },
  },
  app: {
    head: {
      title: 'Lagran CDN',
      meta: [
        { name: 'description', content: 'Lagran CDN Management Console' },
      ],
    },
  },
})
