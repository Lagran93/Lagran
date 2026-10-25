// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2026-10-23',
  future: {
    compatibilityVersion: 4,
  },
  devtools: { enabled: true },
  // The console authenticates with a JWT kept in localStorage, so there is no
  // meaningful server-rendered state; SPA mode avoids hydration mismatches
  // between the logged-out shell and the hydrated session.
  ssr: false,
  modules: ['@pinia/nuxt'],
  css: ['~/assets/css/main.css'],
  runtimeConfig: {
    public: {
      apiBase: process.env.NUXT_PUBLIC_API_BASE || 'http://localhost:8080',
    },
  },
  app: {
    head: {
      htmlAttrs: { lang: 'zh-CN' },
      title: 'Lagran CDN 控制台',
      meta: [
        { charset: 'utf-8' },
        { name: 'viewport', content: 'width=device-width, initial-scale=1' },
        { name: 'description', content: 'Lagran CDN 管理控制台：域名接入、缓存策略、边缘节点与流量监控' },
        { name: 'theme-color', content: '#1677ff' },
      ],
    },
  },
})
