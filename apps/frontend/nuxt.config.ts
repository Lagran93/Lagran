// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2026-10-23',
  future: {
    compatibilityVersion: 4,
  },
  devtools: { enabled: process.env.NODE_ENV === 'development' },
  // The console authenticates with a JWT kept in localStorage, so there is no
  // meaningful server-rendered state; SPA mode avoids hydration mismatches
  // between the logged-out shell and the hydrated session.
  ssr: false,
  modules: ['@pinia/nuxt'],
  css: ['~/assets/css/main.css'],
  runtimeConfig: {
    public: {
      // In production the console is served by Caddy and calls the API on the
      // same origin (Caddy proxies /api/* to the control plane). During
      // `nuxt dev` we still point at the local control plane.
      // NUXT_PUBLIC_API_BASE can override this at build/generate time.
      apiBase:
        process.env.NUXT_PUBLIC_API_BASE ??
        (process.env.NODE_ENV === 'development' ? 'http://localhost:8080' : ''),
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
        { name: 'apple-mobile-web-app-capable', content: 'yes' },
        { name: 'apple-mobile-web-app-status-bar-style', content: 'black-translucent' },
      ],
      link: [
        { rel: 'manifest', href: '/manifest.webmanifest' },
        { rel: 'icon', type: 'image/svg+xml', href: '/icon.svg' },
        { rel: 'icon', type: 'image/png', sizes: '192x192', href: '/icon-192.png' },
        { rel: 'apple-touch-icon', href: '/icon-192.png' },
      ],
    },
  },
})
