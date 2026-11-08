const CACHE = 'lagran-shell-v2'
const SHELL = ['/', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png']

const OFFLINE_HTML = `<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lagran CDN · 离线</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f3f6fb;color:#0f172a;font:14px/1.7 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.box{max-width:420px;padding:32px;text-align:center}
h1{font-size:20px;margin:0 0 8px}
p{margin:0;color:#64748b}
</style></head>
<body><div class="box"><h1>控制台暂时不可用</h1><p>网络连接失败，请检查网络后刷新页面。</p></div></body>
</html>`

function offlineResponse() {
  return new Response(OFFLINE_HTML, {
    status: 503,
    statusText: 'Service Unavailable',
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE)
      await Promise.all(
        SHELL.map(async (url) => {
          try {
            const response = await fetch(url, { cache: 'reload' })
            if (response.ok) await cache.put(url, response)
          } catch {
            // Offline shell is best-effort; navigation has its own fallback.
          }
        }),
      )
      await self.skipWaiting()
    })(),
  )
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  )
})

async function safeMatch(request, options) {
  try {
    return await caches.match(request, options)
  } catch {
    return undefined
  }
}

async function handleNavigation(request) {
  try {
    const response = await fetch(request)
    if (response && response.ok) {
      const copy = response.clone()
      caches.open(CACHE).then((cache) => cache.put('/', copy)).catch(() => {})
    }
    return response || offlineResponse()
  } catch {
    const cached =
      (await safeMatch('/', { ignoreSearch: true })) ||
      (await safeMatch('/index.html')) ||
      (await safeMatch(request, { ignoreSearch: true }))
    return cached || offlineResponse()
  }
}

async function handleAsset(request) {
  const cached = await safeMatch(request)
  if (cached) return cached

  try {
    const response = await fetch(request)
    if (response && response.ok && response.type === 'basic') {
      const copy = response.clone()
      caches.open(CACHE).then((cache) => cache.put(request, copy)).catch(() => {})
    }
    return response || new Response('', { status: 504, statusText: 'Gateway Timeout' })
  } catch {
    return new Response('', { status: 504, statusText: 'Gateway Timeout' })
  }
}

self.addEventListener('fetch', (event) => {
  const request = event.request
  const url = new URL(request.url)
  if (
    request.method !== 'GET' ||
    url.origin !== self.location.origin ||
    url.pathname.startsWith('/api/') ||
    url.pathname === '/sw.js'
  ) {
    return
  }

  if (request.mode === 'navigate') {
    event.respondWith(handleNavigation(request))
    return
  }

  event.respondWith(handleAsset(request))
})
