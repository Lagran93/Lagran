<template>
  <div class="monitor-layout">
    <header class="monitor-top">
      <div class="monitor-brand">
        <div class="brand-mark">L</div>
        <div>
          <div class="brand-name">Lagran CDN</div>
          <div class="brand-sub">LIVE OPERATIONS WALL</div>
        </div>
      </div>
      <div class="monitor-meta">
        <span class="live-dot" />
        <span>LIVE</span>
        <span class="monitor-clock">{{ clock }}</span>
        <NuxtLink to="/" class="btn btn-default btn-sm">返回控制台</NuxtLink>
      </div>
    </header>
    <main class="monitor-content">
      <slot />
    </main>
  </div>
</template>

<script setup lang="ts">
const clock = ref('')
let timer: ReturnType<typeof setInterval> | null = null

function tick() {
  clock.value = new Date().toLocaleString('zh-CN', { hour12: false })
}

onMounted(() => {
  tick()
  timer = setInterval(tick, 1000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.monitor-layout {
  min-height: 100vh;
  background:
    radial-gradient(1200px 600px at 15% -10%, rgba(22, 119, 255, 0.22), transparent 60%),
    radial-gradient(900px 500px at 90% 0%, rgba(0, 180, 170, 0.12), transparent 60%),
    #070a10;
  color: #e8edf5;
}

.monitor-top {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 28px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(7, 10, 16, 0.7);
  backdrop-filter: blur(10px);
}

.monitor-brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-name {
  font-size: 16px;
  font-weight: 600;
  letter-spacing: 0.04em;
}

.brand-sub {
  font-size: 10px;
  color: #6f819c;
  letter-spacing: 0.18em;
}

.monitor-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 12px;
  color: #8da0bb;
}

.live-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #3ddc84;
  box-shadow: 0 0 0 4px rgba(61, 220, 132, 0.12);
  animation: pulse 2s infinite;
}

.monitor-clock {
  font-family: var(--mono);
  color: #dbe6f5;
  letter-spacing: 0.04em;
}

.monitor-content {
  padding: 22px 28px 32px;
}

@keyframes pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.45;
  }
}

@media (max-width: 700px) {
  .monitor-top {
    padding: 0 14px;
    height: 56px;
  }
  .monitor-content {
    padding: 14px;
  }
  .monitor-meta {
    gap: 8px;
  }
}
</style>
