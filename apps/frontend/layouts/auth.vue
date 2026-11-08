<template>
  <div class="auth-layout">
    <div class="auth-orb auth-orb-a" />
    <div class="auth-orb auth-orb-b" />

    <button
      class="auth-theme-toggle"
      type="button"
      :title="theme.mode.value === 'dark' ? '切换到浅色主题' : '切换到深色主题'"
      :aria-label="theme.mode.value === 'dark' ? '切换到浅色主题' : '切换到深色主题'"
      @click="theme.toggle()"
    >
      <AppIcon :name="theme.mode.value === 'dark' ? 'sun' : 'moon'" :size="17" />
    </button>

    <slot />
    <ToastHost />
  </div>
</template>

<script setup lang="ts">
const theme = useTheme()
</script>

<style scoped>
.auth-layout {
  position: relative;
  min-height: 100dvh;
  background:
    radial-gradient(900px 520px at 8% 0%, rgba(37, 99, 235, 0.12), transparent 60%),
    radial-gradient(720px 480px at 100% 100%, rgba(34, 211, 238, 0.10), transparent 58%),
    var(--bg);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 28px 16px;
  overflow: hidden;
}

.auth-orb {
  position: absolute;
  border-radius: 50%;
  pointer-events: none;
  filter: blur(2px);
}

.auth-orb-a {
  width: 420px;
  height: 420px;
  left: -180px;
  top: -160px;
  background: radial-gradient(circle, rgba(37, 99, 235, 0.18), transparent 70%);
}

.auth-orb-b {
  width: 520px;
  height: 520px;
  right: -220px;
  bottom: -240px;
  background: radial-gradient(circle, rgba(34, 211, 238, 0.14), transparent 70%);
}

.auth-theme-toggle {
  position: fixed;
  top: 18px;
  right: 18px;
  z-index: 20;
  width: 38px;
  height: 38px;
  border-radius: 11px;
  border: 1px solid var(--border);
  background: var(--card);
  background: color-mix(in srgb, var(--card) 88%, transparent);
  color: var(--text-2);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  backdrop-filter: saturate(160%) blur(10px);
  box-shadow: var(--shadow-sm);
  transition: border-color 0.15s ease, color 0.15s ease, background 0.15s ease;
}

.auth-theme-toggle:hover {
  color: var(--brand);
  border-color: var(--brand);
}

:global(html[data-theme='dark']) .auth-layout {
  background:
    radial-gradient(900px 520px at 8% 0%, rgba(37, 99, 235, 0.18), transparent 60%),
    radial-gradient(720px 480px at 100% 100%, rgba(34, 211, 238, 0.08), transparent 58%),
    #080d15;
}

:global(html[data-theme='dark']) .auth-theme-toggle {
  background: rgba(16, 24, 36, 0.86);
  border-color: var(--border);
}

@media (max-width: 640px) {
  .auth-layout {
    padding: 64px 12px 24px;
    align-items: flex-start;
  }

  .auth-theme-toggle {
    top: 14px;
    right: 14px;
  }
}
</style>
