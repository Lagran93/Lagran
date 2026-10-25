<script setup lang="ts">
const { items } = useToast()

function iconFor(type: string) {
  if (type === 'success') return 'check'
  if (type === 'error') return 'alert'
  return 'info'
}
</script>

<template>
  <Teleport to="body">
    <div class="toast-host">
      <TransitionGroup name="toast">
        <div v-for="t in items" :key="t.id" class="toast" :class="`toast-${t.type}`">
          <AppIcon :name="iconFor(t.type)" :size="16" class="toast-icon" />
          <span class="toast-text">{{ t.text }}</span>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<style scoped>
.toast-host {
  position: fixed;
  top: 18px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 2000;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  pointer-events: none;
}

.toast {
  display: flex;
  align-items: center;
  gap: 8px;
  max-width: 460px;
  padding: 9px 16px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  font-size: 14px;
  color: var(--text);
}

.toast-success .toast-icon {
  color: var(--success);
}

.toast-error .toast-icon {
  color: var(--danger);
}

.toast-info .toast-icon {
  color: var(--brand);
}

.toast-text {
  line-height: 1.5;
}

.toast-enter-active,
.toast-leave-active {
  transition: all 0.2s ease;
}

.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}

.toast-move {
  transition: transform 0.2s ease;
}
</style>
