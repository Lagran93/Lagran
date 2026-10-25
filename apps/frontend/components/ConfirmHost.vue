<script setup lang="ts">
const { state, settle } = useConfirm()
</script>

<template>
  <Teleport to="body">
    <Transition name="confirm">
      <div v-if="state.open" class="confirm-mask" @click.self="settle(false)">
        <div class="confirm-panel" role="alertdialog" aria-modal="true">
          <div class="confirm-head">
            <span class="confirm-icon" :class="state.danger ? 'danger' : ''">
              <AppIcon :name="state.danger ? 'alert' : 'info'" :size="18" />
            </span>
            <span class="confirm-title">{{ state.title }}</span>
          </div>
          <div v-if="state.message" class="confirm-body">{{ state.message }}</div>
          <div class="confirm-foot">
            <button class="btn btn-default" type="button" @click="settle(false)">
              {{ state.cancelText }}
            </button>
            <button
              class="btn"
              :class="state.danger ? 'btn-danger' : 'btn-primary'"
              type="button"
              @click="settle(true)"
            >
              {{ state.confirmText }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.confirm-mask {
  position: fixed;
  inset: 0;
  z-index: 1100;
  background: rgba(29, 33, 41, 0.45);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 24vh 16px 24px;
}

.confirm-panel {
  width: 420px;
  max-width: 100%;
  background: var(--card);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  padding: 20px;
}

.confirm-head {
  display: flex;
  align-items: center;
  gap: 10px;
}

.confirm-icon {
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: var(--brand-bg);
  color: var(--brand);
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.confirm-icon.danger {
  background: var(--danger-bg);
  color: var(--danger);
}

.confirm-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
}

.confirm-body {
  margin: 12px 0 0 40px;
  font-size: 14px;
  color: var(--text-2);
  line-height: 1.7;
}

.confirm-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 20px;
}

.confirm-enter-active,
.confirm-leave-active {
  transition: opacity 0.18s ease;
}

.confirm-enter-from,
.confirm-leave-to {
  opacity: 0;
}
</style>
