<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    modelValue: boolean
    title?: string
    width?: string
    confirmText?: string
    cancelText?: string
    loading?: boolean
    danger?: boolean
    hideFooter?: boolean
    closeOnOverlay?: boolean
  }>(),
  {
    title: '',
    width: '520px',
    confirmText: '确定',
    cancelText: '取消',
    loading: false,
    danger: false,
    hideFooter: false,
    closeOnOverlay: false,
  },
)

const emit = defineEmits<{
  'update:modelValue': [boolean]
  confirm: []
}>()

function close() {
  if (props.loading) return
  emit('update:modelValue', false)
}
</script>

<template>
  <Teleport to="body">
    <Transition name="modal-fade">
      <div v-if="modelValue" class="modal-mask" @click.self="closeOnOverlay && close()">
        <div class="modal-panel" :style="{ width }" role="dialog" aria-modal="true">
          <div class="modal-head">
            <span class="modal-title">{{ title }}</span>
            <button class="modal-close" type="button" aria-label="关闭" @click="close">
              <AppIcon name="close" :size="16" />
            </button>
          </div>
          <div class="modal-body">
            <slot />
          </div>
          <div v-if="!hideFooter" class="modal-foot">
            <slot name="footer">
              <button class="btn btn-default" type="button" :disabled="loading" @click="close">
                {{ cancelText }}
              </button>
              <button
                class="btn"
                :class="danger ? 'btn-danger' : 'btn-primary'"
                type="button"
                :disabled="loading"
                @click="emit('confirm')"
              >
                {{ loading ? '处理中…' : confirmText }}
              </button>
            </slot>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.modal-mask {
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: rgba(29, 33, 41, 0.45);
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding: 10vh 16px 24px;
  overflow-y: auto;
  overscroll-behavior: contain;
}

.modal-panel {
  max-width: 100%;
  min-height: 0;
  background: var(--card);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  display: flex;
  flex-direction: column;
  max-height: 84vh;
}

.modal-head {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: none;
  padding: 16px 20px;
  border-bottom: 1px solid var(--divider);
}

.modal-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
}

.modal-close {
  margin-left: auto;
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  border-radius: var(--radius);
  color: var(--text-3);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: #f2f3f5;
  color: var(--text);
}

.modal-body {
  min-height: 0;
  padding: 20px;
  overflow-y: auto;
  overscroll-behavior: contain;
  -webkit-overflow-scrolling: touch;
}

.modal-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  flex: none;
  padding: 12px 20px 16px;
  border-top: 1px solid var(--divider);
}

.modal-fade-enter-active,
.modal-fade-leave-active {
  transition: opacity 0.18s ease;
}

.modal-fade-enter-active .modal-panel,
.modal-fade-leave-active .modal-panel {
  transition: transform 0.18s ease;
}

.modal-fade-enter-from,
.modal-fade-leave-to {
  opacity: 0;
}

.modal-fade-enter-from .modal-panel,
.modal-fade-leave-to .modal-panel {
  transform: translateY(-8px) scale(0.98);
}

@media (max-width: 640px) {
  .modal-mask {
    align-items: flex-start;
    padding:
      calc(10px + env(safe-area-inset-top))
      8px
      calc(10px + env(safe-area-inset-bottom));
  }

  .modal-panel {
    width: 100% !important;
    max-height: calc(
      100dvh - 20px - env(safe-area-inset-top) - env(safe-area-inset-bottom)
    );
    border-radius: 14px;
  }

  .modal-head {
    padding: 14px 16px;
  }

  .modal-title {
    font-size: 16px;
  }

  .modal-close {
    width: 34px;
    height: 34px;
  }

  .modal-body {
    padding: 16px;
  }

  .modal-foot {
    padding: 12px 16px 14px;
  }

  .modal-foot :deep(.btn) {
    flex: 1;
    min-height: 42px;
  }
}

@media (max-width: 380px) {
  .modal-body {
    padding: 12px;
  }

  .modal-head {
    padding: 12px 14px;
  }

  .modal-foot {
    padding: 10px 12px 12px;
  }
}
</style>
