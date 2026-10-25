<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    modelValue: boolean
    title?: string
    width?: string
    loading?: boolean
  }>(),
  { title: '', width: '480px', loading: false },
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
    <Transition name="drawer">
      <div v-if="modelValue" class="drawer-mask" @click.self="close">
        <aside class="drawer-panel" :style="{ width }" role="dialog" aria-modal="true">
          <div class="drawer-head">
            <span class="drawer-title">{{ title }}</span>
            <button class="drawer-close" type="button" aria-label="关闭" @click="close">
              <AppIcon name="close" :size="16" />
            </button>
          </div>
          <div class="drawer-body">
            <slot />
          </div>
          <div class="drawer-foot">
            <slot name="footer">
              <button class="btn btn-default" type="button" :disabled="loading" @click="close">
                取消
              </button>
              <button class="btn btn-primary" type="button" :disabled="loading" @click="emit('confirm')">
                {{ loading ? '保存中…' : '保存' }}
              </button>
            </slot>
          </div>
        </aside>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.drawer-mask {
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: rgba(29, 33, 41, 0.45);
  display: flex;
  justify-content: flex-end;
}

.drawer-panel {
  height: 100%;
  max-width: 100%;
  background: var(--card);
  box-shadow: var(--shadow-lg);
  display: flex;
  flex-direction: column;
}

.drawer-head {
  display: flex;
  align-items: center;
  gap: 12px;
  height: 56px;
  padding: 0 20px;
  border-bottom: 1px solid var(--divider);
  flex: none;
}

.drawer-title {
  font-size: 16px;
  font-weight: 600;
}

.drawer-close {
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

.drawer-close:hover {
  background: #f2f3f5;
  color: var(--text);
}

.drawer-body {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}

.drawer-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 20px;
  border-top: 1px solid var(--divider);
  flex: none;
}

.drawer-enter-active,
.drawer-leave-active {
  transition: opacity 0.2s ease;
}

.drawer-enter-active .drawer-panel,
.drawer-leave-active .drawer-panel {
  transition: transform 0.2s ease;
}

.drawer-enter-from,
.drawer-leave-to {
  opacity: 0;
}

.drawer-enter-from .drawer-panel,
.drawer-leave-to .drawer-panel {
  transform: translateX(24px);
}
</style>
