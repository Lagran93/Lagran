<script setup lang="ts">
withDefaults(
  defineProps<{
    title?: string
    text?: string
    icon?: string
  }>(),
  { title: '暂无数据', text: '', icon: 'info' },
)
</script>

<template>
  <div class="empty-state">
    <div class="empty-icon">
      <AppIcon :name="icon" :size="24" />
    </div>
    <div class="empty-title">{{ title }}</div>
    <div v-if="text" class="empty-text">{{ text }}</div>
    <div v-if="$slots.default" class="mt-8">
      <slot />
    </div>
  </div>
</template>
