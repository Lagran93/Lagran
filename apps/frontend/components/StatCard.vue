<script setup lang="ts">
withDefaults(
  defineProps<{
    label: string
    value: string | number
    hint?: string
    icon?: string
    tone?: 'blue' | 'green' | 'orange' | 'red'
  }>(),
  { hint: '', icon: 'activity', tone: 'blue' },
)
</script>

<template>
  <div class="stat-card">
    <div class="stat-icon" :class="tone !== 'blue' ? tone : ''">
      <AppIcon :name="icon" :size="20" />
    </div>
    <div class="stat-body">
      <div class="stat-label">{{ label }}</div>
      <div class="stat-value">{{ value }}</div>
      <div v-if="hint" class="stat-hint">{{ hint }}</div>
    </div>
  </div>
</template>
