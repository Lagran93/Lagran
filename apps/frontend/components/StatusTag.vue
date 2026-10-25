<script setup lang="ts">
type Tone = 'success' | 'warning' | 'danger' | 'info' | 'neutral'

const props = withDefaults(
  defineProps<{
    tone?: Tone
    status?: string
    dot?: boolean
  }>(),
  { tone: undefined, status: '', dot: false },
)

const MAP: Record<string, Tone> = {
  active: 'success',
  online: 'success',
  healthy: 'success',
  ok: 'success',
  success: 'success',
  hit: 'success',
  enabled: 'success',
  disabled: 'neutral',
  offline: 'neutral',
  unknown: 'neutral',
  none: 'neutral',
  pending: 'warning',
  warning: 'warning',
  expired: 'warning',
  stale: 'warning',
  bypass: 'warning',
  unhealthy: 'danger',
  error: 'danger',
  failed: 'danger',
  miss: 'info',
  revalidated: 'info',
  info: 'info',
}

const resolved = computed<Tone>(() => {
  if (props.tone) return props.tone
  return MAP[(props.status || '').toLowerCase()] || 'neutral'
})
</script>

<template>
  <span class="tag" :class="`tag-${resolved}`">
    <span v-if="dot" class="dot" />
    <slot>{{ status }}</slot>
  </span>
</template>
