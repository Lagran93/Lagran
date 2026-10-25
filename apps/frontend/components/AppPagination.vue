<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    total: number
    page: number
    pageSize?: number
    unit?: string
  }>(),
  { pageSize: 10, unit: '条' },
)

const emit = defineEmits<{
  'update:page': [number]
}>()

const totalPages = computed(() => Math.max(1, Math.ceil(props.total / props.pageSize)))

const items = computed<(number | string)[]>(() => {
  const total = totalPages.value
  const current = props.page
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1)
  }
  const result: (number | string)[] = [1]
  const start = Math.max(2, current - 1)
  const end = Math.min(total - 1, current + 1)
  if (start > 2) result.push('left-ellipsis')
  for (let i = start; i <= end; i += 1) result.push(i)
  if (end < total - 1) result.push('right-ellipsis')
  result.push(total)
  return result
})

function go(page: number) {
  const next = Math.min(totalPages.value, Math.max(1, page))
  if (next !== props.page) emit('update:page', next)
}
</script>

<template>
  <div class="pager">
    <span class="pager-info">共 {{ total }} {{ unit }}</span>
    <button class="pager-btn" type="button" :disabled="page <= 1" @click="go(page - 1)">
      <AppIcon name="chevron-left" :size="14" />
    </button>
    <template v-for="item in items" :key="item">
      <span v-if="typeof item === 'string'" class="pager-ellipsis">…</span>
      <button
        v-else
        class="pager-btn"
        :class="{ active: item === page }"
        type="button"
        @click="go(item)"
      >
        {{ item }}
      </button>
    </template>
    <button class="pager-btn" type="button" :disabled="page >= totalPages" @click="go(page + 1)">
      <AppIcon name="chevron-right" :size="14" />
    </button>
  </div>
</template>

<style scoped>
.pager {
  display: flex;
  align-items: center;
  gap: 4px;
}

.pager-info {
  margin-right: 8px;
  color: var(--text-3);
  font-size: 13px;
}

.pager-btn {
  min-width: 28px;
  height: 28px;
  padding: 0 6px;
  border: 1px solid var(--border);
  background: var(--card);
  border-radius: var(--radius-sm);
  color: var(--text-2);
  font-size: 13px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.pager-btn:hover:not(:disabled) {
  color: var(--brand);
  border-color: var(--brand);
}

.pager-btn.active {
  background: var(--brand);
  border-color: var(--brand);
  color: #fff;
}

.pager-btn:disabled {
  color: var(--text-4);
  cursor: not-allowed;
}

.pager-ellipsis {
  color: var(--text-3);
  padding: 0 2px;
}
</style>
