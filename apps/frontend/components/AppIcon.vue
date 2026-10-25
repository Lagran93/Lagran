<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    name: string
    size?: number
    strokeWidth?: number
  }>(),
  { size: 18, strokeWidth: 1.8 },
)

const ICONS: Record<string, string[]> = {
  dashboard: ['M3 3h7v7H3z', 'M14 3h7v7h-7z', 'M14 14h7v7h-7z', 'M3 14h7v7H3z'],
  project: ['M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'],
  domain: [
    'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20',
    'M2 12h20',
    'M12 2c3 3.5 3 16.5 0 20',
    'M12 2c-3 3.5-3 16.5 0 20',
  ],
  rules: ['M4 6h16', 'M4 12h16', 'M4 18h9', 'M17 15v6', 'M14 18h6'],
  cert: [
    'M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z',
    'M9.5 12l1.8 1.8 3.7-3.8',
  ],
  purge: ['M21 12a9 9 0 1 1-2.64-6.36', 'M21 3v6h-6'],
  node: ['M4 4h16v6H4z', 'M4 14h16v6H4z', 'M8 7h.01', 'M8 17h.01'],
  stats: ['M4 20V10', 'M10 20V4', 'M16 20v-7', 'M22 20H2'],
  logs: [
    'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z',
    'M14 3v6h6',
    'M8 13h8',
    'M8 17h5',
  ],
  audit: [
    'M9 4h6v3H9z',
    'M8 4H6a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-2',
    'M9 12h6',
    'M9 16h4',
  ],
  settings: [
    'M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7',
    'M12 2v3',
    'M12 19v3',
    'M2 12h3',
    'M19 12h3',
    'M4.9 4.9l2.1 2.1',
    'M17 17l2.1 2.1',
    'M19.1 4.9L17 7',
    'M7 17l-2.1 2.1',
  ],
  plus: ['M12 5v14', 'M5 12h14'],
  search: ['M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16', 'M21 21l-4.3-4.3'],
  refresh: ['M21 12a9 9 0 1 1-2.64-6.36', 'M21 3v6h-6'],
  close: ['M18 6 6 18', 'M6 6l12 12'],
  check: ['M20 6 9 17l-5-5'],
  alert: ['M12 3 2 21h20z', 'M12 9v6', 'M12 18h.01'],
  info: ['M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20', 'M12 11v6', 'M12 7h.01'],
  'chevron-down': ['m6 9 6 6 6-6'],
  'chevron-left': ['m15 18-6-6 6-6'],
  'chevron-right': ['m9 18 6-6-6-6'],
  trash: ['M3 6h18', 'M8 6V4h8v2', 'M6 6l1 15h10l1-15', 'M10 11v6', 'M14 11v6'],
  edit: ['M12 20h9', 'M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z'],
  users: [
    'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2',
    'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8',
    'M22 21v-2a4 4 0 0 0-3-3.87',
    'M16 3.13a4 4 0 0 1 0 7.75',
  ],
  upload: ['M12 16V4', 'm7 9 5-5 5 5', 'M4 20h16'],
  copy: [
    'M9 9h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V11a2 2 0 0 1 2-2',
    'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
  ],
  external: [
    'M14 3h7v7',
    'M21 3 10 14',
    'M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5',
  ],
  clock: ['M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20', 'M12 7v5l3 2'],
  activity: ['M3 12h4l3-8 4 16 3-8h4'],
  menu: ['M4 6h16', 'M4 12h16', 'M4 18h16'],
  logout: [
    'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4',
    'm16 17 5-5-5-5',
    'M21 12H9',
  ],
  eye: [
    'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12',
    'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6',
  ],
  'eye-off': [
    'M3 3l18 18',
    'M10.6 10.6a3 3 0 0 0 4.2 4.2',
    'M9.9 5.2A10.9 10.9 0 0 1 12 5c6.5 0 10 7 10 7a17.8 17.8 0 0 1-2.4 3.3',
    'M6.6 6.6C3.7 8.5 2 12 2 12s3.5 7 10 7c2 0 3.7-.6 5.2-1.6',
  ],
  'arrow-left': ['M19 12H5', 'm12 19-7-7 7-7'],
  zap: ['M13 2 3 14h7l-1 8 10-12h-7z'],
  shield: ['M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z'],
  filter: ['M3 5h18', 'M6 12h12', 'M10 19h4'],
  sort: ['M8 9l4-4 4 4', 'M16 15l-4 4-4-4'],
  globe: ['M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20', 'M2 12h20'],
}

const paths = computed(() => ICONS[props.name] || ICONS.info)
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    :stroke-width="strokeWidth"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    class="app-icon"
  >
    <path v-for="(d, i) in paths" :key="i" :d="d" />
  </svg>
</template>

<style scoped>
.app-icon {
  display: block;
  flex: none;
}
</style>
