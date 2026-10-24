<template>
  <div>
    <div class="card">
      <h3 style="margin-top:0;">系统设置</h3>
      <p class="muted">API 地址、主题、通知等配置将在此管理。</p>
      <div style="margin-top:1.25rem;">
        <label class="muted" style="display:block;margin-bottom:0.35rem;font-size:0.85rem;">
          控制端 API Base
        </label>
        <code style="background:#0f172a;padding:0.5rem 0.75rem;border-radius:6px;display:inline-block;">
          {{ apiBase }}
        </code>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
const config = useRuntimeConfig()
const apiBase = config.public.apiBase as string
</script>
