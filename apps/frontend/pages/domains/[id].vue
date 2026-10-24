<template>
  <div>
    <p class="muted">域名详情：{{ id }}</p>
    <div class="card" style="margin-top:1rem;">
      <p>后续在此展示源站、SSL 证书、缓存规则绑定等配置。</p>
    </div>
  </div>
</template>

<script setup lang="ts">
const route = useRoute()
const id = route.params.id as string
</script>
