<template>
  <div class="auth-layout">
    <slot />
    <ToastHost />
  </div>
</template>

<style scoped>
.auth-layout {
  min-height: 100vh;
  background: linear-gradient(135deg, #eef4ff 0%, #f7f9fc 45%, #eef8ff 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px 16px;
}
</style>
