<template>
  <div class="app-root">
    <NuxtLayout>
      <NuxtPage :transition="{ name: 'page-fade', mode: 'out-in' }" />
    </NuxtLayout>
  </div>
</template>

<style>
.app-root {
  min-height: 100vh;
  animation: app-reveal 0.32s ease-out both;
}

@keyframes app-reveal {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}

@media (prefers-reduced-motion: reduce) {
  .app-root {
    animation: none;
  }
}
</style>
