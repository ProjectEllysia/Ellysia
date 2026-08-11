<template>
  <router-view />
  <AppToast />
</template>

<script setup>
// La sesión se restaura en main.js, antes de instalar el router: aquí era
// demasiado tarde, porque la primera navegación (y su guard) ya se había
// resuelto para cuando corría este `onMounted`.
import AppToast from '@/components/shared/AppToast.vue'
</script>
