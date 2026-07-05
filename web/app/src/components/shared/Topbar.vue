<template>
  <nav class="topbar">
    <div class="topbar-left">
      <router-link to="/" class="back-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M19 12H5M12 5l-7 7 7 7"/>
        </svg>
        Inicio
      </router-link>
      <span class="topbar-sep">/</span>
      <span class="topbar-title">{{ title }}</span>
      <span v-if="badge" class="topbar-badge">{{ badge }}</span>
    </div>
    <div class="topbar-right">
      <div class="session-pill">
        <div class="session-dot"></div>
        <span>{{ auth.username() }}</span>
      </div>
      <button class="btn-logout" @click="auth.logout">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16 17 21 12 16 7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
        <span>Salir</span>
      </button>
    </div>
  </nav>
</template>

<script setup>
import { useAuthStore } from '@/stores/authStore'

defineProps({
  title: { type: String, required: true },
  badge: { type: String, default: '' },
})

const auth = useAuthStore()
</script>

<style scoped>
/* Forzar color dorado de la app, ignorando overrides de data-module */
.topbar-title {
  color: #d4a04a;
}
.topbar-badge {
  background: rgba(212,160,74,0.10);
  color: #d4a04a;
  border-color: rgba(212,160,74,0.22);
}
</style>
