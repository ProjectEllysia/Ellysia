<template>
  <nav class="topbar">
    <div class="topbar-left">
      <router-link :to="backTo" class="back-link">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M19 12H5M12 5l-7 7 7 7"/>
        </svg>
        {{ backLabel }}
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
      <AccountMenu />
    </div>
  </nav>
</template>

<script setup>
/**
 * Barra de las vistas de herramienta.
 *
 * Antes solo llevaba la píldora de sesión y un botón de salir: desde dentro de
 * Themis o Acheron no había forma de llegar al perfil, a la configuración ni,
 * ahora, al plan o a la organización. El `AccountMenu` compartido resuelve eso
 * sin duplicar nada — es el mismo componente que monta la portada.
 */
import { useAuthStore } from '@/stores/authStore'
import AccountMenu from '@/components/shared/AccountMenu.vue'

defineProps({
  title: { type: String, required: true },
  badge: { type: String, default: '' },
  backTo: { type: String, default: '/' },
  backLabel: { type: String, default: 'Inicio' },
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
