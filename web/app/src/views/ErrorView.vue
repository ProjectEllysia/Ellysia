<template>
  <InfoPage :eyebrow="`Error ${error.code}`" :title="error.entry.title">
    <p v-for="(paragraph, index) in error.entry.paragraphs" :key="index">{{ paragraph }}</p>

    <p v-if="error.entry.reload" class="note">
      <button type="button" class="retry" @click="reload">Volver a intentar</button>
    </p>

    <p v-if="error.entry.links.length" class="note">
      Desde aquí puedes
      <template v-for="(link, index) in error.entry.links" :key="link.to">
        <template v-if="index > 0">{{ index === error.entry.links.length - 1 ? ' o ' : ', ' }}</template>
        <router-link :to="link.to">{{ link.label }}</router-link>
      </template>.
    </p>
  </InfoPage>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import InfoPage from '@/components/shared/InfoPage.vue'
import { resolveError } from '@/views/errorCatalog'

const route = useRoute()

/**
 * Vista genérica de errores: UNA vista para todos los códigos. Resuelve la
 * entrada del catálogo (`views/errorCatalog.js`) y pinta su copia, sus
 * enlaces y, si la entrada lo pide, el botón de reintento. Añadir un error
 * nuevo es añadir una entrada al catálogo, no crear otra vista.
 *
 * Código de error: el de la ruta `/error/:code` si la hay (la usan los guards,
 * el `onError` del router y el `handle_errors` del Caddyfile), o 404 cuando
 * la URL simplemente no existe y ha caído en el comodín del router.
 */
const error = computed(() => resolveError(route.params.code ?? route.meta.errorCode ?? 404))

/** Botón de "volver a intentar" de las entradas que lo declaran. */
function reload() {
  window.location.reload()
}
</script>

<style scoped>
.retry {
  font-family: var(--font-body); font-size-adjust: var(--fsa-body);
  font-size: var(--fs-md); font-weight: 600;
  color: var(--text);
  background: var(--accent-dim);
  border: 1px solid var(--accent);
  border-radius: var(--radius-sm);
  padding: 0.55rem 1.2rem;
  cursor: pointer;
  transition: background 0.15s ease, color 0.15s ease;
}
.retry:hover { background: var(--accent); color: var(--bg); }
</style>
