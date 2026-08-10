<template>
  <span
    class="badge"
    :class="[`badge--${classMap}`, { 'badge--settling': settling }]"
    @animationend="settling = false"
  >{{ label }}</span>
</template>

<script setup>
import { computed, ref, watch } from 'vue'

const props = defineProps({ status: { type: String, required: true } })
const MAP = {
  running: ['running', 'Ejecutando'],
  done: ['done', 'Completado'],
  finished: ['done', 'Completado'],
  pending: ['pending', 'Pendiente'],
  error: ['error', 'Error'],
  cancelled: ['cancelled', 'Cancelado'],
}
const classMap = computed(() => (MAP[(props.status ?? '').toLowerCase()] ?? ['pending'])[0])
const label = computed(() => (MAP[(props.status ?? '').toLowerCase()] ?? ['pending', props.status ?? '—'])[1])

/**
 * Themis sostiene la balanza: cuando un escaneo deja de estar en vuelo, el
 * veredicto se asienta como un platillo que se para.
 *
 * Solo al pasar de "en curso" a un estado terminal — no al pintar la tabla por
 * primera vez, donde treinta insignias moviéndose a la vez serían ruido. Es el
 * único gesto de la vista, y marca justo el instante que el usuario está
 * esperando mientras sondea.
 */
const EN_VUELO = new Set(['running', 'pending'])
const settling = ref(false)

watch(classMap, (ahora, antes) => {
  if (!antes || !EN_VUELO.has(antes) || EN_VUELO.has(ahora)) return
  // Se activa a secas y se limpia sola en `animationend`. La versión anterior
  // usaba requestAnimationFrame para reiniciar la animación, pero rAF no corre
  // en una pestaña de fondo: un escaneo que terminaba mientras mirabas otra
  // cosa dejaba la clase sin poner. Como el paso de "en vuelo" a terminal
  // ocurre una sola vez por escaneo, no hace falta reiniciar nada.
  settling.value = true
})
</script>

<style scoped>
.badge { transition: background-color 0.3s ease, color 0.3s ease; }

.badge--settling { animation: badge-settle 0.62s cubic-bezier(0.22, 1, 0.36, 1); }

/* Cae, se pasa de largo y oscila hasta quedarse a nivel. */
@keyframes badge-settle {
  0%   { transform: translateY(-3px) rotate(0deg);    opacity: 0.55; }
  35%  { transform: translateY(0)    rotate(-3.5deg); opacity: 1; }
  60%  { transform: translateY(0)    rotate(2deg); }
  80%  { transform: translateY(0)    rotate(-0.8deg); }
  100% { transform: translateY(0)    rotate(0deg); }
}

@media (prefers-reduced-motion: reduce) {
  .badge { transition: none; }
  .badge--settling { animation: none; }
}
</style>
