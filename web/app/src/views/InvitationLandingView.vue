<template>
  <div class="landing">
    <SiteHeader />

    <main class="main">
      <div class="card">
        <div class="state" :class="`state--${state}`" aria-hidden="true"></div>

        <h1 class="title">{{ copy.title }}</h1>
        <p class="text">{{ copy.text }}</p>

        <router-link v-if="state === 'ok'" :to="okRoute" class="cta">{{ copy.cta }}</router-link>
        <router-link v-else-if="state === 'error'" to="/" class="cta">Volver a la portada</router-link>
      </div>
    </main>

    <SiteFooter />
  </div>
</template>

<script setup>
/**
 * Aterrizaje de los enlaces de correo: confirmar la dirección y aceptar una
 * invitación.
 *
 * Una vista para los dos porque hacen exactamente lo mismo — coger un token de
 * la query, mandarlo a un endpoint público y contar cómo fue. Lo que cambia es
 * el texto, y eso son datos, no un componente aparte.
 *
 * Ninguno de los dos exige sesión: el token es la única identidad, así que el
 * enlace funciona desde el móvil donde se abrió el correo.
 */
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import SiteHeader from '@/components/shared/SiteHeader.vue'
import SiteFooter from '@/components/shared/SiteFooter.vue'

const props = defineProps({
  /** 'verify' (confirmar correo) o 'invitation' (aceptar invitación). */
  kind: { type: String, required: true },
})

const route = useRoute()
const state = ref('loading')
const serverMessage = ref('')

const ENDPOINTS = {
  verify: '/users/verify-email',
  invitation: '/organizations/invitations/accept',
}

const COPY = {
  verify: {
    loading: { title: 'Confirmando tu correo…', text: 'Un momento.' },
    ok: {
      title: 'Correo confirmado',
      text: 'Ya puedes usar Ellysia sin límites de cuenta sin verificar.',
      cta: 'Entrar',
    },
    error: {
      title: 'Este enlace no vale',
      text: 'Puede que ya lo hayas usado o que haya caducado. Pide uno nuevo desde tu perfil.',
    },
  },
  invitation: {
    loading: { title: 'Aceptando la invitación…', text: 'Un momento.' },
    ok: {
      title: 'Ya formas parte de la organización',
      text: 'Tu plan personal no ha cambiado: lo que la organización incluye se '
        + 'suma a lo que ya tenías, y si algún día sales te lo llevas intacto.',
      cta: 'Ver mi organización',
    },
    error: {
      title: 'Esta invitación no vale',
      text: 'Puede que ya la hayas aceptado, que la hayan revocado o que haya '
        + 'caducado. Pide a quien te invitó que te mande otra.',
    },
  },
}

const copy = computed(() => {
  const base = COPY[props.kind][state.value]
  if (state.value === 'error' && serverMessage.value) {
    return { ...base, text: serverMessage.value }
  }
  return base
})

const okRoute = computed(() => (props.kind === 'verify' ? '/login' : '/organizacion'))

onMounted(async () => {
  const token = route.query.token
  if (!token) {
    state.value = 'error'
    return
  }

  try {
    const res = await fetch(ENDPOINTS[props.kind], {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    })
    if (res.ok) {
      state.value = 'ok'
      return
    }
    const body = await res.json().catch(() => ({}))
    serverMessage.value = body.error_description || ''
    state.value = 'error'
  } catch {
    state.value = 'error'
  }
})
</script>

<style scoped>
.landing { min-height: 100vh; background: var(--bg); display: flex; flex-direction: column; }
.main { flex: 1; display: grid; place-items: center; padding: 3rem 1.5rem; }

.card {
  max-width: 520px; text-align: center;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 12px;
  padding: 2.5rem 2rem;
}

.state {
  width: 46px; height: 46px; margin: 0 auto 1.4rem;
  border-radius: 50%; border: 2px solid var(--border-med);
}
.state--loading { border-top-color: var(--accent); animation: spin 0.9s linear infinite; }
.state--ok { border-color: var(--success); background: var(--success); opacity: 0.9; }
.state--error { border-color: var(--danger); }

@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .state--loading { animation: none; } }

.title {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: clamp(1.5rem, 3vw, 2rem); font-weight: 600; color: var(--text);
}
.text { color: var(--text-muted); margin-top: 0.8rem; line-height: 1.6; }

.cta {
  display: inline-block; margin-top: 1.8rem;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic); font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.18em; text-transform: uppercase;
  padding: 0.7rem 1.6rem; border-radius: 3px;
  color: var(--accent-bright); background: var(--accent-dim);
  border: 1px solid var(--accent);
  transition: all var(--transition);
}
.cta:hover { background: var(--accent); color: var(--on-accent); }
</style>
