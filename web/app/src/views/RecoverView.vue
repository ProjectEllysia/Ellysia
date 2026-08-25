<template>
  <div class="gate-stage">
    <ElysianScene sun-top="16%" variant="minimal" />

    <div class="portal">
      <div class="portal-body">
        <router-link to="/" class="wordmark" aria-label="Ellysia — inicio">
          <img class="wordmark-mark" :src="ellysiaIcon" alt="" aria-hidden="true" />
          <span class="wordmark-text">Ellysia</span>
        </router-link>

        <!-- ───────── Comprobando el enlace ───────── -->
        <template v-if="state === 'loading'">
          <h1 class="title">Restablecer clave</h1>
          <p class="subtitle">Comprobando tu enlace…</p>
          <div class="title-rule" aria-hidden="true"></div>
          <div class="glyph glyph--loading" aria-hidden="true"></div>
        </template>

        <!-- ───────── Enlace inválido ───────── -->
        <template v-else-if="state === 'invalid'">
          <h1 class="title">Este enlace no vale</h1>
          <p class="subtitle">Puede que ya lo hayas usado o que haya caducado.</p>
          <div class="title-rule" aria-hidden="true"></div>

          <div class="gate-alert gate-alert-warning" role="alert">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span>Los enlaces de recuperación caducan a los 30 minutos y solo valen una vez.</span>
          </div>

          <router-link to="/login?recuperar" class="submit submit--link">Solicitar otro enlace</router-link>
          <p class="signup-hint">
            <router-link to="/login" class="link-btn">← Volver al umbral</router-link>
          </p>
        </template>

        <!-- ───────── Nueva clave ───────── -->
        <form v-else-if="state === 'form'" novalidate @submit.prevent="handleSubmit">
          <h1 class="title">Elige tu nueva clave</h1>
          <p class="subtitle">Con ella volverás a cruzar el umbral</p>
          <div class="title-rule" aria-hidden="true"></div>

          <transition name="alert">
            <div v-if="alertMsg" class="gate-alert gate-alert-error" role="alert">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>{{ alertMsg }}</span>
            </div>
          </transition>

          <div class="field">
            <label for="new-password">
              <span>Nueva clave de acceso</span>
              <transition name="caps">
                <span v-if="capsOn" class="caps-warn" role="status">⇪ Mayúsculas activas</span>
              </transition>
            </label>
            <div class="field-box">
              <svg class="field-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <rect x="4" y="11" width="16" height="10" rx="2" />
                <path d="M8 11V7a4 4 0 0 1 8 0v4" />
              </svg>
              <input
                id="new-password"
                v-model="newPassword"
                :type="showPassword ? 'text' : 'password'"
                placeholder="••••••••••••"
                autocomplete="new-password"
                required
                minlength="8"
                :disabled="loading"
                @keyup="checkCaps"
                @keydown="checkCaps"
              />
              <button
                type="button"
                class="reveal"
                :aria-label="showPassword ? 'Ocultar clave' : 'Mostrar clave'"
                :disabled="loading"
                @click="showPassword = !showPassword"
              >
                <svg v-if="!showPassword" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
                <svg v-else width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              </button>
            </div>
            <span class="field-hint">Mínimo 8 caracteres. Al cambiarla, se cerrará la sesión en todos tus dispositivos.</span>
          </div>

          <button type="submit" class="submit" :class="{ loading }" :disabled="loading">
            <span class="submit-label">{{ loading ? 'Guardando…' : 'Restablecer mi clave' }}</span>
            <span class="submit-arrow" aria-hidden="true">→</span>
            <span class="submit-spin" aria-hidden="true"></span>
          </button>
        </form>

        <!-- ───────── Hecho ───────── -->
        <template v-else-if="state === 'done'">
          <h1 class="title">Clave restablecida</h1>
          <p class="subtitle">Tus otras sesiones se han cerrado</p>
          <div class="title-rule" aria-hidden="true"></div>

          <div class="gate-alert gate-alert-success" role="alert">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
              <polyline points="22 4 12 14.01 9 11.01" />
            </svg>
            <span>Ya puedes entrar con tu nueva clave.</span>
          </div>

          <router-link to="/login" class="submit submit--link">Cruzar el umbral</router-link>
        </template>

        <footer class="portal-foot">
          <span class="foot-pulse"><i></i>Enlace cifrado activo</span>
          <span class="foot-ver">Ellysia © 2026</span>
        </footer>
      </div>
    </div>
  </div>
</template>

<script setup>
/**
 * Destino del enlace de recuperación de contraseña (`/recuperar?token=…`).
 *
 * PÚBLICA a propósito — el token es la única identidad, como en `/verificar` y
 * `/quiz`: quien pulsa el enlace no tiene por qué tener la sesión abierta, ni
 * siquiera estar en el mismo dispositivo. Por eso se usa `fetch` a pelo:
 * `apiFetch` exige un JWT y hace logout + redirección.
 *
 * El token no se queda en la URL: en cuanto se lee se limpia del query para
 * que no quede en el historial del navegador.
 */
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { validationMessage } from '@/composables/useApi'
import ElysianScene from '@/components/shared/ElysianScene.vue'
import ellysiaIcon from '@/assets/images/ellysia/Ellysia-BgN.png'

const route = useRoute()
const router = useRouter()

const state = ref('loading') // loading | invalid | form | done
const token = ref('')
const newPassword = ref('')
const showPassword = ref(false)
const loading = ref(false)
const alertMsg = ref('')
const capsOn = ref(false)

function checkCaps(e) {
  if (typeof e.getModifierState === 'function') {
    capsOn.value = e.getModifierState('CapsLock')
  }
}

async function checkToken() {
  const res = await fetch('/users/password-reset/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: token.value }),
  })
  if (!res.ok) {
    state.value = 'invalid'
    return
  }
  const body = await res.json().catch(() => ({}))
  state.value = body.valid ? 'form' : 'invalid'
}

async function handleSubmit() {
  alertMsg.value = ''
  const pw = newPassword.value
  if (!pw) {
    alertMsg.value = 'Introduce la nueva clave.'
    return
  }

  loading.value = true
  try {
    const res = await fetch('/users/password-reset/reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token.value, newPassword: pw }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({}))
      if (body?.code === 1617 || body?.error === 'PasswordResetTokenInvalidError') {
        state.value = 'invalid'
        return
      }
      alertMsg.value =
        validationMessage(body) || body.error_description || 'No se pudo restablecer la clave.'
      return
    }
    newPassword.value = ''
    state.value = 'done'
  } catch {
    alertMsg.value = 'No se pudo conectar con el servidor.'
  } finally {
    loading.value = false
  }
}

onMounted(async () => {
  const raw = route.query.token
  if (typeof raw !== 'string' || !raw) {
    state.value = 'invalid'
    return
  }
  token.value = raw
  // El token ya está en memoria; fuera de la URL, para que no quede en el
  // historial ni en los logs del proxy.
  router.replace({ path: route.path, query: {} }).catch(() => {})
  try {
    await checkToken()
  } catch {
    state.value = 'invalid'
  }
})
</script>

<style scoped>
/* Misma piel que el umbral de LoginView: el enlace llega por correo y debe
   sentirse parte del mismo portal. */
.gate-stage {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  overflow: hidden;
  background: var(--bg);
}

.portal {
  position: relative; z-index: 10; width: 100%; max-width: 400px;
  background: var(--surface);
  border: 1px solid var(--border-med);
  border-radius: 14px;
  box-shadow:
    0 30px 70px rgba(0,0,0,0.28),
    0 0 0 1px var(--border) inset;
  overflow: hidden;
  animation: portal-rise 0.9s cubic-bezier(0.16,1,0.3,1) both;
}
.portal::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent) 25%, var(--accent-bright) 50%, var(--accent) 75%, transparent);
  opacity: 0.7;
}
@keyframes portal-rise {
  from { opacity: 0; transform: translateY(26px); }
  to   { opacity: 1; transform: none; }
}

.portal-body { padding: 2.6rem 2.3rem 1.8rem; }

.wordmark {
  display: flex; align-items: center; justify-content: center; gap: 0.7rem;
  margin-bottom: 1.6rem;
}
.wordmark-mark {
  width: 22px; height: 22px; object-fit: contain;
  filter: drop-shadow(0 0 7px var(--sun-glow));
  transform: translateY(-1px);
}
.wordmark-text {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.34em; text-transform: uppercase;
  color: var(--text);
}

.title {
  text-align: center;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: var(--fs-page-title); font-weight: 600;
  color: var(--text); letter-spacing: 0.02em;
  line-height: 1.1;
}
.subtitle {
  text-align: center;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-style: italic;
  font-size: var(--fs-lg); color: var(--text-dim);
  margin-top: 0.25rem;
}
.title-rule {
  width: 54px; height: 1px; margin: 1.3rem auto 1.6rem;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  opacity: 0.6;
}

.glyph {
  width: 46px; height: 46px; margin: 0 auto;
  border-radius: 50%; border: 2px solid var(--border-med);
}
.glyph--loading { border-top-color: var(--accent); animation: spin 0.9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

.gate-alert {
  display: flex; align-items: flex-start; gap: 0.5rem;
  border-radius: 9px; padding: 0.7rem 0.9rem; font-size: var(--fs-sm);
  margin-bottom: 1.1rem; font-family: var(--font-body); font-size-adjust: var(--fsa-body);
}
.gate-alert svg { flex-shrink: 0; margin-top: 2px; }
.gate-alert-error   { background: var(--danger-dim);  border: 1px solid var(--danger);  color: var(--danger); }
.gate-alert-success { background: var(--success-dim); border: 1px solid var(--success); color: var(--success); }
.gate-alert-warning { background: var(--warn-dim);    border: 1px solid var(--warn);    color: var(--warn); }
.alert-enter-active { transition: opacity 0.35s ease, transform 0.35s ease; }
.alert-enter-from { opacity: 0; transform: translateY(-6px); }

.field { margin-bottom: 1.15rem; }
.field label {
  display: flex; align-items: center; gap: 0.25rem;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-label); font-weight: 600; color: var(--text-dim);
  margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.18em;
}
.caps-warn {
  margin-left: auto; font-size: var(--fs-caption); letter-spacing: 0.04em;
  color: var(--warn); text-transform: none; font-family: var(--font-body); font-size-adjust: var(--fsa-body);
}
.caps-enter-active, .caps-leave-active { transition: opacity 0.2s ease; }
.caps-enter-from, .caps-leave-to { opacity: 0; }

.field-box { position: relative; display: flex; align-items: center; }
.field-ico {
  position: absolute; left: 0.85rem; color: var(--text-muted);
  pointer-events: none;
}
.field-box input {
  width: 100%; padding: 0.82rem 2.7rem 0.82rem 2.5rem;
  background: var(--surface-2);
  border: 1px solid var(--border-solid); border-radius: 10px;
  color: var(--text); font-size: var(--fs-input); font-family: var(--font-body); font-size-adjust: var(--fsa-body); outline: none;
  transition: border-color 0.3s, box-shadow 0.3s, background 0.3s;
}
.field-box input::placeholder { color: var(--text-muted); opacity: 0.6; }
.field-box input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}
.field-box input:disabled { opacity: 0.5; cursor: not-allowed; }
.field-hint {
  display: block; margin-top: 0.4rem;
  font-family: var(--font-body); font-size-adjust: var(--fsa-body);
  font-size: var(--fs-caption); color: var(--text-muted);
}

.reveal {
  position: absolute; right: 8px; display: flex; padding: 7px;
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  border-radius: 7px; transition: color 0.2s, background 0.2s;
}
.reveal:hover:not(:disabled) { color: var(--accent); background: var(--accent-dim); }
.reveal:disabled { cursor: not-allowed; opacity: 0.4; }

.submit {
  position: relative; overflow: hidden;
  width: 100%; margin-top: 0.8rem; padding: 0.95rem;
  display: flex; align-items: center; justify-content: center; gap: 0.5rem;
  background: var(--accent);
  color: var(--surface);
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic); font-weight: 600;
  font-size: var(--fs-btn); letter-spacing: 0.16em; text-transform: uppercase;
  border: none; border-radius: 10px; cursor: pointer;
  box-shadow: 0 6px 20px var(--accent-dim);
  transition: transform 0.25s cubic-bezier(0.16,1,0.3,1), box-shadow 0.25s, background 0.25s, opacity 0.2s;
}
.submit:hover:not(:disabled) {
  background: var(--accent-bright);
  transform: translateY(-2px);
  box-shadow: 0 10px 30px var(--sun-glow);
}
.submit:hover:not(:disabled) .submit-arrow { transform: translateX(4px); }
.submit:active:not(:disabled) { transform: translateY(0); }
.submit:disabled { opacity: 0.6; cursor: not-allowed; }
.submit-label, .submit-arrow { position: relative; z-index: 1; font-size: var(--fs-md); }
.submit-arrow { transition: transform 0.25s ease; }
.submit.loading .submit-label, .submit.loading .submit-arrow { opacity: 0; }
.submit-spin {
  position: absolute; width: 20px; height: 20px;
  border: 2.5px solid rgba(0,0,0,0.18); border-top-color: var(--surface); border-radius: 50%;
  opacity: 0; animation: seq-spin 0.7s linear infinite;
}
.submit.loading .submit-spin { opacity: 1; }
@keyframes seq-spin { to { transform: rotate(360deg); } }

/* Enlace "botón" (estados invalid/done): <a> necesita el modelo de caja del botón. */
.submit--link { display: flex; text-decoration: none; }
.submit--link:hover { color: var(--surface); }

.signup-hint { padding: 0.5rem 0; text-align: center; }
.link-btn {
  background: none; border: none; cursor: pointer; padding: 0.2rem;
  font-family: var(--font-body); font-size-adjust: var(--fsa-body); font-size: var(--fs-sm); color: var(--text-dim);
  text-decoration: underline; text-underline-offset: 2px;
  transition: color 0.2s ease;
}
.link-btn:hover { color: var(--accent); }

.portal-foot {
  display: flex; align-items: center; justify-content: space-between;
  margin-top: 1.6rem; padding-top: 1rem; border-top: 1px solid var(--border);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-caption); color: var(--text-muted);
}
.foot-pulse { display: inline-flex; align-items: center; gap: 0.4rem; }
.foot-pulse i {
  width: 5px; height: 5px; border-radius: 50%; background: var(--success);
  box-shadow: 0 0 6px var(--success); animation: live-pulse 2s ease-in-out infinite;
}
@keyframes live-pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.7); } }
.foot-ver { opacity: 0.8; letter-spacing: 0.04em; }

@media (max-width: 640px) {
  .gate-stage { padding: 1rem; }
  .portal { max-width: 100%; }
  .portal-body { padding: 2.1rem 1.6rem 1.6rem; }
}

@media (prefers-reduced-motion: reduce) {
  .portal, .glyph--loading, .foot-pulse i, .submit-spin { animation: none !important; }
}
</style>
