<template>
  <div class="gate-stage">
    <ElysianScene sun-top="16%" variant="minimal" />

    <!-- Cambio de iluminación (dusk / dawn) -->
    <button
      class="theme-toggle"
      @click="themeStore.toggleTheme()"
      :aria-label="themeStore.theme === 'dusk' ? 'Cambiar a Amanecer' : 'Cambiar a Ocaso'"
      :title="themeStore.theme === 'dusk' ? 'Amanecer' : 'Ocaso'"
    >
      <svg v-if="themeStore.theme === 'dusk'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
        <circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="8" opacity="0.45" />
      </svg>
      <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
        <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
      </svg>
    </button>

    <!-- ───────── El umbral ───────── -->
    <div class="portal">
      <div class="portal-body" :inert="granted">
        <router-link to="/" class="wordmark" aria-label="Ellysia — inicio">
          <img class="wordmark-mark" :src="ellysiaIcon" alt="" aria-hidden="true" />
          <span class="wordmark-text">Ellysia</span>
        </router-link>

        <h1 class="title">El umbral</h1>
        <p class="subtitle">Identifícate para cruzar</p>

        <div class="title-rule" aria-hidden="true"></div>

        <!-- Aviso -->
        <transition name="alert">
          <div v-if="alertMsg" class="gate-alert" :class="'gate-alert-' + alertType" role="alert">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <template v-if="alertType === 'error' || alertType === 'warning'">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </template>
              <template v-else>
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </template>
            </svg>
            <span>{{ alertMsg }}</span>
          </div>
        </transition>

        <form v-if="!mfaStep && mode === 'login'" novalidate @submit.prevent="handleSubmit">
          <!-- Identificador -->
          <div class="field" :class="{ focused: focus === 'user' }">
            <label for="username">Identificador</label>
            <div class="field-box">
              <svg class="field-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <circle cx="12" cy="8" r="4" />
                <path d="M4 21c0-4 4-6 8-6s8 2 8 6" />
              </svg>
              <input
                id="username"
                v-model="username"
                type="text"
                placeholder="nombre de usuario"
                autocomplete="username"
                spellcheck="false"
                required
                :class="{ 'has-error': usernameError }"
                :disabled="loading"
                @focus="focus = 'user'"
                @blur="focus = ''"
              />
            </div>
          </div>

          <!-- Clave -->
          <div class="field" :class="{ focused: focus === 'pass' }">
            <label for="password">
              <span>Clave de acceso</span>
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
                id="password"
                v-model="password"
                :type="showPassword ? 'text' : 'password'"
                placeholder="••••••••••••"
                autocomplete="current-password"
                required
                :class="{ 'has-error': passwordError }"
                :disabled="loading"
                @focus="focus = 'pass'"
                @blur="focus = ''"
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
          </div>

          <button type="submit" class="submit" :class="{ loading }" :disabled="loading">
            <span class="submit-label">{{ loading ? 'Cruzando…' : 'Cruzar el umbral' }}</span>
            <span class="submit-arrow" aria-hidden="true">→</span>
            <span class="submit-spin" aria-hidden="true"></span>
          </button>

          <p class="signup-hint">
            ¿No tienes cuenta?
            <button type="button" class="link-btn" @click="mode = 'register'">
              Regístrate gratis y prueba Ellysia
            </button>
          </p>
        </form>

        <!-- ───────── Alta pública ───────── -->
        <form v-else-if="!mfaStep && mode === 'register'" novalidate @submit.prevent="handleRegister">
          <div class="field" :class="{ focused: focus === 'reg-user' }">
            <label for="reg-username">Identificador</label>
            <div class="field-box">
              <input id="reg-username" v-model="reg.username" type="text" required
                     minlength="3" maxlength="64" autocomplete="username"
                     @focus="focus = 'reg-user'" @blur="focus = ''" />
            </div>
          </div>

          <div class="field" :class="{ focused: focus === 'reg-mail' }">
            <label for="reg-email">Correo</label>
            <div class="field-box">
              <input id="reg-email" v-model="reg.email" type="email" required
                     autocomplete="email" @focus="focus = 'reg-mail'" @blur="focus = ''" />
            </div>
          </div>

          <div class="field-row">
            <div class="field" :class="{ focused: focus === 'reg-first' }">
              <label for="reg-first">Nombre</label>
              <div class="field-box">
                <input id="reg-first" v-model="reg.first_name" type="text" required
                       maxlength="64" @focus="focus = 'reg-first'" @blur="focus = ''" />
              </div>
            </div>
            <div class="field" :class="{ focused: focus === 'reg-last' }">
              <label for="reg-last">Apellidos</label>
              <div class="field-box">
                <input id="reg-last" v-model="reg.last_name" type="text" required
                       maxlength="64" @focus="focus = 'reg-last'" @blur="focus = ''" />
              </div>
            </div>
          </div>

          <div class="field" :class="{ focused: focus === 'reg-pass' }">
            <label for="reg-password">Clave de acceso</label>
            <div class="field-box">
              <input id="reg-password" v-model="reg.password" type="password" required
                     minlength="8" autocomplete="new-password"
                     @focus="focus = 'reg-pass'" @blur="focus = ''" />
            </div>
            <span class="field-hint">Mínimo 8 caracteres.</span>
          </div>

          <button type="submit" class="submit" :class="{ loading }" :disabled="loading">
            <span class="submit-label">{{ loading ? 'Creando…' : 'Crear mi cuenta' }}</span>
            <span class="submit-arrow" aria-hidden="true">→</span>
            <span class="submit-spin" aria-hidden="true"></span>
          </button>

          <p class="signup-hint">
            Empezarás en el plan gratuito. Te mandaremos un correo para
            confirmarlo.
            <button type="button" class="link-btn" @click="mode = 'login'">
              Ya tengo cuenta
            </button>
          </p>
        </form>

        <!-- ───────── Segundo factor (MFA) ───────── -->
        <form v-else novalidate @submit.prevent="handleMfaSubmit">
          <div class="field focused">
            <label for="mfa-code">{{ useRecovery ? 'Código de recuperación' : 'Código de verificación' }}</label>
            <div class="field-box">
              <svg class="field-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <rect x="3" y="11" width="18" height="10" rx="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                <circle cx="12" cy="16" r="1.5" />
              </svg>
              <input
                id="mfa-code"
                v-model="mfaCode"
                type="text"
                :placeholder="useRecovery ? 'XXXX-XXXX' : '123456'"
                :inputmode="useRecovery ? 'text' : 'numeric'"
                autocomplete="one-time-code"
                autofocus
                required
                :disabled="loading"
              />
            </div>
          </div>

          <button type="submit" class="submit" :class="{ loading }" :disabled="loading">
            <span class="submit-label">{{ loading ? 'Verificando…' : 'Verificar' }}</span>
            <span class="submit-arrow" aria-hidden="true">→</span>
            <span class="submit-spin" aria-hidden="true"></span>
          </button>

          <div class="mfa-links">
            <button type="button" class="link-btn" :disabled="loading" @click="toggleRecoveryMode">
              {{ useRecovery ? 'Usar código de la app' : '¿Perdiste el acceso? Usar código de recuperación' }}
            </button>
            <button type="button" class="link-btn" :disabled="loading" @click="resetToCredentials">
              ← Volver
            </button>
          </div>
        </form>

        <p v-if="mode === 'login'" class="plans-hint">
          <router-link to="/planes" class="link-btn">Ver los planes</router-link>
        </p>

        <footer class="portal-foot">
          <span class="foot-pulse"><i></i>Enlace cifrado activo</span>
          <span class="foot-ver">Ellysia © 2026</span>
        </footer>
      </div>
    </div>

    <!-- ───────── Umbral cruzado ───────── -->
    <transition name="grant">
      <div v-if="granted" class="grant-screen" aria-live="assertive">
        <svg class="grant-sun" viewBox="0 0 120 120" fill="none">
          <circle class="grant-ring grant-ring--in" cx="60" cy="60" r="30" stroke="var(--accent-bright)" stroke-width="2" />
          <circle class="grant-ring grant-ring--out" cx="60" cy="60" r="46" stroke="var(--accent)" stroke-width="1.5" stroke-dasharray="3 7" />
          <path class="grant-check" d="M46 60l10 10 20-22" stroke="var(--accent-bright)" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <p class="grant-title">Bienvenido</p>
        <p class="grant-sub">Estableciendo sesión segura…</p>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'
import ElysianScene from '@/components/shared/ElysianScene.vue'
import ellysiaIcon from '@/assets/images/ellysia/Ellysia-BgN.png'

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const themeStore = useThemeStore()

/* ── estado del formulario ── */
const username = ref('')
const password = ref('')
const showPassword = ref(false)
const loading = ref(false)
const alertMsg = ref('')
const alertType = ref('error')
const usernameError = ref(false)
const passwordError = ref(false)
const focus = ref('')
const capsOn = ref(false)
const granted = ref(false)

/* ── segundo factor (MFA) ── */
const mfaStep = ref(false)

/**
 * 'login' o 'register'. Un paso más del mismo formulario, como el de MFA, y no
 * una vista aparte: el alta pública es la puerta de entrada al plan gratuito, y
 * mandar a otra pantalla para volver aquí sobra.
 */
const mode = ref('login')
const reg = ref({ username: '', email: '', first_name: '', last_name: '', password: '' })

/**
 * Alta pública. Al terminar NO se inicia sesión sola: la cuenta nace sin el
 * correo verificado y se le dice, para que sepa por qué ciertas cosas no le
 * dejarán hasta que pulse el enlace.
 */
async function handleRegister() {
  loading.value = true
  try {
    const res = await fetch('/users/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(reg.value),
    })
    const body = await res.json().catch(() => ({}))

    if (!res.ok) {
      showAlert(body.error_description || 'No se pudo crear la cuenta.', 'error')
      return
    }

    showAlert(
      'Cuenta creada. Revisa tu correo para confirmarla y ya puedes entrar.',
      'success',
    )
    username.value = reg.value.username
    reg.value = { username: '', email: '', first_name: '', last_name: '', password: '' }
    mode.value = 'login'
  } catch {
    showAlert('No se pudo conectar con el servidor.', 'error')
  } finally {
    loading.value = false
  }
}
const mfaChallengeToken = ref('')
const mfaCode = ref('')
const useRecovery = ref(false)

const reduceMotion =
  typeof window !== 'undefined' &&
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

/* ── detección de Bloq Mayús ── */
function checkCaps(e) {
  if (typeof e.getModifierState === 'function') {
    capsOn.value = e.getModifierState('CapsLock')
  }
}

/* ── envío ── */
async function handleSubmit() {
  alertMsg.value = ''
  usernameError.value = false
  passwordError.value = false

  const un = username.value.trim()
  const pw = password.value

  if (!un) {
    showAlert('El identificador es obligatorio.', 'error')
    usernameError.value = true
    document.getElementById('username')?.focus()
    return
  }
  if (!pw) {
    showAlert('La clave de acceso es obligatoria.', 'error')
    passwordError.value = true
    document.getElementById('password')?.focus()
    return
  }

  loading.value = true
  try {
    const step = await auth.login(un, pw)
    if (step.mfaRequired) {
      mfaChallengeToken.value = step.challengeToken
      mfaStep.value = true
      loading.value = false
      return
    }
    completeLogin()
  } catch (err) {
    showAlert(err.message || 'Error desconocido.', 'error')
    if (err.message?.includes('Credenciales')) {
      usernameError.value = true
      passwordError.value = true
      password.value = ''
    }
    loading.value = false
  }
}

/* ── envío del segundo factor (MFA) ── */
async function handleMfaSubmit() {
  alertMsg.value = ''
  const value = mfaCode.value.trim()
  if (!value) {
    showAlert('Introduce el código.', 'error')
    return
  }

  loading.value = true
  try {
    await auth.verifyMfa(
      mfaChallengeToken.value,
      useRecovery.value ? { recoveryCode: value } : { code: value },
    )
    completeLogin()
  } catch (err) {
    showAlert(err.message || 'Error desconocido.', 'error')
    mfaCode.value = ''
    loading.value = false
  }
}

function toggleRecoveryMode() {
  useRecovery.value = !useRecovery.value
  mfaCode.value = ''
  alertMsg.value = ''
}

function resetToCredentials() {
  mfaStep.value = false
  mfaChallengeToken.value = ''
  mfaCode.value = ''
  useRecovery.value = false
  alertMsg.value = ''
  password.value = ''
}

function completeLogin() {
  granted.value = true
  const redirect = route.query.redirect
  const target = typeof redirect === 'string' && redirect.startsWith('/') && !redirect.startsWith('//')
    ? redirect
    : '/'
  const delay = reduceMotion ? 300 : 1500
  setTimeout(() => router.push(target), delay)
}

function showAlert(msg, type = 'error') {
  alertMsg.value = msg
  alertType.value = type
}

/* ── ciclo de vida ── */
onMounted(() => {
  // Si la sesión terminó por un cambio de contraseña, avisar de forma destacada.
  if (auth.takeSessionEndReason() === 'password_changed') {
    showAlert(
      'Tu contraseña ha cambiado. Inicia sesión de nuevo con la contraseña actual.',
      'warning',
    )
  }
  if (!reduceMotion) document.getElementById('username')?.focus()
})

onBeforeUnmount(() => {})
</script>

<style scoped>
/* ═══════════ Escenario ═══════════ */
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

.theme-toggle {
  position: fixed; top: 1.4rem; right: 1.6rem; z-index: 20;
  width: 36px; height: 36px; border-radius: 50%;
  display: grid; place-items: center;
  color: var(--accent);
  border: 1px solid var(--border-med);
  background: var(--surface);
  transition: all var(--transition);
}
.theme-toggle:hover { border-color: var(--accent); box-shadow: 0 0 14px var(--accent-dim); }
.theme-toggle svg { width: 17px; height: 17px; }

/* ═══════════ El umbral ═══════════ */
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
/* filo de oro superior, como la línea del horizonte */
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

/* Marca */
.wordmark {
  display: flex; align-items: center; justify-content: center; gap: 0.7rem;
  margin-bottom: 1.6rem;
}
.wordmark-mark {
  width: 22px; height: 22px; object-fit: contain;
  filter: drop-shadow(0 0 7px var(--sun-glow));
  /* Alineación óptica con las mayúsculas del wordmark. */
  transform: translateY(-1px);
}
.wordmark-text {
  font-family: var(--font-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.34em; text-transform: uppercase;
  color: var(--text);
}

/* Título */
.title {
  text-align: center;
  font-family: var(--font-display);
  font-size: var(--fs-page-title); font-weight: 600;
  color: var(--text); letter-spacing: 0.02em;
  line-height: 1.1;
}
.subtitle {
  text-align: center;
  font-family: var(--font-display); font-style: italic;
  font-size: var(--fs-lg); color: var(--text-dim);
  margin-top: 0.25rem;
}
.title-rule {
  width: 54px; height: 1px; margin: 1.3rem auto 1.6rem;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  opacity: 0.6;
}

/* ═══════════ Aviso ═══════════ */
.gate-alert {
  display: flex; align-items: flex-start; gap: 0.5rem;
  border-radius: 9px; padding: 0.7rem 0.9rem; font-size: var(--fs-sm);
  margin-bottom: 1.1rem; font-family: var(--font-body);
}
.gate-alert svg { flex-shrink: 0; margin-top: 2px; }
.gate-alert-error   { background: var(--danger-dim);  border: 1px solid var(--danger);  color: var(--danger); }
.gate-alert-success { background: var(--success-dim); border: 1px solid var(--success); color: var(--success); }
.gate-alert-warning { background: var(--warn-dim);    border: 1px solid var(--warn);    color: var(--warn); }
.alert-enter-active { transition: opacity 0.35s ease, transform 0.35s ease; }
.alert-enter-from { opacity: 0; transform: translateY(-6px); }

/* ═══════════ Campos ═══════════ */
.field { margin-bottom: 1.15rem; }
.field label {
  display: flex; align-items: center; gap: 0.25rem;
  font-family: var(--font-epic);
  font-size: var(--fs-label); font-weight: 600; color: var(--text-dim);
  margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.18em;
  transition: color 0.25s ease;
}
.field.focused label { color: var(--accent); }
.caps-warn {
  margin-left: auto; font-size: var(--fs-caption); letter-spacing: 0.04em;
  color: var(--warn); text-transform: none; font-family: var(--font-body);
}
.caps-enter-active, .caps-leave-active { transition: opacity 0.2s ease; }
.caps-enter-from, .caps-leave-to { opacity: 0; }

.field-box { position: relative; display: flex; align-items: center; }
.field-ico {
  position: absolute; left: 0.85rem; color: var(--text-muted);
  transition: color 0.25s ease; pointer-events: none;
}
.field.focused .field-ico { color: var(--accent); }
.field-box input {
  width: 100%; padding: 0.82rem 2.7rem 0.82rem 2.5rem;
  background: var(--surface-2);
  border: 1px solid var(--border-solid); border-radius: 10px;
  color: var(--text); font-size: var(--fs-input); font-family: var(--font-body); outline: none;
  transition: border-color 0.3s, box-shadow 0.3s, background 0.3s;
}
.field-box input::placeholder { color: var(--text-muted); opacity: 0.6; }
.field-box input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}
.field-box input.has-error {
  border-color: var(--danger);
  box-shadow: 0 0 0 3px var(--danger-dim);
  animation: shake 0.4s ease-in-out;
}
.field-box input:disabled { opacity: 0.5; cursor: not-allowed; }
@keyframes shake {
  0%,100% { transform: translateX(0); }
  20% { transform: translateX(-5px); } 40% { transform: translateX(5px); }
  60% { transform: translateX(-3px); } 80% { transform: translateX(3px); }
}
.reveal {
  position: absolute; right: 8px; display: flex; padding: 7px;
  background: none; border: none; color: var(--text-muted); cursor: pointer;
  border-radius: 7px; transition: color 0.2s, background 0.2s;
}
.reveal:hover:not(:disabled) { color: var(--accent); background: var(--accent-dim); }
.reveal:disabled { cursor: not-allowed; opacity: 0.4; }

/* ═══════════ Botón ═══════════ */
.submit {
  position: relative; overflow: hidden;
  width: 100%; margin-top: 0.8rem; padding: 0.95rem;
  display: flex; align-items: center; justify-content: center; gap: 0.5rem;
  background: var(--accent);
  color: var(--surface);
  font-family: var(--font-epic); font-weight: 600;
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

/* ═══════════ Segundo factor (MFA) ═══════════ */
.mfa-links {
  display: flex; flex-direction: column; align-items: center; gap: 0.5rem;
  margin-top: 1.1rem;
}
.link-btn {
  background: none; border: none; cursor: pointer; padding: 0.2rem;
  font-family: var(--font-body); font-size: var(--fs-sm); color: var(--text-dim);
  text-decoration: underline; text-underline-offset: 2px;
  transition: color 0.2s ease;
}
.link-btn:hover:not(:disabled) { color: var(--accent); }
.link-btn:disabled { opacity: 0.5; cursor: not-allowed; }

/* ═══════════ Pie ═══════════ */
.portal-foot {
  display: flex; align-items: center; justify-content: space-between;
  margin-top: 1.6rem; padding-top: 1rem; border-top: 1px solid var(--border);
  font-family: var(--font-mono); font-size: var(--fs-caption); color: var(--text-muted);
}
.foot-pulse { display: inline-flex; align-items: center; gap: 0.4rem; }
.foot-pulse i {
  width: 5px; height: 5px; border-radius: 50%; background: var(--success);
  box-shadow: 0 0 6px var(--success); animation: live-pulse 2s ease-in-out infinite;
}
@keyframes live-pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.7); } }
.foot-ver { opacity: 0.8; letter-spacing: 0.04em; }
.signup-hint { padding: 0.5rem 0 }


/* ═══════════ Umbral cruzado ═══════════ */
.grant-screen {
  position: fixed; inset: 0; z-index: 30;
  display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.3rem;
  background: var(--bg);
}
.grant-sun { width: 128px; height: 128px; filter: drop-shadow(0 0 26px var(--sun-glow)); }
.grant-ring { fill: none; transform-origin: center; }
.grant-ring--in  { stroke-dasharray: 190; stroke-dashoffset: 190; animation: draw 0.7s ease forwards; }
.grant-ring--out { opacity: 0; animation: ring-fade 0.6s 0.5s ease forwards, ring-turn 200s linear infinite; }
.grant-check { stroke-dasharray: 60; stroke-dashoffset: 60; animation: draw 0.4s 0.6s ease forwards; }
@keyframes draw { to { stroke-dashoffset: 0; } }
@keyframes ring-fade { to { opacity: 1; } }
@keyframes ring-turn { to { transform: rotate(360deg); } }
.grant-title {
  margin-top: 1rem; font-family: var(--font-display); font-weight: 600;
  font-size: var(--fs-3xl); letter-spacing: 0.04em; color: var(--text);
  opacity: 0; animation: fade-up 0.5s 0.85s ease forwards;
}
.grant-sub {
  font-family: var(--font-mono); font-size: var(--fs-sm); color: var(--text-dim); letter-spacing: 0.08em;
  opacity: 0; animation: fade-up 0.5s 1.05s ease forwards;
}
@keyframes fade-up { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }
.grant-enter-active { transition: opacity 0.35s ease; }
.grant-enter-from { opacity: 0; }
.grant-leave-active { transition: opacity 0.4s ease; }
.grant-leave-to { opacity: 0; }

/* ═══════════ Responsive ═══════════ */
@media (max-width: 640px) {
  .gate-stage { padding: 1rem; }
  .portal { max-width: 100%; }
  .portal-body { padding: 2.1rem 1.6rem 1.6rem; }
}

/* ═══════════ Movimiento reducido ═══════════ */
@media (prefers-reduced-motion: reduce) {
  .portal, .grant-ring--out { animation: none !important; }
  .foot-pulse i, .submit-spin { animation: none !important; }
}
</style>
