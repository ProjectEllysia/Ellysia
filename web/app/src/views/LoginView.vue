<template>
  <div
    class="login-stage"
    :class="{ booting, granted }"
    @mousemove="onPointerMove"
    @mouseleave="resetTilt"
  >
    <!-- ───────── Ambient background ───────── -->
    <div class="bg-orbs" aria-hidden="true">
      <span class="orb orb--gold"></span>
      <span class="orb orb--green"></span>
      <span class="orb orb--blue"></span>
    </div>
    <div class="bg-grid" aria-hidden="true"></div>
    <div class="bg-radar" aria-hidden="true"><span class="radar-sweep"></span></div>
    <div class="bg-scanlines" aria-hidden="true"></div>

    <!-- Constellation of drifting nodes -->
    <svg class="bg-constellation" aria-hidden="true" preserveAspectRatio="none">
      <line
        v-for="(l, i) in links"
        :key="'l' + i"
        :x1="nodes[l[0]].x + '%'"
        :y1="nodes[l[0]].y + '%'"
        :x2="nodes[l[1]].x + '%'"
        :y2="nodes[l[1]].y + '%'"
      />
      <circle
        v-for="(n, i) in nodes"
        :key="'n' + i"
        :cx="n.x + '%'"
        :cy="n.y + '%'"
        :r="n.r"
        :style="{ animationDelay: n.delay + 's' }"
      />
    </svg>

    <!-- Cursor spotlight -->
    <div class="spotlight" aria-hidden="true"></div>

    <!-- Giant watermark -->
    <div class="watermark" aria-hidden="true">
      <span class="watermark-text">Ellysia</span>
      <span class="watermark-sub">SECURITY · OPERATIONS · CLEARANCE</span>
    </div>

    <!-- ───────── Clearance console card ───────── -->
    <div class="console" :style="cardStyle">
      <div class="console-sheen" aria-hidden="true"></div>
      <div class="console-edge" aria-hidden="true"></div>

      <!-- Terminal bar -->
      <header class="term-bar">
        <span class="term-dots" aria-hidden="true">
          <i class="d d-r"></i><i class="d d-y"></i><i class="d d-g"></i>
        </span>
        <span class="term-path">ellysia://clearance/access</span>
        <span class="term-clock">{{ clock }}</span>
      </header>

      <!-- Boot diagnostics overlay -->
      <transition name="boot">
        <div v-if="booting" class="boot" aria-hidden="true">
          <p v-for="(line, i) in bootShown" :key="i" class="boot-line">
            <span class="boot-mark">›</span>{{ line }}
            <span class="boot-ok">OK</span>
          </p>
          <p class="boot-cursor"><span class="boot-mark">›</span><span class="caret">▌</span></p>
        </div>
      </transition>

      <!-- Body -->
      <div class="console-body" :inert="booting || granted">
        <div class="brand">
          <span class="brand-bracket">[</span>
          <span class="brand-mark" :class="{ glitch: glitching }" data-text="Ellysia">Ellysia</span>
          <span class="brand-bracket">]</span>
          <span class="brand-shield" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
              <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" />
              <path d="M9 12l2 2 4-4" stroke-width="2" />
            </svg>
          </span>
        </div>

        <h1 class="title">
          <span class="title-main">Security Operations</span>
          <span class="title-tag">Acceso restringido</span>
        </h1>
        <p class="subtitle">
          Verificación de identidad requerida para continuar
        </p>

        <!-- Alert -->
        <transition name="alert">
          <div
            v-if="alertMsg"
            class="alert"
            :class="'alert-' + alertType"
            role="alert"
          >
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

        <form novalidate @submit.prevent="handleSubmit">
          <!-- Username -->
          <div class="field" :class="{ focused: focus === 'user', filled: username }">
            <label for="username">
              <span>Identificador</span>
              <span class="field-cursor">_</span>
            </label>
            <div class="field-box">
              <svg class="field-ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                <circle cx="12" cy="8" r="4" />
                <path d="M4 21c0-4 4-6 8-6s8 2 8 6" />
              </svg>
              <input
                id="username"
                v-model="username"
                type="text"
                placeholder="nombre_de_usuario"
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

          <!-- Password -->
          <div class="field" :class="{ focused: focus === 'pass', filled: password }">
            <label for="password">
              <span>Clave de acceso</span>
              <span class="field-cursor">_</span>
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
                @input="scramble"
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

            <!-- Live encryption cipher strip -->
            <div class="cipher" :class="{ active: password.length }" aria-hidden="true">
              <span class="cipher-tag">
                <span class="cipher-lock"></span>{{ password.length ? 'AES-256 · CIFRANDO' : 'EN ESPERA' }}
              </span>
              <span class="cipher-stream">{{ cipherText }}</span>
            </div>
          </div>

          <button type="submit" class="submit" :class="{ loading }" :disabled="loading">
            <span class="submit-label">{{ loading ? 'Autorizando…' : 'Solicitar acceso' }}</span>
            <span class="submit-arrow" aria-hidden="true">→</span>
            <span class="submit-shine" aria-hidden="true"></span>
            <span class="submit-spin" aria-hidden="true"></span>
          </button>
        </form>

        <footer class="console-foot">
          <span class="foot-pulse"><i></i>Enlace cifrado activo</span>
          <span class="foot-ver">build 2.6.0 · Ellysia © 2026</span>
        </footer>
      </div>
    </div>

    <!-- ───────── Access granted overlay ───────── -->
    <transition name="grant">
      <div v-if="granted" class="grant-screen" aria-live="assertive">
        <svg class="grant-shield" viewBox="0 0 120 120" fill="none">
          <path
            class="grant-shield-body"
            d="M60 8l40 15v30c0 25-17.5 42.5-40 55C37.5 95.5 20 78 20 53V23L60 8z"
            stroke="var(--accent-bright)"
            stroke-width="2.5"
          />
          <path
            class="grant-check"
            d="M42 60l13 13 24-26"
            stroke="var(--accent-bright)"
            stroke-width="4"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
        <p class="grant-title">ACCESO CONCEDIDO</p>
        <p class="grant-sub">Estableciendo sesión segura…</p>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'

const router = useRouter()
const auth = useAuthStore()

/* ── reactive form state ── */
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

const reduceMotion =
  typeof window !== 'undefined' &&
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

/* ── live clock in the terminal bar ── */
const clock = ref('')
let clockTimer = null
function tick() {
  clock.value = new Date().toLocaleTimeString('es-ES', { hour12: false })
}

/* ── boot diagnostics sequence ── */
const bootLines = [
  'init secure channel',
  'handshake TLS 1.3',
  'vault integrity check',
  'identity module ready',
]
const booting = ref(!reduceMotion)
const bootShown = ref([])
let bootTimers = []

/* ── brand glitch tease ── */
const glitching = ref(false)
let glitchTimer = null

/* ── cursor parallax tilt + spotlight ── */
const tilt = reactive({ rx: 0, ry: 0, mx: 50, my: 50 })
let rafId = null
function onPointerMove(e) {
  if (reduceMotion) return
  const { innerWidth: w, innerHeight: h } = window
  const nx = e.clientX / w - 0.5
  const ny = e.clientY / h - 0.5
  if (rafId) cancelAnimationFrame(rafId)
  rafId = requestAnimationFrame(() => {
    tilt.ry = nx * 9
    tilt.rx = -ny * 9
    tilt.mx = (e.clientX / w) * 100
    tilt.my = (e.clientY / h) * 100
  })
}
function resetTilt() {
  tilt.rx = 0
  tilt.ry = 0
}
const cardStyle = computed(() => ({
  '--rx': tilt.rx + 'deg',
  '--ry': tilt.ry + 'deg',
  '--mx': tilt.mx + '%',
  '--my': tilt.my + '%',
}))

/* ── live encryption visualization ──
   Derives a deterministic 24-char hex digest from the password, then
   briefly scrambles before settling — evokes real-time encryption. */
const HEX = '0123456789abcdef'
const cipherText = ref('— — — — — — — —'.replace(/ /g, ''))
let scrambleRaf = null
let scrambleFrames = 0

function digest(str) {
  // simple, fast rolling hash → 24 hex chars (visual only, never sent)
  const out = []
  let h = 0x811c9dc5
  for (let i = 0; i < 24; i++) {
    const c = str.charCodeAt(i % Math.max(str.length, 1)) || (i * 7 + 13)
    h ^= c + i * 31
    h = (h * 0x01000193) >>> 0
    out.push(HEX[(h >>> (i % 24)) & 15])
  }
  return out.join('')
}

function renderCipher() {
  if (!password.value.length) {
    cipherText.value = '························'
    return
  }
  const target = digest(password.value)
  if (reduceMotion || scrambleFrames <= 0) {
    cipherText.value = target
    return
  }
  // scramble: random hex blended toward the settled digest
  const progress = 1 - scrambleFrames / 8
  cipherText.value = target
    .split('')
    .map((ch, i) => (Math.random() < progress ? ch : HEX[(Math.random() * 16) | 0]))
    .join('')
  scrambleFrames--
  scrambleRaf = requestAnimationFrame(renderCipher)
}

function scramble() {
  if (reduceMotion) {
    renderCipher()
    return
  }
  if (scrambleRaf) cancelAnimationFrame(scrambleRaf)
  scrambleFrames = 8
  renderCipher()
}

/* ── caps lock detection ── */
function checkCaps(e) {
  if (typeof e.getModifierState === 'function') {
    capsOn.value = e.getModifierState('CapsLock')
  }
}

/* ── submit ── */
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
    await auth.login(un, pw)
    granted.value = true
    const delay = reduceMotion ? 300 : 1500
    setTimeout(() => router.push('/hub'), delay)
  } catch (err) {
    showAlert(err.message || 'Error desconocido.', 'error')
    if (err.message?.includes('Credenciales')) {
      usernameError.value = true
      passwordError.value = true
      password.value = ''
      renderCipher()
    }
    loading.value = false
  }
}

function showAlert(msg, type = 'error') {
  alertMsg.value = msg
  alertType.value = type
}

/* ── lifecycle ── */
onMounted(() => {
  tick()
  clockTimer = setInterval(tick, 1000)
  renderCipher()

  // Si la sesión terminó por un cambio de contraseña, avisar de forma destacada.
  if (auth.takeSessionEndReason() === 'password_changed') {
    showAlert(
      'Tu contraseña ha cambiado. Inicia sesión de nuevo con la contraseña actual.',
      'warning',
    )
  }

  if (booting.value) {
    bootLines.forEach((line, i) => {
      bootTimers.push(
        setTimeout(() => bootShown.value.push(line), 180 + i * 230)
      )
    })
    bootTimers.push(
      setTimeout(() => {
        booting.value = false
        document.getElementById('username')?.focus()
      }, 180 + bootLines.length * 230 + 280)
    )
  }

  // periodic, subtle brand glitch
  if (!reduceMotion) {
    glitchTimer = setInterval(() => {
      glitching.value = true
      setTimeout(() => (glitching.value = false), 320)
    }, 6500)
  }
})

onBeforeUnmount(() => {
  clearInterval(clockTimer)
  clearInterval(glitchTimer)
  bootTimers.forEach(clearTimeout)
  if (rafId) cancelAnimationFrame(rafId)
  if (scrambleRaf) cancelAnimationFrame(scrambleRaf)
})

/* ── decorative constellation (computed once) ── */
const nodes = Array.from({ length: 9 }, () => ({
  x: 8 + Math.random() * 84,
  y: 8 + Math.random() * 84,
  r: 1.2 + Math.random() * 1.8,
  delay: Math.random() * 4,
}))
const links = [
  [0, 1], [1, 2], [2, 4], [4, 3], [3, 0],
  [4, 5], [5, 6], [6, 7], [7, 8], [8, 5],
]
</script>

<style scoped>
/* ════════ Stage ════════ */
.login-stage {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1.5rem;
  overflow: hidden;
  background:
    radial-gradient(ellipse at 50% 0%, #14130f 0%, var(--bg) 55%);
  perspective: 1400px;
}

/* ════════ Ambient orbs ════════ */
.bg-orbs { position: fixed; inset: 0; z-index: 0; pointer-events: none; }
.orb {
  position: absolute;
  border-radius: 50%;
  filter: blur(140px);
  animation: orb-drift 26s ease-in-out infinite;
}
.orb--gold {
  width: 640px; height: 640px; top: -22%; left: -14%;
  background: radial-gradient(circle, rgba(212,160,74,0.18) 0%, transparent 70%);
}
.orb--green {
  width: 480px; height: 480px; bottom: -18%; right: -10%;
  background: radial-gradient(circle, rgba(76,183,130,0.10) 0%, transparent 70%);
  animation-delay: -10s;
}
.orb--blue {
  width: 420px; height: 420px; top: 40%; left: 58%;
  background: radial-gradient(circle, rgba(96,128,224,0.08) 0%, transparent 70%);
  animation-delay: -18s;
}
@keyframes orb-drift {
  0%, 100% { transform: translate(0,0) scale(1); }
  33%      { transform: translate(38px,-26px) scale(1.07); }
  66%      { transform: translate(-26px,30px) scale(0.95); }
}

/* ════════ Perspective grid ════════ */
.bg-grid {
  position: fixed; inset: -50%; z-index: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(212,160,74,0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(212,160,74,0.04) 1px, transparent 1px);
  background-size: 58px 58px;
  transform: perspective(620px) rotateX(62deg);
  animation: grid-drift 22s linear infinite;
  mask-image: radial-gradient(ellipse at center, #000 12%, transparent 68%);
}
@keyframes grid-drift {
  from { transform: perspective(620px) rotateX(62deg) translateY(0); }
  to   { transform: perspective(620px) rotateX(62deg) translateY(58px); }
}

/* ════════ Radar ════════ */
.bg-radar {
  position: fixed; inset: 0; z-index: 0; pointer-events: none;
  display: flex; align-items: center; justify-content: center;
}
.radar-sweep {
  width: 130vmax; height: 130vmax; border-radius: 50%;
  border: 1px solid rgba(212,160,74,0.04);
  position: relative;
  animation: radar-rotate 14s linear infinite;
}
.radar-sweep::before {
  content: ''; position: absolute; inset: 0; border-radius: 50%;
  background: conic-gradient(from 0deg, rgba(212,160,74,0.10), transparent 22%);
}
.radar-sweep::after {
  content: ''; position: absolute; inset: 22%; border-radius: 50%;
  border: 1px solid rgba(212,160,74,0.04);
}
@keyframes radar-rotate { to { transform: rotate(360deg); } }

/* ════════ Scanlines ════════ */
.bg-scanlines {
  position: fixed; inset: 0; z-index: 1; pointer-events: none; opacity: 0.35;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.16) 2px, rgba(0,0,0,0.16) 4px);
}

/* ════════ Constellation ════════ */
.bg-constellation {
  position: fixed; inset: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none;
}
.bg-constellation line { stroke: rgba(212,160,74,0.07); stroke-width: 1; }
.bg-constellation circle {
  fill: rgba(232,188,106,0.55);
  animation: node-twinkle 4s ease-in-out infinite;
}
@keyframes node-twinkle {
  0%, 100% { opacity: 0.2; }
  50%      { opacity: 0.9; }
}

/* ════════ Cursor spotlight ════════ */
.spotlight {
  position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background: radial-gradient(420px circle at var(--mx, 50%) var(--my, 50%), rgba(212,160,74,0.06), transparent 65%);
  transition: background 0.18s ease-out;
}

/* ════════ Watermark ════════ */
.watermark {
  position: fixed; top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  z-index: 0; pointer-events: none; text-align: center; user-select: none;
}
.watermark-text {
  display: block; font-family: var(--font-display);
  font-size: clamp(11rem, 34vw, 27rem); font-weight: 800; line-height: 0.82;
  letter-spacing: -0.04em; color: transparent;
  -webkit-text-stroke: 1px rgba(212,160,74,0.06);
  opacity: 0.4; animation: breathe 7s ease-in-out infinite;
}
.watermark-sub {
  display: block; font-family: var(--font-mono);
  font-size: clamp(0.6rem, 1vw, 0.9rem); letter-spacing: 0.85em;
  color: rgba(212,160,74,0.09); margin-top: 1rem; text-indent: 0.85em;
}
@keyframes breathe {
  0%, 100% { opacity: 0.28; transform: translate(-50%,-50%) scale(1); }
  50%      { opacity: 0.46; transform: translate(-50%,-50%) scale(1.025); }
}

/* ════════ Console card ════════ */
.console {
  position: relative; z-index: 2; width: 100%; max-width: 440px;
  background: rgba(17, 18, 24, 0.72);
  border: 1px solid var(--border-solid);
  border-radius: 16px; overflow: hidden;
  backdrop-filter: blur(26px) saturate(1.25);
  box-shadow:
    0 40px 90px rgba(0,0,0,0.55),
    0 0 0 1px rgba(255,255,255,0.03) inset,
    0 1px 0 rgba(255,255,255,0.05) inset;
  transform: rotateX(var(--rx, 0deg)) rotateY(var(--ry, 0deg));
  transform-style: preserve-3d;
  transition: transform 0.3s cubic-bezier(0.16,1,0.3,1);
  animation: console-enter 1s cubic-bezier(0.16,1,0.3,1) both;
}
@keyframes console-enter {
  from { opacity: 0; transform: translateY(34px) scale(0.96) rotateX(8deg); }
  to   { opacity: 1; transform: translateY(0) scale(1) rotateX(var(--rx,0)) rotateY(var(--ry,0)); }
}

/* moving sheen that follows cursor */
.console-sheen {
  position: absolute; inset: 0; z-index: 3; pointer-events: none; border-radius: 16px;
  background: radial-gradient(300px circle at var(--mx,50%) var(--my,50%), rgba(232,188,106,0.08), transparent 60%);
  opacity: 0.9; mix-blend-mode: screen;
}
/* animated gradient edge */
.console-edge {
  position: absolute; inset: -1px; z-index: 1; border-radius: 16px; padding: 1px;
  pointer-events: none;
  background: linear-gradient(135deg, rgba(212,160,74,0.5), transparent 30%, transparent 70%, rgba(212,160,74,0.5));
  background-size: 300% 300%;
  animation: edge-flow 7s ease infinite;
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor; mask-composite: exclude;
  opacity: 0.55;
}
@keyframes edge-flow {
  0%, 100% { background-position: 0% 50%; }
  50%      { background-position: 100% 50%; }
}

/* ════════ Terminal bar ════════ */
.term-bar {
  position: relative; z-index: 4;
  display: flex; align-items: center; gap: 0.7rem;
  padding: 0.65rem 1rem;
  background: rgba(255,255,255,0.018);
  border-bottom: 1px solid var(--border-solid);
}
.term-dots { display: flex; gap: 5px; }
.d { width: 8px; height: 8px; border-radius: 50%; box-shadow: 0 0 7px currentColor; }
.d-r { background: #d96c6c; color: #d96c6c; }
.d-y { background: #d4a04a; color: #d4a04a; }
.d-g { background: #4cb782; color: #4cb782; }
.term-path { flex: 1; font-family: var(--font-mono); font-size: 0.68rem; color: var(--text-dim); }
.term-clock {
  font-family: var(--font-mono); font-size: 0.68rem; color: var(--accent);
  letter-spacing: 0.06em; opacity: 0.75;
  font-variant-numeric: tabular-nums;
}

/* ════════ Boot diagnostics ════════ */
.boot {
  position: absolute; inset: 0; z-index: 6;
  background: rgba(13,14,18,0.94);
  backdrop-filter: blur(8px);
  padding: 3.2rem 2rem; display: flex; flex-direction: column; gap: 0.55rem;
  font-family: var(--font-mono); font-size: 0.78rem;
}
.boot-line, .boot-cursor {
  display: flex; align-items: center; gap: 0.55rem; color: var(--text-dim);
  animation: boot-in 0.3s ease both;
}
.boot-mark { color: var(--accent); }
.boot-ok {
  margin-left: auto; color: var(--success);
  font-size: 0.62rem; letter-spacing: 0.15em;
}
.boot-cursor .caret { color: var(--accent); animation: blink 1s step-end infinite; }
@keyframes boot-in { from { opacity: 0; transform: translateX(-6px); } to { opacity: 1; transform: none; } }
.boot-leave-active { transition: opacity 0.4s ease, transform 0.4s ease; }
.boot-leave-to { opacity: 0; transform: scale(1.02); }

/* ════════ Body ════════ */
.console-body { position: relative; z-index: 2; padding: 2.4rem 2.25rem 1.7rem; }

/* Brand */
.brand {
  display: flex; align-items: center; justify-content: center; gap: 0.35rem;
  margin-bottom: 1.1rem;
  animation: fade-up 0.7s 0.15s cubic-bezier(0.16,1,0.3,1) both;
}
.brand-bracket { color: var(--accent); font-size: 1.8rem; font-weight: 300; opacity: 0.45; font-family: var(--font-mono); }
.brand-mark {
  position: relative; color: var(--text);
  font-family: var(--font-display); font-size: 2.1rem; font-weight: 800; letter-spacing: 2px;
}
.brand-mark::after {
  content: attr(data-text); position: absolute; left: 0; top: 0; color: transparent;
  -webkit-text-stroke: 1px rgba(212,160,74,0.18); transform: translate(2px,2px); pointer-events: none;
}
.brand-mark.glitch { animation: glitch 0.32s steps(2) both; }
@keyframes glitch {
  0%   { text-shadow: 2px 0 #d96c6c, -2px 0 #4cb782; transform: translateX(0); }
  25%  { text-shadow: -2px 0 #d96c6c, 2px 0 #6080e0; transform: translateX(1px); }
  50%  { text-shadow: 2px 0 #4cb782, -2px 0 #d4a04a; transform: translateX(-1px); }
  100% { text-shadow: none; transform: none; }
}
.brand-shield {
  color: var(--accent); width: 22px; height: 22px; margin-left: 0.4rem; opacity: 0.8;
  filter: drop-shadow(0 0 6px rgba(212,160,74,0.4));
}

/* Title */
.title { text-align: center; font-family: var(--font-display); margin-bottom: 0.4rem; animation: fade-up 0.7s 0.25s cubic-bezier(0.16,1,0.3,1) both; }
.title-main { display: block; font-size: 1.05rem; font-weight: 600; color: var(--text); letter-spacing: 0.03em; }
.title-tag {
  display: inline-block; margin-top: 0.45rem; font-family: var(--font-mono);
  font-size: 0.6rem; font-weight: 500; letter-spacing: 0.28em; text-transform: uppercase;
  color: var(--accent);
  padding: 0.2rem 0.6rem; border: 1px solid rgba(212,160,74,0.22); border-radius: 100px;
  background: rgba(212,160,74,0.05);
}
.subtitle {
  text-align: center; font-size: 0.8rem; color: var(--text-dim);
  margin: 0.4rem 0 1.6rem; animation: fade-up 0.7s 0.35s cubic-bezier(0.16,1,0.3,1) both;
}
@keyframes fade-up { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }

/* ════════ Alert ════════ */
.alert {
  display: flex; align-items: flex-start; gap: 0.5rem;
  border-radius: 9px; padding: 0.7rem 0.9rem; font-size: 0.8rem;
  margin-bottom: 1.1rem; font-family: var(--font-body);
}
.alert svg { flex-shrink: 0; margin-top: 1px; }
.alert-error { background: rgba(217,108,108,0.07); border: 1px solid rgba(217,108,108,0.22); color: #e09090; box-shadow: 0 0 22px rgba(217,108,108,0.07); }
.alert-success { background: rgba(76,183,130,0.07); border: 1px solid rgba(76,183,130,0.22); color: #6ed9a0; box-shadow: 0 0 22px rgba(76,183,130,0.07); }
.alert-warning { background: rgba(212,160,74,0.08); border: 1px solid rgba(212,160,74,0.28); color: #e0b060; box-shadow: 0 0 22px rgba(212,160,74,0.08); }
.alert-enter-active { transition: opacity 0.35s ease, transform 0.35s ease; }
.alert-enter-from { opacity: 0; transform: translateY(-6px); }

/* ════════ Fields ════════ */
form { animation: fade-up 0.7s 0.45s cubic-bezier(0.16,1,0.3,1) both; }
.field { margin-bottom: 1.15rem; }
.field label {
  display: flex; align-items: center; gap: 0.25rem;
  font-size: 0.68rem; font-weight: 600; color: var(--text-dim);
  margin-bottom: 0.45rem; text-transform: uppercase; letter-spacing: 0.1em;
  transition: color 0.25s ease; font-family: var(--font-mono);
}
.field.focused label { color: var(--accent); }
.field-cursor { color: var(--accent); opacity: 0; }
.field.focused .field-cursor { opacity: 1; animation: blink 1s step-end infinite; }
@keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0; } }

.caps-warn {
  margin-left: auto; font-size: 0.58rem; letter-spacing: 0.06em;
  color: #e0b060; text-transform: none; font-family: var(--font-mono);
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
  background: rgba(27, 29, 38, 0.6);
  border: 1px solid var(--border-solid); border-radius: 11px;
  color: var(--text); font-size: 0.92rem; font-family: var(--font-body); outline: none;
  transition: border-color 0.3s, box-shadow 0.3s, background 0.3s;
}
.field-box input::placeholder { color: var(--text-muted); opacity: 0.3; }
.field-box input:focus {
  border-color: rgba(212,160,74,0.45);
  background: rgba(27,29,38,0.9);
  box-shadow: 0 0 0 3px rgba(212,160,74,0.09), 0 6px 22px rgba(0,0,0,0.25);
}
.field-box input.has-error {
  border-color: rgba(217,108,108,0.55);
  box-shadow: 0 0 0 3px rgba(217,108,108,0.09);
  animation: shake 0.4s ease-in-out;
}
.field-box input:disabled { opacity: 0.4; cursor: not-allowed; }
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
.reveal:hover:not(:disabled) { color: var(--accent); background: rgba(212,160,74,0.08); }
.reveal:disabled { cursor: not-allowed; opacity: 0.4; }

/* ════════ Cipher strip ════════ */
.cipher {
  display: flex; align-items: center; gap: 0.6rem;
  margin-top: 0.5rem; padding: 0 0.2rem;
  font-family: var(--font-mono); font-size: 0.62rem;
  opacity: 0.5; transition: opacity 0.3s ease;
}
.cipher.active { opacity: 1; }
.cipher-tag {
  display: inline-flex; align-items: center; gap: 0.35rem;
  color: var(--text-muted); letter-spacing: 0.08em; white-space: nowrap;
  transition: color 0.3s ease;
}
.cipher.active .cipher-tag { color: var(--success); }
.cipher-lock {
  width: 5px; height: 5px; border-radius: 50%; background: var(--text-muted);
  transition: background 0.3s ease;
}
.cipher.active .cipher-lock {
  background: var(--success); box-shadow: 0 0 7px var(--success);
  animation: live-pulse 1.6s ease-in-out infinite;
}
.cipher-stream {
  flex: 1; overflow: hidden; text-overflow: clip; white-space: nowrap;
  color: rgba(212,160,74,0.55); letter-spacing: 0.18em;
  mask-image: linear-gradient(90deg, #000 78%, transparent);
}
@keyframes live-pulse { 0%,100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.7); } }

/* ════════ Submit ════════ */
.submit {
  position: relative; overflow: hidden;
  width: 100%; margin-top: 0.7rem; padding: 0.9rem;
  display: flex; align-items: center; justify-content: center; gap: 0.5rem;
  background: linear-gradient(135deg, var(--accent), #c08a30);
  color: #0b0c10; font-weight: 700; font-size: 0.9rem; letter-spacing: 0.03em;
  font-family: var(--font-body); border: none; border-radius: 11px; cursor: pointer;
  box-shadow: 0 6px 24px rgba(212,160,74,0.28), 0 0 0 1px rgba(212,160,74,0.18) inset;
  transition: transform 0.25s cubic-bezier(0.16,1,0.3,1), box-shadow 0.25s, opacity 0.2s;
}
.submit:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 10px 34px rgba(212,160,74,0.4), 0 0 0 1px rgba(212,160,74,0.25) inset; }
.submit:hover:not(:disabled) .submit-arrow { transform: translateX(4px); }
.submit:active:not(:disabled) { transform: translateY(0); }
.submit:disabled { opacity: 0.55; cursor: not-allowed; }
.submit-label, .submit-arrow { position: relative; z-index: 1; }
.submit-arrow { transition: transform 0.25s ease; }
.submit.loading .submit-label, .submit.loading .submit-arrow { opacity: 0; }
.submit-shine {
  position: absolute; top: 0; left: -100%; width: 55%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,0.25), transparent);
  transform: skewX(-20deg);
}
.submit:hover:not(:disabled) .submit-shine { animation: shine 0.85s ease forwards; }
@keyframes shine { to { left: 160%; } }
.submit-spin {
  position: absolute; width: 20px; height: 20px;
  border: 2.5px solid rgba(11,12,16,0.18); border-top-color: #0b0c10; border-radius: 50%;
  opacity: 0; animation: seq-spin 0.7s linear infinite;
}
.submit.loading .submit-spin { opacity: 1; }
@keyframes seq-spin { to { transform: rotate(360deg); } }

/* ════════ Footer ════════ */
.console-foot {
  display: flex; align-items: center; justify-content: space-between;
  margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border);
  font-family: var(--font-mono); font-size: 0.62rem; color: var(--text-muted);
  animation: fade-up 0.7s 0.6s cubic-bezier(0.16,1,0.3,1) both;
}
.foot-pulse { display: inline-flex; align-items: center; gap: 0.4rem; }
.foot-pulse i {
  width: 5px; height: 5px; border-radius: 50%; background: var(--success);
  box-shadow: 0 0 6px var(--success); animation: live-pulse 2s ease-in-out infinite;
}
.foot-ver { opacity: 0.7; letter-spacing: 0.04em; }

/* ════════ Access granted overlay ════════ */
.grant-screen {
  position: fixed; inset: 0; z-index: 20;
  display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.4rem;
  background: radial-gradient(ellipse at center, rgba(20,19,15,0.97), rgba(11,12,16,0.99));
  backdrop-filter: blur(10px);
}
.grant-shield { width: 132px; height: 132px; filter: drop-shadow(0 0 24px rgba(212,160,74,0.5)); }
.grant-shield-body { stroke-dasharray: 360; stroke-dashoffset: 360; animation: draw 0.7s ease forwards; }
.grant-check { stroke-dasharray: 80; stroke-dashoffset: 80; animation: draw 0.4s 0.55s ease forwards; }
@keyframes draw { to { stroke-dashoffset: 0; } }
.grant-title {
  margin-top: 0.8rem; font-family: var(--font-display); font-weight: 800;
  font-size: 1.5rem; letter-spacing: 0.16em; color: var(--accent-bright);
  opacity: 0; animation: fade-up 0.5s 0.85s ease forwards;
  text-shadow: 0 0 28px rgba(212,160,74,0.5);
}
.grant-sub {
  font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-dim); letter-spacing: 0.1em;
  opacity: 0; animation: fade-up 0.5s 1.05s ease forwards;
}
.grant-enter-active { transition: opacity 0.35s ease; }
.grant-enter-from { opacity: 0; }
.grant-leave-active { transition: opacity 0.4s ease; }
.grant-leave-to { opacity: 0; }

/* ════════ Responsive ════════ */
@media (max-width: 640px) {
  .login-stage { padding: 1rem; }
  .console { max-width: 100%; }
  .console-body { padding: 2rem 1.5rem 1.6rem; }
  .watermark-text { font-size: 9rem; opacity: 0.16; }
  .watermark-sub { display: none; }
}

/* ════════ Reduced motion ════════ */
@media (prefers-reduced-motion: reduce) {
  .orb, .bg-grid, .radar-sweep, .radar-sweep::before, .watermark-text,
  .console-edge, .bg-constellation circle, .brand-mark.glitch,
  .cipher.active .cipher-lock, .foot-pulse i, .submit-shine, .status-pulse {
    animation: none !important;
  }
  .console { animation: none !important; transform: none !important; }
  .spotlight, .console-sheen { display: none; }
  * { scroll-behavior: auto; }
}
</style>
