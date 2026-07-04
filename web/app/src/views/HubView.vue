<template>
  <div
    class="hub-stage"
    :style="stageStyle"
    @mousemove="onPointerMove"
  >
    <!-- ───────── Ambient background (shared language with login) ───────── -->
    <div class="bg-orbs" aria-hidden="true">
      <span class="orb orb--gold"></span>
      <span class="orb orb--green"></span>
      <span class="orb orb--blue"></span>
    </div>
    <div class="bg-grid" aria-hidden="true"></div>
    <div class="bg-radar" aria-hidden="true"><span class="radar-sweep"></span></div>
    <div class="bg-scanlines" aria-hidden="true"></div>
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
    <div class="watermark" aria-hidden="true"><span>Ellysia</span></div>
    <div class="spotlight" aria-hidden="true"></div>

    <!-- Profile trigger -->
    <button class="profile-trigger" @click="profileOpen = !profileOpen" aria-label="Perfil">
      <span class="profile-ring" aria-hidden="true"></span>
      <div class="profile-avatar-mini">{{ profileInitials }}</div>
    </button>

    <!-- Profile dropdown -->
    <Transition name="drop">
      <div v-if="profileOpen" class="profile-drop" ref="dropRef">
        <div class="drop-header">
          <div class="drop-avatar">{{ profileInitials }}</div>
          <div class="drop-name-wrap">
            <h3 v-if="profileLoaded" class="drop-name">{{ profileName }}</h3>
            <div v-else class="skeleton-line"></div>
            <span class="drop-role"><span class="role-pulse"></span>{{ roleLabel }}</span>
          </div>
        </div>
        <nav class="drop-menu">
          <router-link to="/profile" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            Perfil
          </router-link>
          <router-link v-if="auth.isAdmin" to="/users" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
            Usuarios
          </router-link>
          <router-link v-if="auth.isAdmin" to="/config" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            Configuración
          </router-link>
          <router-link v-if="auth.isAdmin" to="/queue" class="drop-item" @click="profileOpen = false">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="8" y1="9" x2="16" y2="9"/><line x1="8" y1="13" x2="14" y2="13"/></svg>
            Cola de Tareas
          </router-link>
          <div class="drop-divider"></div>
          <button class="drop-item drop-item--danger" @click="logout">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Cerrar sesión
          </button>
        </nav>
      </div>
    </Transition>

    <Transition name="fade">
      <div v-if="profileOpen" class="drop-backdrop" @click="profileOpen = false"></div>
    </Transition>

    <!-- Main dashboard -->
    <main class="hub-dashboard">
      <!-- Left column -->
      <section class="hub-left" style="animation-delay: 0.1s">
        <div class="hero-block">
          <div class="hero-head">
            <img :src="ellysiaLogo" alt="Ellysia" class="hero-logo-img" />
            <div class="hero-head-body">
              <div class="hero-logo">
                <span class="hero-bracket">[</span>
                <span class="hero-text" :class="{ glitch: glitching }" data-text="Ellysia">Ellysia</span>
                <span class="hero-bracket">]</span>
                <span class="hero-shield" aria-hidden="true">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
                    <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" />
                    <path d="M9 12l2 2 4-4" stroke-width="2" />
                  </svg>
                </span>
              </div>
              <div class="hero-sub">
                <span class="hero-sub-badge">Security Operations Platform</span>
              </div>
            </div>
          </div>

          <!-- Clearance strip — operator + role + live clock -->
          <div class="clearance-strip">
            <span class="clr-seg clr-op">
              <span class="clr-key">OPERADOR</span>
              <span class="clr-val">{{ profileLoaded ? profileName : '············' }}</span>
            </span>
            <span class="clr-seg clr-role" :data-role="roleLabel">
              <span class="clr-dot"></span>{{ roleLabel }}
            </span>
            <span class="clr-seg clr-clock">{{ clock }}</span>
          </div>

          <div class="hero-divider"></div>
        </div>

        <div class="hub-signal" style="animation-delay: 0.2s">
          <SignalStream />
        </div>

        <div class="hub-quickstats" style="animation-delay: 0.3s">
          <a href="https://github.com/ProjectEllysia/Ellysia" target="_blank" rel="noopener noreferrer" class="stat-tile stat-tile--link">
            <div class="stat-icon stat-icon--github">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
              </svg>
            </div>
            <div class="stat-body">
              <span class="stat-value">ProjectEllysia/Ellysia</span>
              <span class="stat-label">GitHub</span>
            </div>
          </a>
          <div class="stat-tile">
            <div class="stat-icon stat-icon--status">
              <span class="status-beacon"></span>
            </div>
            <div class="stat-body">
              <span class="stat-value">Operativo</span>
              <span class="stat-label">{{ activeModules }}/4 módulos</span>
            </div>
          </div>
          <div class="stat-tile">
            <div class="stat-icon stat-icon--version">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
              </svg>
            </div>
            <div class="stat-body">
              <span class="stat-value">v{{ appVersion }}</span>
              <span class="stat-label">Build</span>
            </div>
          </div>
        </div>
      </section>

      <!-- Right column: module cards grid -->
      <section class="hub-right">
        <router-link
          to="/sentinel" class="card card-sentinel" style="animation-delay: 0.25s"
          @mousemove="tiltCard" @mouseleave="resetCard"
        >
          <div class="card-bg"></div>
          <div class="card-edge"></div>
          <div class="card-sheen"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="sentinelIcon" alt="Sentinel" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Sentinel</h2>
            <p class="card-desc">Escaneo de red, análisis de vulnerabilidades y generación de informes con IA.</p>
            <div class="card-meta">
              <span class="card-status status-active"><span class="status-dot"></span>Operativo</span>
              <span class="card-info">3 escáneres</span>
            </div>
          </div>
          <span class="card-go" aria-hidden="true">→</span>
        </router-link>

        <router-link
          to="/aegis" class="card card-aegis" style="animation-delay: 0.33s"
          @mousemove="tiltCard" @mouseleave="resetCard"
        >
          <div class="card-bg"></div>
          <div class="card-edge"></div>
          <div class="card-sheen"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="aegisIcon" alt="Aegis" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Aegis</h2>
            <p class="card-desc">Newsletter de inteligencia de seguridad generada por IA para concienciación.</p>
            <div class="card-meta">
              <span class="card-status status-active"><span class="status-dot"></span>Operativo</span>
              <span class="card-info">Exporta MD / JSON</span>
            </div>
          </div>
          <span class="card-go" aria-hidden="true">→</span>
        </router-link>

        <router-link
          to="/iris" class="card card-iris" style="animation-delay: 0.41s"
          @mousemove="tiltCard" @mouseleave="resetCard"
        >
          <div class="card-bg"></div>
          <div class="card-edge"></div>
          <div class="card-sheen"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="irisIcon" alt="Iris" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Iris</h2>
            <p class="card-desc">Análisis de cabeceras de correo para detectar phishing mediante reglas de verificación.</p>
            <div class="card-meta">
              <span class="card-status status-active"><span class="status-dot"></span>Operativo</span>
              <span class="card-info">SPF, DKIM y DMARC</span>
            </div>
          </div>
          <span class="card-go" aria-hidden="true">→</span>
        </router-link>

        <router-link
          to="/acheron" class="card card-acheron" style="animation-delay: 0.49s"
          @mousemove="tiltCard" @mouseleave="resetCard"
        >
          <div class="card-bg"></div>
          <div class="card-edge"></div>
          <div class="card-sheen"></div>
          <div class="card-accent"></div>
          <div class="card-icon">
            <img :src="acheronIcon" alt="Acheron" class="card-icon-img" />
          </div>
          <div class="card-body">
            <h2 class="card-title">Acheron</h2>
            <p class="card-desc">Bóveda cifrada de credenciales y tarjetas para tu organización.</p>
            <div class="card-meta">
              <span class="card-status status-active"><span class="status-dot"></span>Operativo</span>
              <span class="card-info">Cifrado en el navegador</span>
            </div>
          </div>
          <span class="card-go" aria-hidden="true">→</span>
        </router-link>
      </section>
    </main>

    <footer class="hub-footer">
      <span class="foot-pulse"><i></i>Enlace cifrado activo</span>
      <span class="foot-text">Ellysia Platform — Security Operations Suite</span>
    </footer>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import { useProfileStore } from '@/stores/profileStore'
import SignalStream from '@/components/shared/SignalStream.vue'

import sentinelIcon from '@/assets/images/sentinel/Sentinel-Turqoise-BgN.png'
import aegisIcon from '@/assets/images/aegis/Ellysia-Aegis-Blue-BgN.png'
import irisIcon from '@/assets/images/iris/Iris-Red-BgN.png'
import acheronIcon from '@/assets/images/acheron/Acheron-Purple-BgN.png'
import ellysiaLogo from '@/assets/images/ellysia/Ellysia-BgN.png'

const auth = useAuthStore()
const profileStore = useProfileStore()

const profileOpen = ref(false)
const dropRef = ref(null)

const appVersion = ref('…')

const reduceMotion =
  typeof window !== 'undefined' &&
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

const activeModules = 4

const profileName = computed(() => {
  const fn = profileStore.profile.first_name
  const ln = profileStore.profile.last_name
  if (fn || ln) return `${fn} ${ln}`.trim()
  return auth.username() || 'Usuario'
})

const profileLoaded = computed(() => !!profileStore.profile.username)

const roleLabel = computed(() => {
  const r = profileStore.profile.role || auth.role
  if (r === 'role_root') return 'Root'
  if (r === 'role_admin') return 'Admin'
  return 'Usuario'
})

const profileInitials = computed(() => {
  const parts = profileName.value.split(' ')
  return parts.length >= 2
    ? (parts[0][0] + parts[1][0]).toUpperCase()
    : (parts[0]?.[0] || 'U').toUpperCase()
})

/* ── Cursor-tracking spotlight (page level) ── */
const spot = ref({ x: 50, y: 50 })
const stageStyle = computed(() => ({ '--mx': spot.value.x + '%', '--my': spot.value.y + '%' }))
let spotRaf = null
function onPointerMove(e) {
  if (reduceMotion) return
  if (spotRaf) return
  spotRaf = requestAnimationFrame(() => {
    spot.value = {
      x: (e.clientX / window.innerWidth) * 100,
      y: (e.clientY / window.innerHeight) * 100,
    }
    spotRaf = null
  })
}

/* ── Per-card 3D tilt + sheen tracking ── */
function tiltCard(e) {
  if (reduceMotion) return
  const el = e.currentTarget
  const r = el.getBoundingClientRect()
  const px = (e.clientX - r.left) / r.width
  const py = (e.clientY - r.top) / r.height
  el.style.setProperty('--rx', (0.5 - py) * 7 + 'deg')
  el.style.setProperty('--ry', (px - 0.5) * 7 + 'deg')
  el.style.setProperty('--mx', px * 100 + '%')
  el.style.setProperty('--my', py * 100 + '%')
}
function resetCard(e) {
  const el = e.currentTarget
  el.style.setProperty('--rx', '0deg')
  el.style.setProperty('--ry', '0deg')
}

/* ── Live clock (echoes the login terminal bar) ── */
const clock = ref('')
let clockTimer = null
function tick() {
  clock.value = new Date().toLocaleTimeString('es-ES', { hour12: false })
}

/* ── Periodic brand glitch ── */
const glitching = ref(false)
let glitchTimer = null

let clickOutside = null

onMounted(() => {
  profileStore.loadProfile()
  tick()
  clockTimer = setInterval(tick, 1000)

  fetch('/system/say-hello')
    .then(r => r.json())
    .then(d => { if (d.version) appVersion.value = d.version })
    .catch(() => {})

  if (!reduceMotion) {
    glitchTimer = setInterval(() => {
      glitching.value = true
      setTimeout(() => (glitching.value = false), 320)
    }, 7000)
  }

  clickOutside = (e) => {
    const d = dropRef.value
    const t = document.querySelector('.profile-trigger')
    if (d && t && !d.contains(e.target) && !t.contains(e.target)) {
      profileOpen.value = false
    }
  }
  document.addEventListener('click', clickOutside)
})

onUnmounted(() => {
  if (clickOutside) document.removeEventListener('click', clickOutside)
  clearInterval(clockTimer)
  clearInterval(glitchTimer)
  if (spotRaf) cancelAnimationFrame(spotRaf)
})

function logout() {
  profileOpen.value = false
  auth.logout()
}

/* ── Decorative constellation (computed once) ── */
const nodes = Array.from({ length: 9 }, () => ({
  x: 6 + Math.random() * 88,
  y: 6 + Math.random() * 88,
  r: 1.2 + Math.random() * 1.8,
  delay: Math.random() * 4,
}))
const links = [
  [0, 1], [1, 2], [2, 4], [4, 3], [3, 0],
  [4, 5], [5, 6], [6, 7], [7, 8], [8, 5],
]
</script>

<style scoped>
.hub-stage {
  height: 100vh;
  display: flex;
  flex-direction: column;
  position: relative;
  overflow: hidden;
  background: radial-gradient(ellipse at 50% -10%, #14130f 0%, var(--bg) 55%);
}

/* ════════ Ambient background ════════ */
.bg-orbs { position: fixed; inset: 0; z-index: 0; pointer-events: none; }
.orb { position: absolute; border-radius: 50%; filter: blur(140px); animation: orb-drift 26s ease-in-out infinite; }
.orb--gold  { width: 640px; height: 640px; top: -24%; left: -12%; background: radial-gradient(circle, rgba(212,160,74,0.16) 0%, transparent 70%); }
.orb--green { width: 480px; height: 480px; bottom: -20%; right: 6%; background: radial-gradient(circle, rgba(76,183,130,0.09) 0%, transparent 70%); animation-delay: -10s; }
.orb--blue  { width: 440px; height: 440px; top: 30%; left: 48%; background: radial-gradient(circle, rgba(96,128,224,0.07) 0%, transparent 70%); animation-delay: -18s; }
@keyframes orb-drift {
  0%, 100% { transform: translate(0,0) scale(1); }
  33%      { transform: translate(38px,-26px) scale(1.07); }
  66%      { transform: translate(-26px,30px) scale(0.95); }
}

.bg-grid {
  position: fixed; inset: -50%; z-index: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(212,160,74,0.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(212,160,74,0.035) 1px, transparent 1px);
  background-size: 58px 58px;
  transform: perspective(620px) rotateX(62deg);
  animation: grid-drift 22s linear infinite;
  mask-image: radial-gradient(ellipse at center, #000 8%, transparent 60%);
}
@keyframes grid-drift {
  from { transform: perspective(620px) rotateX(62deg) translateY(0); }
  to   { transform: perspective(620px) rotateX(62deg) translateY(58px); }
}

.bg-radar { position: fixed; inset: 0; z-index: 0; pointer-events: none; display: flex; align-items: center; justify-content: center; }
.radar-sweep {
  width: 150vmax; height: 150vmax; border-radius: 50%;
  border: 1px solid rgba(212,160,74,0.03); position: relative;
  animation: radar-rotate 16s linear infinite;
}
.radar-sweep::before { content: ''; position: absolute; inset: 0; border-radius: 50%; background: conic-gradient(from 0deg, rgba(212,160,74,0.07), transparent 20%); }
.radar-sweep::after  { content: ''; position: absolute; inset: 28%; border-radius: 50%; border: 1px solid rgba(212,160,74,0.03); }
@keyframes radar-rotate { to { transform: rotate(360deg); } }

.bg-scanlines {
  position: fixed; inset: 0; z-index: 1; pointer-events: none; opacity: 0.25;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.14) 2px, rgba(0,0,0,0.14) 4px);
}

.bg-constellation { position: fixed; inset: 0; width: 100%; height: 100%; z-index: 0; pointer-events: none; }
.bg-constellation line { stroke: rgba(212,160,74,0.05); stroke-width: 1; }
.bg-constellation circle { fill: rgba(232,188,106,0.45); animation: node-twinkle 4s ease-in-out infinite; }
@keyframes node-twinkle { 0%, 100% { opacity: 0.15; } 50% { opacity: 0.7; } }

.watermark {
  position: fixed; top: 46%; left: 50%; transform: translate(-50%, -50%);
  z-index: 0; pointer-events: none; user-select: none;
}
.watermark span {
  font-family: var(--font-display); font-size: clamp(14rem, 40vw, 32rem);
  font-weight: 800; letter-spacing: -0.04em; color: transparent;
  -webkit-text-stroke: 1px rgba(212,160,74,0.04);
  opacity: 0.5; animation: breathe 7s ease-in-out infinite;
}
@keyframes breathe { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.6; } }

.spotlight {
  position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background: radial-gradient(500px circle at var(--mx, 50%) var(--my, 50%), rgba(212,160,74,0.05), transparent 62%);
  transition: background 0.2s ease-out;
}

/* ════════ Profile trigger ════════ */
.profile-trigger {
  position: fixed; top: 1rem; right: 1.25rem; z-index: 51;
  cursor: pointer; background: none; border: none; padding: 0;
  display: grid; place-items: center;
}
.profile-ring {
  position: absolute; inset: -4px; border-radius: 50%;
  border: 1px solid rgba(212,160,74,0.25);
  animation: ring-pulse 3s ease-in-out infinite;
}
@keyframes ring-pulse { 0%, 100% { opacity: 0.3; transform: scale(1); } 50% { opacity: 0.8; transform: scale(1.12); } }
.profile-avatar-mini {
  position: relative;
  width: 34px; height: 34px; border-radius: 50%;
  background: var(--accent-dim); border: 1.5px solid var(--border-med);
  color: var(--accent-bright); font-family: var(--font-body);
  font-size: 0.7rem; font-weight: 700;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.25s ease;
}
.profile-trigger:hover .profile-avatar-mini {
  border-color: var(--accent); box-shadow: 0 0 14px var(--accent-dim);
}

/* ════════ Profile dropdown ════════ */
.profile-drop {
  position: fixed; top: calc(1rem + 44px); right: 1.25rem; z-index: 51; width: 256px;
  background: rgba(17,18,24,0.92);
  backdrop-filter: blur(26px); -webkit-backdrop-filter: blur(26px);
  border: 1px solid var(--border-solid); border-radius: 13px; padding: 0.85rem;
  box-shadow: 0 24px 56px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.03) inset;
}
.drop-enter-active, .drop-leave-active { transition: opacity 0.14s ease, transform 0.14s ease; }
.drop-enter-from, .drop-leave-to { opacity: 0; transform: translateY(-6px); }
.drop-header {
  display: flex; align-items: center; gap: 0.65rem;
  padding-bottom: 0.75rem; border-bottom: 1px solid var(--border); margin-bottom: 0.45rem;
}
.drop-avatar {
  width: 40px; height: 40px; border-radius: 50%;
  background: var(--accent-dim); color: var(--accent-bright);
  font-size: 0.78rem; font-weight: 700; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  border: 1px solid var(--border-med);
}
.drop-name-wrap { flex: 1; min-width: 0; }
.drop-name { font-size: 0.9rem; font-weight: 600; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.drop-role {
  display: inline-flex; align-items: center; gap: 0.35rem;
  font-family: var(--font-mono); font-size: 0.66rem; color: var(--accent);
  letter-spacing: 0.06em; text-transform: uppercase;
}
.role-pulse { width: 5px; height: 5px; border-radius: 50%; background: var(--success); box-shadow: 0 0 6px var(--success); }
.skeleton-line {
  width: 100px; height: 14px; border-radius: 4px; background: var(--surface-2);
  animation: seq-shimmer 1.5s infinite; background-size: 200% 100%;
  background-image: linear-gradient(90deg, var(--surface-2) 25%, var(--surface-3) 50%, var(--surface-2) 75%);
}
.drop-menu { display: flex; flex-direction: column; gap: 0.15rem; }
.drop-item {
  display: flex; align-items: center; gap: 0.55rem;
  padding: 0.52rem 0.6rem; border-radius: 7px;
  color: var(--text-dim); font-size: 0.8rem; font-weight: 500;
  cursor: pointer; transition: all 0.15s ease; text-decoration: none;
  border: none; background: none; width: 100%; text-align: left;
}
.drop-item svg { width: 16px; height: 16px; flex-shrink: 0; opacity: 0.5; transition: opacity 0.15s ease; }
.drop-item:hover { background: rgba(212,160,74,0.07); color: var(--text); }
.drop-item:hover svg { opacity: 0.9; }
.drop-item--danger { color: var(--danger); }
.drop-item--danger:hover { background: var(--danger-dim); }
.drop-divider { height: 1px; background: var(--border); margin: 0.3rem 0; }
.drop-backdrop { position: fixed; inset: 0; z-index: 50; background: transparent; }
.fade-enter-active, .fade-leave-active { transition: opacity 0.15s ease; }
.fade-enter-from, .fade-leave-to { opacity: 0; }

/* ════════ Dashboard grid ════════ */
.hub-dashboard {
  flex: 1; min-height: 0;
  display: grid; grid-template-columns: 2fr 1fr; grid-template-rows: 1fr;
  gap: 3rem; max-width: 1700px; width: 100%; margin: 0 auto;
  padding: 2.5rem 3rem 0; position: relative; z-index: 2;
}

/* ════════ Left column ════════ */
.hub-left {
  display: flex; flex-direction: column; gap: 1.5rem;
  animation: seq-fade-up 0.7s ease-out backwards;
  min-width: 0; min-height: 0; overflow-y: auto;
}
.hero-block { display: flex; flex-direction: column; }
.hero-head { display: flex; align-items: center; gap: 1.2rem; }
.hero-head-body { display: flex; flex-direction: column; }
.hero-logo-img { height: 6rem; width: auto; display: block; flex-shrink: 0; filter: drop-shadow(0 0 18px rgba(212,160,74,0.2)); }
.hero-logo { display: flex; align-items: center; gap: 0.5rem; }
.hero-bracket { font-size: 4.2rem; font-weight: 200; font-family: var(--font-display); line-height: 1; color: var(--accent); text-shadow: 0 0 40px var(--accent-dim); }
.hero-text {
  position: relative; font-size: 4.2rem; font-weight: 800; font-family: var(--font-display);
  letter-spacing: 4px; line-height: 1;
  background: linear-gradient(135deg, var(--accent-bright) 0%, var(--text) 60%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
}
.hero-text.glitch { animation: glitch 0.32s steps(2) both; }
@keyframes glitch {
  0%   { text-shadow: 3px 0 #d96c6c, -3px 0 #4cb782; transform: translateX(0); }
  50%  { text-shadow: -3px 0 #6080e0, 3px 0 #d4a04a; transform: translateX(1px); }
  100% { text-shadow: none; transform: none; }
}
.hero-shield { color: var(--accent); width: 30px; height: 30px; margin-left: 0.5rem; opacity: 0.8; filter: drop-shadow(0 0 8px rgba(212,160,74,0.4)); }
.hero-sub { margin-top: 0.5rem; }
.hero-sub-badge {
  display: inline-block; padding: 0.3rem 0.9rem; border-radius: 20px;
  background: rgba(212,160,74,0.05); border: 1px solid rgba(212,160,74,0.18);
  font-size: 0.7rem; font-weight: 500; color: var(--accent);
  letter-spacing: 0.1em; text-transform: uppercase; font-family: var(--font-mono);
}

/* Clearance strip */
.clearance-strip {
  display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;
  margin-top: 1.25rem; font-family: var(--font-mono); font-size: 0.68rem;
}
.clr-seg {
  display: inline-flex; align-items: center; gap: 0.4rem;
  padding: 0.32rem 0.7rem; border-radius: 7px;
  background: rgba(255,255,255,0.02); border: 1px solid var(--border-med);
}
.clr-key { color: var(--text-muted); letter-spacing: 0.12em; }
.clr-val { color: var(--text); font-weight: 500; }
.clr-role { color: var(--accent); letter-spacing: 0.1em; text-transform: uppercase; }
.clr-role[data-role="Root"] { color: var(--danger); border-color: rgba(217,108,108,0.25); }
.clr-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; box-shadow: 0 0 7px currentColor; }
.clr-clock { color: var(--accent); letter-spacing: 0.08em; font-variant-numeric: tabular-nums; margin-left: auto; opacity: 0.8; }

.hero-divider { margin-top: 1.5rem; width: 100%; height: 1px; background: linear-gradient(90deg, var(--accent), transparent 80%); opacity: 0.35; }

.hub-signal { animation: seq-fade-up 0.7s ease-out backwards; }

/* Quick stats */
.hub-quickstats { display: flex; gap: 0.65rem; animation: seq-fade-up 0.7s ease-out backwards; }
.stat-tile {
  flex: 1; display: flex; align-items: center; gap: 0.55rem;
  padding: 0.65rem 0.8rem;
  background: rgba(17,18,24,0.55);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(255,255,255,0.05); border-radius: 10px;
  transition: all 0.3s ease;
}
.stat-tile:hover { border-color: rgba(212,160,74,0.25); background: rgba(17,18,24,0.78); transform: translateY(-2px); }
.stat-icon { width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.stat-icon svg { width: 15px; height: 15px; }
.stat-icon--version { background: rgba(212,160,74,0.12); color: var(--accent); }
.stat-icon--github  { background: rgba(255,255,255,0.06); color: var(--text-dim); }
.stat-icon--status  { background: rgba(76,183,130,0.12); }
.status-beacon { width: 9px; height: 9px; border-radius: 50%; background: var(--success); box-shadow: 0 0 10px var(--success); animation: live-pulse 1.8s ease-in-out infinite; }
@keyframes live-pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.7); } }
.stat-tile--link { text-decoration: none; color: inherit; cursor: pointer; }
.stat-body { display: flex; flex-direction: column; min-width: 0; }
.stat-value { font-family: var(--font-mono); font-size: 0.82rem; font-weight: 700; color: var(--text); line-height: 1.2; }
.stat-label { font-size: 0.58rem; font-weight: 500; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; font-family: var(--font-mono); }

/* ════════ Right column: module cards ════════ */
.hub-right {
  display: flex; flex-direction: column; gap: 1rem;
  overflow-y: auto; min-height: 0; padding: 0.5rem 0.4rem 0.5rem 0;
  perspective: 1100px;
}

.card {
  position: relative; overflow: hidden;
  background: rgba(17,18,24,0.6);
  backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
  border: 1px solid rgba(255,255,255,0.05); border-radius: 14px;
  padding: 1.5rem; text-decoration: none;
  display: flex; flex-direction: column; min-height: 260px;
  animation: seq-fade-up 0.6s ease-out backwards;
  transform: rotateX(var(--rx, 0deg)) rotateY(var(--ry, 0deg));
  transform-style: preserve-3d;
  transition: transform 0.35s cubic-bezier(0.16,1,0.3,1), border-color 0.3s ease, box-shadow 0.4s ease;
  cursor: pointer; isolation: isolate;
}

/* animated gold edge (shared language with login console) */
.card-edge {
  position: absolute; inset: -1px; z-index: 3; border-radius: 14px; padding: 1px;
  pointer-events: none;
  background: linear-gradient(135deg, rgba(212,160,74,0.5), transparent 30%, transparent 70%, rgba(212,160,74,0.5));
  background-size: 300% 300%;
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor; mask-composite: exclude;
  opacity: 0; transition: opacity 0.4s ease; animation: edge-flow 7s ease infinite;
}
@keyframes edge-flow { 0%, 100% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } }

/* cursor-tracking sheen */
.card-sheen {
  position: absolute; inset: 0; z-index: 2; pointer-events: none; border-radius: 14px;
  background: radial-gradient(260px circle at var(--mx, 50%) var(--my, 50%), rgba(232,188,106,0.09), transparent 60%);
  opacity: 0; transition: opacity 0.4s ease; mix-blend-mode: screen;
}

.card-accent { position: absolute; left: 0; top: 12%; bottom: 12%; width: 3px; border-radius: 0 3px 3px 0; transition: all 0.4s ease; z-index: 4; }
.card-bg { position: absolute; top: 0; right: 0; width: 200px; height: 200px; border-radius: 50%; opacity: 0; transition: opacity 0.5s ease; pointer-events: none; filter: blur(70px); z-index: -1; }

.card-sentinel .card-accent { background: #4cb782; box-shadow: 0 0 12px rgba(76,183,130,0.25); }
.card-sentinel .card-bg     { background: radial-gradient(circle, rgba(76,183,130,0.15) 0%, transparent 70%); }
.card-aegis .card-accent    { background: #6080e0; box-shadow: 0 0 12px rgba(96,128,224,0.25); }
.card-aegis .card-bg        { background: radial-gradient(circle, rgba(96,128,224,0.15) 0%, transparent 70%); }
.card-iris .card-accent     { background: #e07a5f; box-shadow: 0 0 12px rgba(224,122,95,0.25); }
.card-iris .card-bg         { background: radial-gradient(circle, rgba(224,122,95,0.15) 0%, transparent 70%); }
.card-acheron .card-accent  { background: #a07ac0; box-shadow: 0 0 12px rgba(160,122,192,0.15); }
.card-acheron .card-bg      { background: radial-gradient(circle, rgba(160,122,192,0.12) 0%, transparent 70%); }

.card:not(.card-disabled):hover {
  border-color: rgba(255,255,255,0.08);
  box-shadow: 0 28px 56px rgba(0,0,0,0.45), inset 4px 0 24px rgba(255,255,255,0.03);
}
.card:not(.card-disabled):hover .card-edge,
.card:not(.card-disabled):hover .card-sheen { opacity: 1; }
.card:not(.card-disabled):hover .card-accent { width: 4px; box-shadow: 0 0 20px currentColor; }
.card:not(.card-disabled):hover .card-bg { opacity: 1; }

.card-icon {
  width: 46px; height: 46px; border-radius: 11px;
  background: rgba(255,255,255,0.04);
  display: flex; align-items: center; justify-content: center;
  margin-bottom: 1rem; border: 1px solid rgba(255,255,255,0.06);
  transition: all 0.35s ease; position: relative; z-index: 1;
}
.card-icon-img { width: 100%; height: 100%; object-fit: contain; display: block; transition: transform 0.35s ease; }
.card:not(.card-disabled):hover .card-icon { border-color: rgba(212,160,74,0.2); box-shadow: 0 0 22px var(--accent-dim); background: rgba(255,255,255,0.06); }
.card:not(.card-disabled):hover .card-icon-img { transform: scale(1.1); }

.card-body { flex: 1; display: flex; flex-direction: column; position: relative; z-index: 1; }
.card-title { font-size: 1.55rem; font-weight: 700; color: var(--text); margin-bottom: 0.35rem; font-family: var(--font-display); letter-spacing: 0.02em; }
.card-desc { font-size: 1.1rem; color: var(--text-dim); line-height: 1.6; margin-bottom: 0.9rem; flex: 1; }
.card-meta { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; position: relative; z-index: 1; }
.card-status { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.2rem 0.65rem; border-radius: 5px; font-size: 0.9rem; font-weight: 600; letter-spacing: 0.02em; }
.status-dot { width: 5px; height: 5px; border-radius: 50%; background: currentColor; }
.status-active { background: var(--success-dim); color: var(--success); border: 1px solid rgba(76,183,130,0.15); }
.status-later { background: var(--warn-dim); color: var(--warn); border: 1px solid rgba(212,160,74,0.15); }
.card-info { font-size: 0.9rem; color: var(--text-muted); font-family: var(--font-mono); }

/* go arrow */
.card-go {
  position: absolute; right: 1.4rem; bottom: 1.4rem; z-index: 4;
  font-size: 1.3rem; color: var(--accent); opacity: 0;
  transform: translateX(-6px); transition: opacity 0.3s ease, transform 0.3s ease;
}
.card:not(.card-disabled):hover .card-go { opacity: 1; transform: translateX(0); }

.card-disabled { opacity: 0.38; pointer-events: none; cursor: default; }
.card-wip {
  position: absolute; top: 0; right: 0; display: flex; align-items: center; gap: 0.3rem;
  padding: 0.5rem 0.75rem; color: var(--text-muted); font-size: 0.9rem; font-weight: 500;
  border-radius: 0 14px 0 14px; background: rgba(255,255,255,0.025); pointer-events: none; z-index: 4;
}
.card-wip svg { width: 15px; height: 15px; }

/* ════════ Footer ════════ */
.hub-footer {
  display: flex; align-items: center; justify-content: space-between;
  padding: 1.1rem 3rem; max-width: 1700px; width: 100%; margin: 0 auto;
  font-family: var(--font-mono); font-size: 0.66rem; color: var(--text-muted);
  border-top: 1px solid var(--border); position: relative; z-index: 2; letter-spacing: 0.04em;
}
.foot-pulse { display: inline-flex; align-items: center; gap: 0.4rem; color: var(--text-dim); }
.foot-pulse i { width: 5px; height: 5px; border-radius: 50%; background: var(--success); box-shadow: 0 0 6px var(--success); animation: live-pulse 2s ease-in-out infinite; }
.foot-text { opacity: 0.8; }

/* ════════ Responsive ════════ */
@media (max-width: 1024px) {
  .hub-stage { height: auto; min-height: 100vh; overflow: visible; }
  .hub-dashboard { grid-template-columns: 1fr; grid-template-rows: none; gap: 1.75rem; padding: 1.5rem 1.25rem 0; max-width: 700px; min-height: auto; }
  .hub-left, .hub-right { overflow-y: visible; min-height: auto; }
  .hub-footer { padding: 1.1rem 1.25rem; }
}
@media (max-width: 640px) {
  .hub-dashboard { padding: 1rem 1rem 0; gap: 1.25rem; }
  .hero-logo-img { height: 4rem; }
  .hero-head { gap: 0.8rem; }
  .hero-text, .hero-bracket { font-size: 2.8rem; letter-spacing: 2px; }
  .hero-shield { width: 22px; height: 22px; }
  .clr-clock { margin-left: 0; }
  .hub-quickstats { flex-wrap: wrap; }
  .card { min-height: 200px; padding: 1.2rem; }
  .hub-footer { flex-direction: column; gap: 0.5rem; text-align: center; }
}

/* ════════ Reduced motion ════════ */
@media (prefers-reduced-motion: reduce) {
  .orb, .bg-grid, .radar-sweep, .radar-sweep::before, .watermark span,
  .bg-constellation circle, .card-edge, .hero-text.glitch,
  .status-beacon, .foot-pulse i, .profile-ring, .role-pulse {
    animation: none !important;
  }
  .card { transform: none !important; }
  .spotlight, .card-sheen { display: none; }
}
</style>
