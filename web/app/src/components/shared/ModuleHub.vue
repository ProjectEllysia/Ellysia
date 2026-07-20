<template>
  <div class="sanctum" :data-module="moduleId">
    <StarBackground />
    <SiteHeader />

    <!-- ═══════════ HERO — el santuario ═══════════ -->
    <header class="sanctum-hero">
      <!-- Epígrafe latino gigante, grabado tras el contenido -->
      <span class="hero-watermark" aria-hidden="true">{{ epigraph }}</span>

      <div class="hero-inner">
        <div class="hero-emblem" aria-hidden="true">
          <span class="emblem-halo"></span>
          <img :src="icon" alt="" />
        </div>

        <span class="hero-kicker">{{ numeral }} · {{ name }} · {{ epigraph }}</span>

        <h1 class="hero-claim">{{ claim }}</h1>
        <p class="hero-myth">{{ myth }}</p>

        <div class="hero-actions">
          <router-link v-if="auth.isAuthenticated" :to="toolRoute" class="cta cta--solid">{{ toolLabel }}</router-link>
          <router-link v-else :to="{ path: '/login', query: { redirect: toolRoute } }" class="cta cta--solid">Entrar</router-link>
          <button class="cta cta--line" @click="scrollToFeatures">Conocer más</button>
        </div>

        <!-- Placa: actividad real si hay sesión; dato de producto si es visita pública -->
        <div class="hero-plaque">
          <slot v-if="auth.isAuthenticated" name="metric">
            <p class="metric-empty">Todavía no hay actividad que mostrar.</p>
          </slot>
          <template v-else>
            <span class="metric-label">{{ highlight.label }}</span>
            <span class="metric-value">{{ highlight.value }}</span>
            <span v-if="highlight.sub" class="metric-sub">{{ highlight.sub }}</span>
          </template>
        </div>

        <nav v-if="shortcuts.length && auth.isAuthenticated" class="hero-shortcuts" aria-label="Atajos">
          <router-link v-for="s in shortcuts" :key="s.label" :to="s.to" class="shortcut">
            {{ s.label }} <span aria-hidden="true">→</span>
          </router-link>
        </nav>
      </div>

      <button class="scroll-cue" @click="scrollToFeatures" aria-label="Bajar a las capacidades">
        <span></span>
      </button>
    </header>

    <!-- ═══════════ Banda — friso del módulo ═══════════ -->
    <div class="sanctum-band" aria-hidden="true"></div>

    <!-- ═══════════ CAPACIDADES ═══════════ -->
    <section id="features" class="rites">
      <div class="rites-intro">
        <h2 class="rites-title">Qué hace {{ name }}</h2>
        <p class="rites-bajada">{{ tagline }}</p>
      </div>

      <div class="rites-grid">
        <article v-for="f in features" :key="f.title" class="rite" ref="riteRefs">
          <span class="rite-kicker">{{ f.kicker }}</span>
          <h3 class="rite-title">{{ f.title }}</h3>
          <p class="rite-desc">{{ f.desc }}</p>
        </article>
      </div>
    </section>

    <!-- ═══════════ RECURSOS ═══════════ -->
    <section v-if="resources.length" class="scrolls">
      <h2 class="scrolls-title">Recursos</h2>
      <ul class="scrolls-list">
        <li v-for="r in resources" :key="r.label">
          <a v-if="r.external" :href="r.href" target="_blank" rel="noopener noreferrer" class="scroll-link">
            {{ r.label }} <span aria-hidden="true">↗</span>
          </a>
          <router-link v-else :to="r.href" class="scroll-link">{{ r.label }}</router-link>
        </li>
      </ul>
    </section>

    <!-- ═══════════ EL RESTO DEL PANTEÓN ═══════════ -->
    <section class="pantheon">
      <h2 class="pantheon-title">El resto del panteón</h2>
      <div class="pantheon-grid">
        <router-link
          v-for="m in otherModules"
          :key="m.id"
          :to="m.route"
          class="pantheon-card"
          :data-module="m.id"
        >
          <img :src="m.icon" alt="" aria-hidden="true" />
          <span class="pantheon-name">{{ m.numeral }} · {{ m.name }}</span>
          <p class="pantheon-desc">{{ m.desc }}</p>
        </router-link>
      </div>
    </section>

    <!-- ═══════════ LLAMADA FINAL ═══════════ -->
    <section class="sanctum-call">
      <span class="call-epigraph">{{ epigraph }}</span>
      <h2 class="call-title">{{ claim }}</h2>
      <router-link v-if="auth.isAuthenticated" :to="toolRoute" class="call-cta">{{ toolLabel }}</router-link>
      <router-link v-else :to="{ path: '/login', query: { redirect: toolRoute } }" class="call-cta">Entrar</router-link>
    </section>

    <SiteFooter />
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import SiteHeader from '@/components/shared/SiteHeader.vue'
import SiteFooter from '@/components/shared/SiteFooter.vue'
import StarBackground from '@/components/shared/StarBackground.vue'

import themisIcon from '@/assets/images/themis/Themis-Turqoise-BgN.png'
import aegisIcon from '@/assets/images/aegis/Ellysia-Aegis-Blue-BgN.png'
import irisIcon from '@/assets/images/iris/Iris-Red-BgN.png'
import acheronIcon from '@/assets/images/acheron/Acheron-Purple-BgN.png'
import hygeiaIcon from '@/assets/images/hygeia/Hygeia-DarkGreen-BgN.png'

const props = defineProps({
  moduleId: { type: String, required: true }, // 'themis' | 'aegis' | 'iris' | 'acheron' | 'hygeia'
  icon: { type: String, required: true },
  name: { type: String, required: true },
  numeral: { type: String, required: true },
  epigraph: { type: String, required: true },
  tagline: { type: String, required: true },
  myth: { type: String, required: true },
  claim: { type: String, required: true },
  toolRoute: { type: String, required: true },
  toolLabel: { type: String, required: true },
  // Dato de producto que ve el visitante SIN sesión (la placa "que te conoce"
  // no puede conocer a un anónimo, así que muestra una cifra de la herramienta).
  highlight: { type: Object, required: true }, // { label, value, sub }
  shortcuts: { type: Array, default: () => [] }, // [{ label, to }]
  features: { type: Array, default: () => [] }, // [{ kicker, title, desc }]
  resources: { type: Array, default: () => [] }, // [{ label, href, external }]
})

const auth = useAuthStore()

/** El panteón completo, para las tarjetas de los otros tres módulos. */
const ALL_MODULES = [
  { id: 'themis', numeral: 'I', name: 'Themis', icon: themisIcon, route: '/themis', desc: 'Pesa cada amenaza antes de que golpee: motor propio, escáneres clásicos, informes IA.' },
  { id: 'aegis', numeral: 'II', name: 'Aegis', icon: aegisIcon, route: '/aegis', desc: 'Concienciación que llega antes que el ataque: píldoras IA y campañas con seguimiento.' },
  { id: 'iris', numeral: 'III', name: 'Iris', icon: irisIcon, route: '/iris', desc: 'Verifica quién firma cada correo: 37 reglas contra el phishing.' },
  { id: 'acheron', numeral: 'IV', name: 'Acheron', icon: acheronIcon, route: '/acheron', desc: 'Guarda lo que no debe perderse: bóveda cifrada en tu navegador.' },
  { id: 'hygeia', numeral: 'V', name: 'Hygeia', icon: hygeiaIcon, route: '/hygeia', desc: 'Vigila el pulso de cada activo: telemetría en vivo y alertas antes del fallo.' },
]

const otherModules = computed(() => ALL_MODULES.filter((m) => m.id !== props.moduleId))

const riteRefs = ref([])

const reduceMotion =
  typeof window !== 'undefined' &&
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

function scrollToFeatures() {
  document.getElementById('features')?.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth' })
}

/* ── Revelado de capacidades al hacer scroll (patrón de LandingView) ── */
let observer = null

onMounted(() => {
  if (reduceMotion) {
    for (const el of riteRefs.value) el.classList.add('revealed')
    return
  }
  observer = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          e.target.classList.add('revealed')
          observer.unobserve(e.target)
        }
      }
    },
    { threshold: 0.25 }
  )
  for (const el of riteRefs.value) observer.observe(el)
})

onUnmounted(() => observer?.disconnect())
</script>

<style scoped>
.sanctum {
  min-height: 100vh;
  background: var(--bg);
  position: relative;
}

/* ═══════════ HERO ═══════════ */
.sanctum-hero {
  position: relative;
  min-height: calc(100vh - 72px);
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  z-index: 1;
  /* El color del módulo baña el santuario desde lo alto */
  background: radial-gradient(ellipse 90% 55% at 50% 0%, var(--accent-dim), transparent 70%);
}

/* Epígrafe grabado — marca de agua tras el contenido */
.hero-watermark {
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  font-family: var(--font-epic);
  font-size: clamp(5rem, 17vw, 13rem);
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text);
  opacity: 0.045;
  white-space: nowrap;
  pointer-events: none;
  user-select: none;
  z-index: 0;
}

.hero-inner {
  position: relative;
  z-index: 1;
  text-align: center;
  padding: 3.5rem 1.5rem 4.5rem;
  max-width: 880px;
  animation: hero-rise 0.9s ease-out both;
}
@keyframes hero-rise {
  from { opacity: 0; transform: translateY(16px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* ── Emblema ── */
.hero-emblem {
  position: relative;
  width: 180px; height: 180px;
  margin: 0 auto 1.6rem;
  border-radius: 50%;
  display: grid; place-items: center;
  background: var(--surface);
  border: 1px solid var(--accent);
  box-shadow: 0 0 0 6px var(--bg), 0 0 0 7px var(--border-med), 0 0 34px var(--accent-dim);
}
.hero-emblem img { width: 56%; height: 56%; object-fit: contain; }
.emblem-halo {
  position: absolute;
  inset: -10px;
  border: 1px dashed var(--accent);
  border-radius: 50%;
  opacity: 0.35;
  animation: halo-turn 240s linear infinite;
  pointer-events: none;
}
@keyframes halo-turn { to { transform: rotate(360deg); } }

/* ── Kicker: numeral · nombre · epígrafe ── */
.hero-kicker {
  display: block;
  font-family: var(--font-epic);
  font-size: var(--fs-lg); font-weight: 600;
  letter-spacing: 0.34em; text-transform: uppercase;
  color: var(--accent);
}

/* ── Titular benefit-led: aquí manda lo que hace, no cómo se llama ── */
.hero-claim {
  font-family: var(--font-display);
  font-size: clamp(2.6rem, 6vw, 4.2rem);
  font-weight: 600;
  line-height: 1.12;
  color: var(--text);
  margin-top: 1rem;
  text-shadow: 0 0 50px var(--accent-dim);
  text-wrap: balance;
}
.hero-myth {
  font-family: var(--font-display);
  font-style: italic;
  font-size: clamp(1.5rem, 3vw, 1.9rem);
  color: var(--text-dim);
  margin-top: 0.9rem;
  text-wrap: balance;
}

/* ── CTAs ── */
.hero-actions {
  display: flex; align-items: center; justify-content: center; gap: 1rem;
  margin-top: 2.2rem; flex-wrap: wrap;
}
.cta {
  font-family: var(--font-epic);
  font-size: var(--fs-lg); font-weight: 600;
  letter-spacing: 0.18em; text-transform: uppercase;
  padding: 0.9rem 2.1rem;
  border-radius: 3px;
  transition: all var(--transition);
}
.cta--solid {
  background: var(--accent);
  color: var(--on-accent);
  border: 1px solid var(--accent);
}
.cta--solid:hover { background: var(--accent-bright); border-color: var(--accent-bright); box-shadow: 0 0 24px var(--accent-dim); }
.cta--line {
  color: var(--text);
  border: 1px solid var(--accent);
  background: var(--accent-dim);
}
.cta--line:hover { background: var(--accent); color: var(--on-accent); }
.cta:focus-visible, .shortcut:focus-visible, .scroll-link:focus-visible,
.pantheon-card:focus-visible, .call-cta:focus-visible {
  outline: 2px solid var(--accent-bright);
  outline-offset: 3px;
}

/* ── Placa de actividad — museo, no dashboard ── */
.hero-plaque {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  gap: 0.15rem;
  margin-top: 2.4rem;
  padding: 1.1rem 2.2rem;
  border: 1px solid var(--border-med);
  border-radius: 4px;
  background: color-mix(in srgb, var(--surface) 72%, transparent);
  min-width: 300px;
}
.hero-plaque :slotted(.metric-label),
.hero-plaque .metric-label {
  font-family: var(--font-mono);
  font-size: var(--fs-md);
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--text-muted);
}
.hero-plaque :slotted(.metric-value),
.hero-plaque .metric-value {
  font-family: var(--font-display);
  font-size: var(--fs-3xl); font-weight: 600;
  color: var(--accent-bright);
  line-height: 1.2;
  padding-bottom: 0.5rem;
}
.hero-plaque :slotted(.metric-sub),
.hero-plaque .metric-sub {
  font-family: var(--font-mono);
  font-size: var(--fs-md);
  color: var(--text-dim);
}
.hero-plaque :slotted(.metric-loading),
.hero-plaque :slotted(.metric-empty),
.hero-plaque .metric-empty {
  font-family: var(--font-mono);
  font-size: var(--fs-md);
  color: var(--text-muted);
}

/* ── Atajos ── */
.hero-shortcuts {
  display: flex; align-items: center; justify-content: center; gap: 1.6rem;
  margin-top: 1.4rem; flex-wrap: wrap;
}
.shortcut {
  font-family: var(--font-mono);
  font-size: var(--fs-lg);
  color: var(--text-dim);
  padding-bottom: 0.15rem;
  border-bottom: 1px solid transparent;
  transition: color var(--transition), border-color var(--transition);
}
.shortcut:hover { color: var(--accent-bright); border-color: var(--accent); }

/* ── Cue de scroll ── */
.scroll-cue {
  position: absolute; bottom: 1.6rem; left: 50%;
  transform: translateX(-50%);
  z-index: 1;
  width: 30px; height: 42px;
  display: flex; justify-content: center;
}
.scroll-cue span {
  display: block; width: 1px; height: 100%;
  background: linear-gradient(to bottom, transparent, var(--accent));
  animation: cue-fall 2.4s ease-in-out infinite;
}
@keyframes cue-fall {
  0%   { transform: scaleY(0); transform-origin: top; }
  55%  { transform: scaleY(1); transform-origin: top; }
  56%  { transform-origin: bottom; }
  100% { transform: scaleY(0); transform-origin: bottom; }
}

/* ═══════════ Banda — friso del módulo ═══════════ */
.sanctum-band {
  height: 8px;
  background: var(--accent);
  opacity: 0.85;
}

/* ═══════════ CAPACIDADES ═══════════ */
.rites {
  position: relative; z-index: 1;
  max-width: 1060px;
  margin: 0 auto;
  padding: 5rem 2rem 4rem;
}
.rites-intro { text-align: center; margin-bottom: 3.5rem; }
.rites-title {
  font-family: var(--font-epic);
  font-size: clamp(1.5rem, 3.4vw, 2.2rem);
  font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--text);
}
.rites-bajada {
  font-family: var(--font-display);
  font-style: italic;
  font-size: var(--fs-xl);
  color: var(--text-muted);
  margin-top: 0.6rem;
  text-wrap: balance;
}
.rites-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 3rem 4rem;
}
.rite {
  border-top: 1px solid var(--border-med);
  padding-top: 1.3rem;
  opacity: 0;
  transform: translateY(18px);
  transition: opacity 0.7s ease, transform 0.5s ease;
}
.rite.revealed { opacity: 1; transform: translateY(0); }
.rite-kicker {
  font-family: var(--font-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.28em; text-transform: uppercase;
  color: var(--accent);
}
.rite-title {
  font-family: var(--font-display);
  font-size: var(--fs-2xl); font-weight: 600;
  line-height: 1.25;
  color: var(--text);
  margin-top: 0.5rem;
}
.rite-desc {
  font-size: var(--fs-lg);
  color: var(--text-dim);
  margin-top: 0.55rem;
  line-height: 1.65;
}

/* ═══════════ RECURSOS ═══════════ */
.scrolls {
  position: relative; z-index: 1;
  max-width: 1060px;
  margin: 0 auto;
  padding: 0 2rem 4rem;
  text-align: center;
}
.scrolls-title {
  font-family: var(--font-epic);
  font-size: var(--fs-lg); font-weight: 600;
  letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 1.2rem;
}
.scrolls-list {
  list-style: none;
  display: flex; align-items: center; justify-content: center; gap: 1rem;
  flex-wrap: wrap;
}
.scroll-link {
  display: inline-block;
  font-size: var(--fs-lg);
  color: var(--text-dim);
  padding: 0.5rem 1.1rem;
  border: 1px solid var(--border-med);
  border-radius: 3px;
  transition: all var(--transition);
}
.scroll-link:hover { color: var(--accent-bright); border-color: var(--accent); background: var(--accent-dim); }

/* ═══════════ PANTEÓN ═══════════ */
.pantheon {
  position: relative; z-index: 1;
  max-width: 1060px;
  margin: 0 auto;
  padding: 0 2rem 5rem;
}
.pantheon-title {
  font-family: var(--font-epic);
  font-size: var(--fs-lg); font-weight: 600;
  letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--accent);
  text-align: center;
  margin-bottom: 1.6rem;
}
.pantheon-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.1rem;
}
/* Cada tarjeta hereda el acento de SU módulo vía data-module */
.pantheon-card {
  display: flex; flex-direction: column; align-items: flex-start; gap: 0.5rem;
  background: var(--surface);
  border: 1px solid var(--border-med);
  border-radius: var(--radius);
  padding: 1.4rem 1.5rem;
  transition: all var(--transition);
}
.pantheon-card:hover {
  border-color: var(--accent);
  transform: translateY(-3px);
  box-shadow: 0 10px 30px rgba(0,0,0,0.2), 0 0 0 1px var(--accent-dim);
}
.pantheon-card img { width: 40px; height: 40px; object-fit: contain; }
.pantheon-name {
  font-family: var(--font-epic);
  font-size: var(--fs-lg); font-weight: 600;
  letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--accent);
  margin-top: 0.3rem;
}
.pantheon-desc {
  font-size: var(--fs-lg);
  color: var(--text-dim);
  line-height: 1.55;
}

/* ═══════════ LLAMADA FINAL ═══════════ */
.sanctum-call {
  position: relative; z-index: 1;
  background: var(--accent);
  text-align: center;
  padding: 4rem 2rem 4.4rem;
}
.call-epigraph {
  font-family: var(--font-epic);
  font-size: var(--fs-lg); font-weight: 600;
  letter-spacing: 0.4em; text-transform: uppercase;
  color: var(--on-accent);
  opacity: 0.65;
}
.call-title {
  font-family: var(--font-display);
  font-size: clamp(1.8rem, 4vw, 2.7rem);
  font-weight: 600;
  color: var(--on-accent);
  margin-top: 0.7rem;
  text-wrap: balance;
}
.call-cta {
  display: inline-block;
  margin-top: 1.8rem;
  font-family: var(--font-epic);
  font-size: var(--fs-lg); font-weight: 600;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--text);
  background: var(--bg);
  padding: 0.95rem 2.4rem;
  border-radius: 3px;
  transition: all var(--transition);
}
.call-cta:hover { box-shadow: 0 0 30px rgba(0,0,0,0.3); transform: translateY(-2px); }

/* ═══════════ Responsive ═══════════ */
@media (max-width: 860px) {
  .rites-grid { grid-template-columns: 1fr; gap: 2.2rem; }
  .rites { padding: 3.5rem 1.4rem 3rem; }
  .hero-watermark { letter-spacing: 0.1em; }
}
@media (max-width: 640px) {
  .hero-inner { padding: 2.5rem 1.2rem 4rem; }
  .hero-plaque { min-width: 0; width: 100%; }
  .hero-actions .cta { padding: 0.8rem 1.4rem; }
  .hero-shortcuts { gap: 1rem; }
  .scrolls, .pantheon { padding-left: 1.4rem; padding-right: 1.4rem; }
}

/* ═══════════ Movimiento reducido ═══════════ */
@media (prefers-reduced-motion: reduce) {
  .hero-inner, .scroll-cue span { animation: none !important; }
  .emblem-halo { animation: none !important; }
  .rite { opacity: 1; transform: none; transition: none; }
  .pantheon-card:hover, .call-cta:hover { transform: none !important; }
}
</style>
