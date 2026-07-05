<template>
  <!-- La vista de los Campos Elíseos: cielo con velos, sol de doble anillo
       y lago en calma. Fondo compartido por la landing y el login. -->
  <div class="scene" aria-hidden="true">
    <div class="sky"></div>

    <!-- Estrellas — sólo en Ocaso. El cielo de Amanecer es claro. -->
    <div v-if="isDusk" class="stars">
      <span
        v-for="i in starCount"
        :key="i"
        class="star"
        :style="starStyle(i)"
      ></span>
      <span class="shooting-star" :style="shootingStyle"></span>
    </div>

    <!-- Velos que descienden del cielo -->
    <div class="veils">
      <span class="veil veil--1"></span>
      <span class="veil veil--2"></span>
      <span class="veil veil--3"></span>
      <span class="veil veil--4"></span>
      <span class="veil veil--5"></span>
    </div>

    <!-- Motas de oro flotando en el aire -->
    <div class="motes">
      <span
        v-for="i in moteCount"
        :key="i"
        class="mote"
        :style="moteStyle(i)"
      ></span>
    </div>

    <!-- Sol con doble circunferencia y rayos -->
    <div class="sun-wrap" :style="{ top: sunTop }">
      <svg class="god-rays" viewBox="0 0 360 360">
        <g class="god-ray-group">
          <line
            v-for="a in 12"
            :key="a"
            :x1="180" :y1="180"
            :x2="rayEnd(a).x" :y2="rayEnd(a).y"
            class="god-ray"
          />
        </g>
      </svg>
      <svg class="sun" viewBox="0 0 360 360">
        <defs>
          <radialGradient id="elySunCore" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="var(--sun-core)" />
            <stop offset="70%" stop-color="var(--sun-core)" stop-opacity="0.85" />
            <stop offset="100%" stop-color="var(--sun-core)" stop-opacity="0" />
          </radialGradient>
        </defs>
        <circle cx="180" cy="180" r="52" fill="url(#elySunCore)" />
        <circle cx="180" cy="180" r="80" class="ring ring--inner" />
        <circle cx="180" cy="180" r="118" class="ring ring--outer" />
      </svg>
      <span class="sun-halo"></span>
    </div>

    <!-- Templo clásico en el horizonte — columnata con frontón -->
    <svg class="horizon-temple" viewBox="0 0 1200 140" preserveAspectRatio="xMidYMax meet">
      <!-- Frontón triangular -->
      <polygon points="600,8 740,46 460,46" class="temple-stroke" />
      <!-- Arquitrabe -->
      <rect x="455" y="46" width="290" height="6" class="temple-fill" />
      <!-- Columnas (10) -->
      <g class="temple-stroke">
        <rect v-for="c in 10" :key="c" :x="templeColX(c)" y="52" width="5" height="78" />
        <!-- Capiteles -->
        <rect v-for="c in 10" :key="'k'+c" :x="templeColX(c)-2" y="50" width="9" height="4" class="temple-fill" />
      </g>
      <!-- Bases / escalinata -->
      <rect x="445" y="130" width="310" height="6" class="temple-fill" />
      <rect x="430" y="136" width="340" height="4" class="temple-fill" opacity="0.7" />
    </svg>

    <!-- Lago — espejo del cielo en calma -->
    <div class="lake">
      <span class="lake-shimmer"></span>
      <span class="reflection-glow"></span>
      <!-- Ripples concéntricos desde el reflejo del sol -->
      <div class="ripples">
        <span
          v-for="i in 4"
          :key="i"
          class="ripple"
          :style="{ animationDelay: (i * 1.6) + 's' }"
        ></span>
      </div>
      <span class="reflection"></span>
      <!-- Niebla baja que se desplaza sobre el agua -->
      <span class="lake-mist"></span>
    </div>
    <div class="horizon-line"></div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useThemeStore } from '@/stores/themeStore'

const props = defineProps({
  /** Posición vertical del sol; permite subirlo o bajarlo según la vista. */
  sunTop: { type: String, default: '24%' },
})

const themeStore = useThemeStore()
const isDusk = computed(() => themeStore.theme === 'dusk')

/* ── Conteos responsivos ── */
const isSmall = typeof window !== 'undefined' && window.innerWidth < 640
const starCount = isSmall ? 28 : 56
const moteCount = isSmall ? 15 : 30

/* ── Generadores pseudoaleatorios deterministas por índice ──
   Evitan layouts saltarines y son reproducibles. */
function seeded(n, seed = 1) {
  const x = Math.sin(n * 9301 + seed * 49297) * 233280
  return x - Math.floor(x)
}

function starStyle(i) {
  const top = seeded(i, 7) * 48          // 0-48% del alto (cielo superior)
  const left = seeded(i, 13) * 100       // 0-100% del ancho
  const size = 1 + seeded(i, 23) * 1.4   // 1-2.4px
  const delay = seeded(i, 31) * 6        // 0-6s
  const dur = 4 + seeded(i, 41) * 4      // 4-8s
  const base = 0.3 + seeded(i, 53) * 0.6 // 0.3-0.9
  return {
    top: top + '%',
    left: left + '%',
    width: size + 'px',
    height: size + 'px',
    animationDelay: delay + 's',
    animationDuration: dur + 's',
    '--star-base': base,
  }
}

const shootingStyle = {
  top: (seeded(3, 71) * 30) + '%',
  left: (seeded(8, 83) * 40) + '%',
  animationDelay: '12s',
}

function moteStyle(i) {
  const top = 55 + seeded(i, 17) * 35    // 55-90% (zona velos/lago)
  const left = seeded(i, 29) * 100
  const size = 2 + seeded(i, 43) * 2.4   // 2-4.4px
  const delay = seeded(i, 59) * 18       // 0-18s
  const dur = 60 + seeded(i, 67) * 30    // 60-90s
  return {
    top: top + '%',
    left: left + '%',
    width: size + 'px',
    height: size + 'px',
    animationDelay: delay + 's',
    animationDuration: dur + 's',
  }
}

/* ── Geometría de los rayos de sol ── */
function rayEnd(a) {
  const angle = (a - 1) * (360 / 12) * Math.PI / 180
  const r = 178
  return {
    x: 180 + Math.cos(angle) * r,
    y: 180 + Math.sin(angle) * r,
  }
}

/* ── Posición horizontal de cada columna del templo ── */
function templeColX(c) {
  // 10 columnas entre x=470 y x=730
  return 470 + (c - 1) * ((730 - 470) / 9)
}
</script>

<style scoped>
.scene { position: absolute; inset: 0; overflow: hidden; }

.sky {
  position: absolute; inset: 0;
  background: linear-gradient(to bottom,
    var(--sky-1) 0%,
    var(--sky-2) 46%,
    var(--sky-3) 74%);
  transition: background 0.4s ease;
}

/* ── Estrellas ── */
.stars {
  position: absolute; inset: 0;
  z-index: 1;
  /* Desvanecer hacia el horizonte */
  mask-image: linear-gradient(to bottom, #000 0%, #000 38%, transparent 58%);
  -webkit-mask-image: linear-gradient(to bottom, #000 0%, #000 38%, transparent 58%);
  pointer-events: none;
}
.star {
  position: absolute;
  border-radius: 50%;
  background: var(--star);
  box-shadow: 0 0 4px var(--star-dim);
  opacity: var(--star-base, 0.6);
  animation: star-twinkle 5s ease-in-out infinite;
  will-change: opacity;
}
@keyframes star-twinkle {
  0%, 100% { opacity: calc(var(--star-base, 0.6) * 0.4); }
  50%      { opacity: var(--star-base, 0.6); }
}

/* Estrella fugaz — cruza cada ~30s */
.shooting-star {
  position: absolute;
  width: 90px; height: 1px;
  background: linear-gradient(to right, transparent, var(--star) 70%, transparent);
  transform: rotate(28deg);
  opacity: 0;
  animation: shooting 32s linear infinite;
  will-change: transform, opacity;
}
@keyframes shooting {
  0%, 88%, 100% { opacity: 0; transform: rotate(28deg) translateX(0); }
  90%           { opacity: 1; }
  94%           { opacity: 0; transform: rotate(28deg) translateX(40vw); }
}

/* Velos — cortinas de luz que nacen del cielo y caen hacia el horizonte.
   Doble capa: un núcleo brillante estrecho sobre un manto ancho y tenue. */
.veils { position: absolute; inset: 0; z-index: 2; overflow: hidden; }
.veil {
  position: absolute;
  top: -8%;
  height: 86%;
  background-image:
    linear-gradient(to bottom, var(--veil-core), transparent 72%),
    linear-gradient(to bottom, var(--veil), transparent 86%);
  background-size: 26% 100%, 100% 100%;
  background-position: 50% 0, 0 0;
  background-repeat: no-repeat;
  transform: skewX(-8deg);
  filter: blur(17px);
  mix-blend-mode: screen;
  animation: veil-drift 64s ease-in-out infinite alternate;
}
.veil--1 { left: 4%;  width: 21vw; }
.veil--2 { left: 24%; width: 12vw; animation-delay: -18s; animation-duration: 80s; }
.veil--3 { left: 42%; width: 17vw; animation-delay: -37s; animation-duration: 72s; }
.veil--4 { left: 63%; width: 10vw; animation-delay: -9s;  animation-duration: 90s; }
.veil--5 { left: 78%; width: 16vw; animation-delay: -52s; animation-duration: 68s; }
@keyframes veil-drift {
  from { transform: skewX(-8deg) translateX(0);       opacity: 0.7; }
  50%  { transform: skewX(-5.5deg) translateX(2.2vw); opacity: 1; }
  to   { transform: skewX(-9.5deg) translateX(-1.8vw); opacity: 0.75; }
}

/* ── Motas de oro flotando ── */
.motes {
  position: absolute; inset: 0;
  z-index: 3;
  pointer-events: none;
}
.mote {
  position: absolute;
  border-radius: 50%;
  background: var(--mote);
  box-shadow: 0 0 6px var(--mote);
  filter: blur(0.4px);
  opacity: 0;
  animation: mote-float 70s linear infinite;
  will-change: transform, opacity;
}
@keyframes mote-float {
  0%   { transform: translateY(0);        opacity: 0; }
  8%   { opacity: 0.7; }
  88%  { opacity: 0.5; }
  100% { transform: translateY(-26vh);    opacity: 0; }
}

/* Sol de doble circunferencia con rayos */
.sun-wrap {
  position: absolute;
  left: 50%;
  z-index: 4;
  width: min(42vmin, 380px); height: min(42vmin, 380px);
  transform: translateX(-50%);
}
.sun { width: 100%; height: 100%; overflow: visible; }
.ring { fill: none; stroke: var(--accent); }
.ring--inner { stroke-width: 1.6; opacity: 0.75; }
.ring--outer {
  stroke-width: 1; opacity: 0.4;
  stroke-dasharray: 3 7;
  transform-origin: center;
  animation: ring-turn 240s linear infinite;
}
@keyframes ring-turn { to { transform: rotate(360deg); } }
.sun-halo {
  position: absolute; inset: -30%;
  background: radial-gradient(circle, var(--sun-glow) 0%, transparent 58%);
  animation: halo-breathe 11s ease-in-out infinite;
}
@keyframes halo-breathe { 0%, 100% { opacity: 0.75; } 50% { opacity: 1; } }

/* Rayos de sol — god rays radiales */
.god-rays {
  position: absolute; inset: 0;
  width: 100%; height: 100%;
  overflow: visible;
  mix-blend-mode: screen;
  animation: god-ray-breathe 14s ease-in-out infinite;
}
.god-ray-group {
  transform-origin: 180px 180px;
  animation: god-ray-turn 300s linear infinite;
}
.god-ray {
  stroke: var(--sun-core);
  stroke-width: 1.2;
  opacity: 0.18;
  stroke-linecap: round;
}
@keyframes god-ray-turn { to { transform: rotate(360deg); } }
@keyframes god-ray-breathe { 0%, 100% { opacity: 0.7; } 50% { opacity: 1; } }

/* ── Templo clásico en el horizonte ── */
.horizon-temple {
  position: absolute;
  left: 0; right: 0;
  bottom: 24vh;
  width: 100%;
  height: 14vh;
  z-index: 3;
  opacity: 0.2;
  animation: temple-breathe 30s ease-in-out infinite;
  pointer-events: none;
  filter: drop-shadow(0 0 8px var(--sun-glow));
}
.temple-stroke { stroke: var(--temple); stroke-width: 0.8; fill: none; }
.temple-fill   { fill: var(--temple); }
@keyframes temple-breathe {
  0%, 100% { opacity: 0.16; }
  50%      { opacity: 0.24; }
}

/* Lago — espejo en calma: banda cálida en el horizonte que se hunde en
   azul profundo. Sin bandas ni oleaje duro; solo luz difusa que respira. */
.lake {
  position: absolute;
  left: 0; right: 0; bottom: 0;
  z-index: 5;
  height: 24vh;
  background: linear-gradient(to bottom,
    var(--lake-horizon) 0%,
    var(--lake-1) 30%,
    var(--lake-2) 100%);
  overflow: hidden;
  transition: background 0.4s ease;
}
.lake-shimmer {
  position: absolute;
  left: 0; right: 0; top: 0;
  height: 42%;
  background: linear-gradient(to bottom, var(--lake-shine), transparent 100%);
  opacity: 0.5;
  filter: blur(3px);
  animation: shimmer-breathe 9s ease-in-out infinite;
}
@keyframes shimmer-breathe { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.62; } }
.reflection-glow {
  position: absolute;
  top: -6%; left: 50%;
  width: min(30vmin, 260px); height: 70%;
  transform: translateX(-50%);
  background: radial-gradient(ellipse 60% 100% at 50% 0%, var(--lake-shine), transparent 72%);
  filter: blur(10px);
  opacity: 0.7;
}

/* ── Ripples concéntricos desde el reflejo del sol ── */
.ripples {
  position: absolute;
  top: 8%; left: 50%;
  width: 0; height: 0;
  z-index: 1;
}
.ripple {
  position: absolute;
  top: 0; left: 0;
  width: 60px; height: 18px;
  border: 1px solid var(--lake-shine);
  border-radius: 50%;
  transform: translate(-50%, -50%) scale(0.3);
  opacity: 0;
  animation: ripple-expand 7s ease-out infinite;
  will-change: transform, opacity;
}
@keyframes ripple-expand {
  0%   { transform: translate(-50%, -50%) scale(0.3); opacity: 0.55; }
  100% { transform: translate(-50%, -50%) scale(2.4); opacity: 0; }
}

.reflection {
  position: absolute;
  top: 0; left: 50%;
  width: min(34vmin, 260px); height: 92%;
  transform: translateX(-50%);
  clip-path: polygon(46% 0, 54% 0, 78% 100%, 22% 100%);
  background: linear-gradient(to bottom, var(--lake-shine), transparent 82%);
  filter: blur(7px);
  mix-blend-mode: screen;
  mask-image: linear-gradient(90deg, transparent, #000 35%, #000 65%, transparent);
  -webkit-mask-image: linear-gradient(90deg, transparent, #000 35%, #000 65%, transparent);
  animation: reflection-breathe 11s ease-in-out infinite;
  z-index: 2;
}
@keyframes reflection-breathe {
  0%, 100% { opacity: 0.55; }
  50%      { opacity: 0.8; }
}

/* ── Niebla baja sobre el agua ── */
.lake-mist {
  position: absolute;
  left: -10%; right: -10%;
  top: 18%;
  height: 38%;
  background: linear-gradient(to right,
    transparent 0%,
    var(--mist) 25%,
    var(--mist) 75%,
    transparent 100%);
  filter: blur(20px);
  opacity: 0.5;
  animation: mist-drift 40s ease-in-out infinite alternate;
  z-index: 3;
}
@keyframes mist-drift {
  from { transform: translateX(-6%); }
  to   { transform: translateX(6%); }
}

.horizon-line {
  position: absolute;
  left: 0; right: 0; bottom: 24vh;
  height: 1px;
  z-index: 6;
  background: linear-gradient(90deg, transparent, var(--accent) 18%, var(--accent-bright) 50%, var(--accent) 82%, transparent);
  opacity: 0.65;
  box-shadow: 0 0 18px var(--sun-glow);
}

@media (prefers-reduced-motion: reduce) {
  .veil, .ring--outer, .sun-halo, .reflection, .lake-shimmer,
  .star, .shooting-star, .mote, .god-rays, .god-ray-group,
  .ripple, .lake-mist, .horizon-temple {
    animation: none !important;
  }
  .star { opacity: var(--star-base, 0.6); }
  .mote { opacity: 0.4; }
  .ripple { display: none; }
  .shooting-star { opacity: 0; }
}
</style>
