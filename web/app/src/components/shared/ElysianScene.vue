<template>
  <!-- La vista de los Campos Elíseos: cielo con velos, sol de doble anillo
       y lago en calma. Fondo compartido por la landing y el login. -->
  <div class="scene" aria-hidden="true">
    <div class="sky"></div>

    <!-- Velos que descienden del cielo -->
    <div class="veils">
      <span class="veil veil--1"></span>
      <span class="veil veil--2"></span>
      <span class="veil veil--3"></span>
      <span class="veil veil--4"></span>
      <span class="veil veil--5"></span>
    </div>

    <!-- Sol con doble circunferencia -->
    <div class="sun-wrap" :style="{ top: sunTop }">
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

    <!-- Lago — espejo del cielo en calma -->
    <div class="lake">
      <span class="lake-shimmer"></span>
      <span class="reflection-glow"></span>
      <span class="reflection"></span>
    </div>
    <div class="horizon-line"></div>
  </div>
</template>

<script setup>
defineProps({
  /** Posición vertical del sol; permite subirlo o bajarlo según la vista. */
  sunTop: { type: String, default: '24%' },
})
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

/* Velos — cortinas de luz que nacen del cielo y caen hacia el horizonte.
   Doble capa: un núcleo brillante estrecho sobre un manto ancho y tenue. */
.veils { position: absolute; inset: 0; overflow: hidden; }
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

/* Sol de doble circunferencia */
.sun-wrap {
  position: absolute;
  left: 50%;
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

/* Lago — espejo en calma: banda cálida en el horizonte que se hunde en
   azul profundo. Sin bandas ni oleaje duro; solo luz difusa que respira. */
.lake {
  position: absolute;
  left: 0; right: 0; bottom: 0;
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
}
@keyframes reflection-breathe {
  0%, 100% { opacity: 0.55; }
  50%      { opacity: 0.8; }
}

.horizon-line {
  position: absolute;
  left: 0; right: 0; bottom: 24vh;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent) 18%, var(--accent-bright) 50%, var(--accent) 82%, transparent);
  opacity: 0.65;
  box-shadow: 0 0 18px var(--sun-glow);
}

@media (prefers-reduced-motion: reduce) {
  .veil, .ring--outer, .sun-halo, .reflection, .lake-shimmer {
    animation: none !important;
  }
}
</style>
