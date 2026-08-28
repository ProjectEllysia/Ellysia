<template>
  <div class="quiz-page" data-module="aegis">
    <StarBackground />

    <main class="quiz-shell" :style="brandStyle">
      <header class="quiz-brand">
        <img v-if="whiteLabel.brandLogo" class="brand-logo" :src="whiteLabel.brandLogo" :alt="whiteLabel.brandName" />
        <span v-if="productBrandVisible" class="brand-mark">Ellysia</span>
        <span v-else-if="!whiteLabel.brandLogo" class="brand-mark">{{ whiteLabel.brandName }}</span>
        <span class="brand-sub">Formación de concienciación</span>
      </header>

      <!-- ── Cargando ── -->
      <section v-if="state === 'loading'" class="card card--center">
        <div class="spinner" aria-hidden="true"></div>
        <p class="muted">Cargando tu formación…</p>
      </section>

      <!-- ── Token inválido / error ── -->
      <section v-else-if="state === 'error'" class="card card--center">
        <div class="glyph glyph--danger" aria-hidden="true">✕</div>
        <h1 class="card-title">{{ errorTitle }}</h1>
        <p class="muted">{{ errorDetail }}</p>
      </section>

      <!-- ── Ya completado (al abrir o tras enviar) ── -->
      <section v-else-if="state === 'completed'" class="card card--center">
        <div class="glyph" :class="scoreGlyphClass" aria-hidden="true">{{ passed ? '✓' : '!' }}</div>
        <h1 class="card-title">{{ justSubmitted ? '¡Test completado!' : 'Ya completaste este test' }}</h1>
        <p class="score">
          <strong>{{ result.score }}</strong><span class="score-sep">/</span>{{ result.total }}
        </p>
        <p class="muted">{{ scoreMessage }}</p>
        <p class="muted fine">Este enlace es de un solo uso y ya no admite más respuestas.</p>
      </section>

      <!-- ── Cuestionario ── -->
      <template v-else>
        <section class="card intro-card">
          <p class="eyebrow">Tu formación</p>
          <h1 class="pill-title">{{ quiz.pillTitle }}</h1>
          <p class="muted">
            Responde a {{ quiz.questions.length }}
            {{ quiz.questions.length === 1 ? 'pregunta' : 'preguntas' }} para
            completar la formación. Solo puedes enviar el test una vez.
          </p>
        </section>

        <form class="quiz-form" @submit.prevent="submit">
          <fieldset
            v-for="(question, index) in quiz.questions"
            :key="question.position"
            class="card question-card"
            :disabled="state === 'submitting'"
          >
            <legend class="sr-only">Pregunta {{ index + 1 }}</legend>
            <div class="question-head">
              <span class="question-num">{{ index + 1 }}</span>
              <p class="question-prompt">{{ question.prompt }}</p>
            </div>

            <!-- Se itera el orden barajado, pero `optionIndex` sigue siendo el
                 índice ORIGINAL: es el que se guarda en `answers` y el que se
                 envía, porque es contra el que corrige el servidor. -->
            <label
              v-for="optionIndex in orderFor(question)"
              :key="optionIndex"
              class="option"
              :class="{ 'option--picked': answers[question.position] === optionIndex }"
            >
              <input
                type="radio"
                :name="`q-${question.position}`"
                :value="optionIndex"
                :checked="answers[question.position] === optionIndex"
                @change="answers[question.position] = optionIndex"
              />
              <span class="option-text">{{ question.options[optionIndex] }}</span>
            </label>
          </fieldset>

          <div class="quiz-actions">
            <p v-if="!allAnswered" class="muted fine">
              Te faltan {{ pendingCount }}
              {{ pendingCount === 1 ? 'pregunta' : 'preguntas' }} por responder.
            </p>
            <p v-if="submitError" class="submit-error">{{ submitError }}</p>
            <button type="submit" class="submit-btn" :disabled="!allAnswered || state === 'submitting'">
              {{ state === 'submitting' ? 'Enviando…' : 'Enviar respuestas' }}
            </button>
          </div>
        </form>
      </template>

      <footer class="quiz-foot">{{ footerBrand }} · Concienciación en seguridad</footer>
    </main>
  </div>
</template>

<script setup>
/**
 * Página pública del quiz de una campaña de Aegis.
 *
 * Es el destino del enlace que llega por correo. El destinatario NO tiene
 * cuenta en Ellysia: el token de la query string es la única identidad, así
 * que aquí se usa `fetch` a pelo — `apiFetch` (composables/useApi.js) exige
 * un JWT y hace logout+redirección cuando no lo hay.
 *
 * La página vive en /quiz y no en /aegis/quiz a propósito: todo lo que cuelga
 * de /aegis/ lo captura el proxy hacia Flask (el matcher @api del Caddyfile,
 * vite.config.js), y
 * el destinatario acabaría viendo el JSON de la API en vez de esta vista.
 */
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import StarBackground from '@/components/shared/StarBackground.vue'
import { shuffledOrder } from '@/components/aegis/quizShuffle.js'

const route = useRoute()
const token = String(route.query.t || '')

// loading | quiz | submitting | completed | error
const state = ref('loading')
const quiz = ref({ pillTitle: '', questions: [] })
const result = ref({ score: 0, total: 0 })
const answers = reactive({})
// position → orden de pintado de sus opciones. Se calcula UNA vez al cargar:
// generarlo dentro del v-for lo recalcularía en cada render y las opciones
// bailarían con cada clic.
const optionOrder = reactive({})
// Marca de la campaña: la sirve el propio endpoint del quiz, resuelta igual
// que la del correo (ajustes de la organización, topados por su plan). Sin
// white-labeling llega en nivel 'none' y la página queda como siempre.
const whiteLabel = ref({ level: 'none', brandName: '', brandLogo: '', brandColor: '' })
const justSubmitted = ref(false)
const submitError = ref('')
const errorTitle = ref('')
const errorDetail = ref('')

/** En nivel 'full' la marca del producto desaparece de la página, igual que
 *  desaparece del correo. En 'logo' solo se suma el logo del cliente. */
const productBrandVisible = computed(() => whiteLabel.value.level !== 'full')
/** El color del cliente se inyecta como variable local del contenedor: pisa
 *  el acento del tema solo dentro de esta página, sin tocar el resto de la
 *  app ni el resto de variables. */
const brandStyle = computed(() =>
  whiteLabel.value.brandColor
    ? { '--accent': whiteLabel.value.brandColor, '--accent-bright': whiteLabel.value.brandColor }
    : {},
)
const footerBrand = computed(
  () => (productBrandVisible.value ? 'Ellysia' : whiteLabel.value.brandName),
)

const pendingCount = computed(
  () => quiz.value.questions.filter(q => answers[q.position] === undefined).length
)
const allAnswered = computed(() => quiz.value.questions.length > 0 && pendingCount.value === 0)
const passed = computed(() => result.value.total > 0 && result.value.score / result.value.total >= 0.6)
const scoreGlyphClass = computed(() => (passed.value ? 'glyph--success' : 'glyph--warn'))
const scoreMessage = computed(() => {
  if (!result.value.total) return 'Test registrado.'
  return passed.value
    ? 'Buen trabajo. Has superado la comprobación.'
    : 'Repasa la formación con tu responsable de seguridad.'
})

/** Orden barajado de la pregunta, o el natural si por lo que sea falta: una
 *  pregunta en blanco es peor que una pregunta sin barajar. */
function orderFor(question) {
  return optionOrder[question.position] ?? question.options.map((_, index) => index)
}

function fail(title, detail) {
  errorTitle.value = title
  errorDetail.value = detail
  state.value = 'error'
}

async function load() {
  if (!token) {
    fail('Enlace incompleto', 'Al enlace le falta el identificador. Abre el que recibiste por correo tal cual, sin recortarlo.')
    return
  }

  let response
  try {
    response = await fetch(`/aegis/quiz?t=${encodeURIComponent(token)}`)
  } catch {
    fail('No hemos podido conectar', 'Revisa tu conexión y vuelve a intentarlo en unos minutos.')
    return
  }

  if (response.status === 404) {
    fail('Enlace no válido', 'Este enlace no corresponde a ninguna formación. Puede que se haya escrito mal o que la campaña ya no exista.')
    return
  }
  if (response.status === 429) {
    fail('Demasiados intentos', 'Se ha alcanzado el límite de peticiones. Espera un rato antes de volver a abrir el enlace.')
    return
  }
  if (!response.ok) {
    fail('Algo ha fallado', 'No hemos podido cargar tu formación. Inténtalo de nuevo más tarde.')
    return
  }

  const data = await response.json()
  if (data.whiteLabel) whiteLabel.value = data.whiteLabel
  if (data.status === 'completed') {
    result.value = { score: data.score ?? 0, total: data.total ?? 0 }
    state.value = 'completed'
    return
  }

  quiz.value = { pillTitle: data.pillTitle || 'Formación de concienciación', questions: data.questions || [] }
  if (!quiz.value.questions.length) {
    fail('Formación sin preguntas', 'Esta campaña no tiene ningún test asociado. Avisa a quien te la envió.')
    return
  }

  for (const question of quiz.value.questions) {
    optionOrder[question.position] = shuffledOrder(question.options.length)
  }

  state.value = 'quiz'
}

async function submit() {
  if (!allAnswered.value) return
  submitError.value = ''
  state.value = 'submitting'

  const payload = {
    answers: quiz.value.questions.map(q => ({
      questionPosition: q.position,
      selectedIndex: answers[q.position],
    })),
  }

  let response
  try {
    response = await fetch(`/aegis/quiz?t=${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
  } catch {
    state.value = 'quiz'
    submitError.value = 'No hemos podido enviar tus respuestas. Revisa tu conexión e inténtalo otra vez.'
    return
  }

  if (response.status === 409) {
    // Otra pestaña (o un doble envío) ganó la carrera: el test ya está
    // cerrado. Releer para dar la nota real y no inventarse un 0.
    state.value = 'loading'
    await load()
    return
  }
  if (!response.ok) {
    state.value = 'quiz'
    submitError.value = response.status === 429
      ? 'Demasiados envíos seguidos. Espera un momento antes de reintentar.'
      : 'No hemos podido registrar tus respuestas. Inténtalo de nuevo.'
    return
  }

  const data = await response.json()
  result.value = { score: data.score ?? 0, total: data.total ?? quiz.value.questions.length }
  justSubmitted.value = true
  state.value = 'completed'
}

onMounted(load)
</script>

<style scoped>
.quiz-page { min-height: 100vh; background: var(--bg); position: relative; }
.quiz-shell {
  position: relative; z-index: 1;
  max-width: 680px; margin: 0 auto;
  padding: 3rem 1.25rem 4rem;
  display: flex; flex-direction: column; gap: 1rem;
}

/* ── Cabecera de marca (sin Topbar: el destinatario no tiene sesión) ── */
.quiz-brand { text-align: center; margin-bottom: 1.25rem; }
.brand-logo { display: block; margin: 0 auto 0.6rem; max-width: 180px; max-height: 64px; object-fit: contain; }
.brand-mark {
  display: block; font-family: var(--font-epic); font-size-adjust: var(--fsa-epic); font-size: var(--fs-2xl);
  letter-spacing: 0.18em; text-transform: uppercase; color: var(--accent);
}
.brand-sub {
  display: block; margin-top: 0.35rem; font-size: var(--fs-xs);
  letter-spacing: 0.14em; text-transform: uppercase; color: var(--text-muted);
}

.card {
  background: var(--surface); border: 1px solid var(--border-med);
  border-radius: var(--radius); padding: 1.5rem;
  animation: seq-fade-up 0.4s ease-out backwards;
}
.card--center { text-align: center; display: flex; flex-direction: column; align-items: center; gap: 0.75rem; padding: 3rem 1.5rem; }
.card-title { font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: var(--fs-xl); color: var(--text); font-weight: 600; }

.intro-card { border-left: 3px solid var(--accent); }
.eyebrow { font-size: var(--fs-xs); letter-spacing: 0.12em; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0.4rem; }
.pill-title { font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: var(--fs-2xl); line-height: 1.25; color: var(--text); margin-bottom: 0.6rem; font-weight: 600; }
.muted { color: var(--text-dim); font-size: var(--fs-body); line-height: 1.55; }
.fine { font-size: var(--fs-sm); color: var(--text-muted); }

/* ── Preguntas ── */
.quiz-form { display: flex; flex-direction: column; gap: 1rem; }
.question-card { border: 1px solid var(--border-med); min-width: 0; }
.question-card[disabled] { opacity: 0.6; }
.question-head { display: flex; gap: 0.75rem; align-items: flex-start; margin-bottom: 1rem; }
.question-num {
  flex: 0 0 auto; width: 26px; height: 26px; border-radius: 50%;
  background: var(--accent); color: var(--on-accent);
  font-size: var(--fs-sm); font-weight: 700;
  display: flex; align-items: center; justify-content: center;
}
.question-prompt { font-size: var(--fs-md); line-height: 1.45; color: var(--text); }

.option {
  display: flex; align-items: flex-start; gap: 0.65rem;
  padding: 0.7rem 0.85rem; margin-bottom: 0.45rem;
  background: var(--bg); border: 1px solid var(--border-med); border-radius: var(--radius-sm);
  cursor: pointer; transition: border-color var(--transition), background var(--transition);
}
.option:last-child { margin-bottom: 0; }
.option:hover { border-color: var(--accent); }
.option--picked { border-color: var(--accent); background: var(--accent-dim); }
.option input { accent-color: var(--accent); margin-top: 0.25rem; cursor: pointer; }
.option-text { color: var(--text); line-height: 1.45; }
.option:focus-within { outline: 2px solid var(--accent-bright); outline-offset: 2px; }

/* ── Envío ── */
.quiz-actions { display: flex; flex-direction: column; align-items: center; gap: 0.6rem; padding: 0.5rem 0 0; }
.submit-btn {
  padding: 0.75rem 2.25rem; font-family: inherit; font-size: var(--fs-btn); font-weight: 700;
  color: var(--on-accent); background: var(--accent); border: none; border-radius: var(--radius-sm);
  cursor: pointer; transition: filter var(--transition);
}
.submit-btn:hover:not(:disabled) { filter: brightness(1.1); }
.submit-btn:disabled { opacity: 0.45; cursor: not-allowed; }
.submit-error { color: var(--danger); font-size: var(--fs-sm); text-align: center; }

/* ── Resultado y errores ── */
.glyph {
  width: 56px; height: 56px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: var(--fs-xl); font-weight: 700;
}
.glyph--success { background: var(--success-dim); color: var(--success); }
.glyph--warn    { background: var(--warn-dim);    color: var(--warn); }
.glyph--danger  { background: var(--danger-dim);  color: var(--danger); }
.score { font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: var(--fs-3xl); color: var(--text); }
.score strong { color: var(--accent); }
.score-sep { color: var(--text-muted); margin: 0 0.1em; }

.spinner {
  width: 32px; height: 32px; border-radius: 50%;
  border: 2px solid var(--border-med); border-top-color: var(--accent);
  animation: seq-spin 0.8s linear infinite;
}

.quiz-foot { text-align: center; margin-top: 1.5rem; font-size: var(--fs-xs); letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-muted); }

.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }

@media (prefers-reduced-motion: reduce) {
  .card { animation: none; }
  .spinner { animation-duration: 2s; }
}
</style>
