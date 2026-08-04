<template>
  <div class="editor">
    <div class="editor-toolbar">
      <span class="doc-id">Editando Doc #{{ doc.id }}</span>
      <div class="toolbar-spacer"></div>
      <button type="button" class="toolbar-btn" :disabled="saving" @click="emit('cancel')">Cancelar</button>
      <button type="button" class="toolbar-btn toolbar-save" :disabled="saving" @click="save">
        {{ saving ? 'Guardando…' : 'Guardar' }}
      </button>
    </div>

    <div class="editor-body">
      <!-- ── TÍTULO ── -->
      <section class="editor-section">
        <label class="field-label" for="ed-subtitle">Título</label>
        <input
          id="ed-subtitle"
          v-model="form.subtitle"
          type="text"
          class="field-input field-title"
          maxlength="256"
          placeholder="Título de la píldora"
        />
        <p v-if="errors.subtitle" class="field-error">{{ errors.subtitle }}</p>
      </section>

      <!-- ── INTRODUCCIÓN ── -->
      <section class="editor-section">
        <label class="field-label" for="ed-intro">Introducción</label>
        <textarea
          id="ed-intro"
          v-model="form.intro"
          class="field-input field-area"
          rows="6"
          placeholder="Texto introductorio. Separa los párrafos con una línea en blanco."
        ></textarea>
      </section>

      <!-- ── RECOMENDACIONES ── -->
      <section class="editor-section">
        <div class="section-head">
          <span class="field-label">Recomendaciones</span>
          <button type="button" class="add-btn add-btn--primary" @click="addTip">+ Añadir recomendación</button>
        </div>

        <div v-if="!form.tips.length" class="empty-hint">Sin recomendaciones. Añade la primera.</div>

        <div v-for="(tip, i) in form.tips" :key="i" class="tip-card">
          <div class="tip-card-head">
            <span class="tip-num">{{ i + 1 }}</span>
            <div class="tip-card-actions">
              <button type="button" class="icon-btn" title="Subir" :disabled="i === 0" @click="moveTip(i, -1)">↑</button>
              <button type="button" class="icon-btn" title="Bajar" :disabled="i === form.tips.length - 1" @click="moveTip(i, 1)">↓</button>
              <button type="button" class="icon-btn icon-danger" title="Eliminar" @click="removeTip(i)">✕</button>
            </div>
          </div>

          <label class="field-sublabel">Título de la recomendación</label>
          <input
            v-model="tip.headline"
            type="text"
            class="field-input"
            maxlength="150"
            placeholder="Título de la recomendación"
          />
          <p v-if="errors.tips[i]?.headline" class="field-error">{{ errors.tips[i].headline }}</p>

          <label class="field-sublabel">Cuerpo</label>
          <textarea
            v-model="tip.body"
            class="field-input field-area"
            rows="3"
            placeholder="Desarrollo de la recomendación"
          ></textarea>
          <p v-if="errors.tips[i]?.body" class="field-error">{{ errors.tips[i].body }}</p>

          <div class="links-block">
            <div class="section-head">
              <span class="field-sublabel">Enlaces</span>
              <button type="button" class="add-btn add-btn--sm" @click="addLink(tip)">+ Enlace</button>
            </div>
            <div v-for="(link, j) in tip.links" :key="j" class="link-row">
              <input v-model="link.text" type="text" class="field-input link-text" placeholder="Texto" />
              <input v-model="link.url" type="url" class="field-input link-url" placeholder="https://…" />
              <button type="button" class="icon-btn icon-danger" title="Quitar enlace" @click="removeLink(tip, j)">✕</button>
            </div>
          </div>
        </div>
      </section>

      <!-- ── PREGUNTAS DEL TEST ── -->
      <section class="editor-section">
        <div class="section-head">
          <span class="field-label">Preguntas del test</span>
          <button
            type="button"
            class="add-btn add-btn--primary"
            :disabled="form.questions.length >= 20"
            @click="addQuestion"
          >+ Añadir pregunta</button>
        </div>

        <p class="section-hint">
          Sin preguntas no se puede lanzar una campaña. Marca la opción correcta de cada una.
        </p>

        <div v-if="!form.questions.length" class="empty-hint">Sin preguntas. Añade la primera.</div>

        <div v-for="(question, i) in form.questions" :key="i" class="tip-card">
          <div class="tip-card-head">
            <span class="tip-num">{{ i + 1 }}</span>
            <div class="tip-card-actions">
              <button type="button" class="icon-btn" title="Subir" :disabled="i === 0" @click="moveQuestion(i, -1)">↑</button>
              <button type="button" class="icon-btn" title="Bajar" :disabled="i === form.questions.length - 1" @click="moveQuestion(i, 1)">↓</button>
              <button type="button" class="icon-btn icon-danger" title="Eliminar" @click="removeQuestion(i)">✕</button>
            </div>
          </div>

          <label class="field-sublabel">Enunciado</label>
          <textarea
            v-model="question.prompt"
            class="field-input field-area"
            rows="2"
            maxlength="300"
            placeholder="¿Qué harías si recibes un SMS que dice ser de tu banco?"
          ></textarea>
          <p v-if="errors.questions[i]?.prompt" class="field-error">{{ errors.questions[i].prompt }}</p>

          <div class="links-block">
            <div class="section-head">
              <span class="field-sublabel">Opciones · marca la correcta</span>
              <button
                type="button"
                class="add-btn add-btn--sm"
                :disabled="question.options.length >= 4"
                @click="addOption(question)"
              >+ Opción</button>
            </div>

            <div v-for="(option, j) in question.options" :key="j" class="option-row">
              <input
                type="radio"
                class="option-radio"
                :name="`correct-${i}`"
                :checked="question.correctIndex === j"
                :title="`Marcar la opción ${j + 1} como correcta`"
                :aria-label="`Opción ${j + 1} correcta`"
                @change="question.correctIndex = j"
              />
              <input
                v-model="question.options[j]"
                type="text"
                class="field-input option-text"
                maxlength="200"
                :placeholder="`Opción ${j + 1}`"
              />
              <button
                type="button"
                class="icon-btn icon-danger"
                title="Quitar opción"
                :disabled="question.options.length <= 2"
                @click="removeOption(question, j)"
              >✕</button>
            </div>
            <p v-if="errors.questions[i]?.options" class="field-error">{{ errors.questions[i].options }}</p>
          </div>
        </div>
      </section>

      <!-- ── CIERRE ── -->
      <section class="editor-section">
        <label class="field-label" for="ed-closing">Cierre</label>
        <textarea
          id="ed-closing"
          v-model="form.closing"
          class="field-input field-area"
          rows="3"
          placeholder="Conclusión o llamada a la acción"
        ></textarea>
      </section>

      <!-- ── CONTACTO ── -->
      <section class="editor-section">
        <label class="field-label" for="ed-contact">Email de contacto</label>
        <input
          id="ed-contact"
          v-model="form.contactEmail"
          type="email"
          class="field-input"
          maxlength="128"
          placeholder="seguridad@empresa.com"
        />
      </section>
    </div>
  </div>
</template>

<script setup>
import { reactive } from 'vue'

const props = defineProps({
  doc: { type: Object, required: true },
  saving: { type: Boolean, default: false },
})
const emit = defineEmits(['save', 'cancel'])

/** Copia profunda de la píldora para que "Cancelar" descarte los cambios. */
const pill = props.doc.pill ?? {}
const form = reactive({
  subtitle: pill.subtitle ?? props.doc.title ?? '',
  intro: pill.intro ?? '',
  closing: pill.closing ?? '',
  contactEmail: pill.contactEmail ?? '',
  company: pill.company ?? '',
  tips: (pill.tips ?? []).map(t => ({
    headline: t.headline ?? '',
    body: t.body ?? '',
    links: (t.links ?? []).map(l => ({ text: l.text ?? '', url: l.url ?? '' })),
  })),
  // Las preguntas TIENEN que viajar de ida y vuelta: el backend reemplaza el
  // quiz entero con lo que llegue en el PUT (save_questions borra e inserta),
  // así que omitirlas aquí borraba el test de la píldora al guardar.
  questions: (pill.questions ?? []).map(q => ({
    prompt: q.prompt ?? '',
    options: [...(q.options ?? [])],
    correctIndex: q.correctIndex ?? 0,
  })),
})

const errors = reactive({ subtitle: '', tips: [], questions: [] })

function addTip() {
  form.tips.push({ headline: '', body: '', links: [] })
}
function removeTip(i) {
  form.tips.splice(i, 1)
}
function moveTip(i, dir) {
  const j = i + dir
  if (j < 0 || j >= form.tips.length) return
  const [t] = form.tips.splice(i, 1)
  form.tips.splice(j, 0, t)
}
function addLink(tip) {
  tip.links.push({ text: '', url: '' })
}
function removeLink(tip, j) {
  tip.links.splice(j, 1)
}

function addQuestion() {
  form.questions.push({ prompt: '', options: ['', ''], correctIndex: 0 })
}
function removeQuestion(i) {
  form.questions.splice(i, 1)
}
function moveQuestion(i, dir) {
  const j = i + dir
  if (j < 0 || j >= form.questions.length) return
  const [q] = form.questions.splice(i, 1)
  form.questions.splice(j, 0, q)
}
function addOption(question) {
  if (question.options.length >= 4) return
  question.options.push('')
}
function removeOption(question, j) {
  if (question.options.length <= 2) return
  question.options.splice(j, 1)
  // La correcta se desplaza con las opciones; si era la borrada, vuelve a la 0.
  if (question.correctIndex === j) question.correctIndex = 0
  else if (question.correctIndex > j) question.correctIndex -= 1
}

/** Refleja AegisQuizQuestionUpdateSchema del backend (aegis/schemas.py). */
function validate() {
  errors.subtitle = ''
  errors.tips = form.tips.map(() => ({ headline: '', body: '' }))
  errors.questions = form.questions.map(() => ({ prompt: '', options: '' }))
  let ok = true

  if (!form.subtitle.trim()) {
    errors.subtitle = 'El título es obligatorio.'
    ok = false
  }
  form.tips.forEach((tip, i) => {
    if (!tip.headline.trim()) { errors.tips[i].headline = 'El título es obligatorio.'; ok = false }
    else if (tip.headline.length > 150) { errors.tips[i].headline = 'Máximo 150 caracteres.'; ok = false }
    if (!tip.body.trim()) { errors.tips[i].body = 'El cuerpo es obligatorio.'; ok = false }
  })
  form.questions.forEach((question, i) => {
    if (!question.prompt.trim()) { errors.questions[i].prompt = 'El enunciado es obligatorio.'; ok = false }
    else if (question.prompt.length > 300) { errors.questions[i].prompt = 'Máximo 300 caracteres.'; ok = false }

    const filled = question.options.filter(o => o.trim())
    if (filled.length !== question.options.length) {
      errors.questions[i].options = 'No dejes ninguna opción vacía.'
      ok = false
    } else if (filled.length < 2 || filled.length > 4) {
      errors.questions[i].options = 'Cada pregunta necesita entre 2 y 4 opciones.'
      ok = false
    } else if (question.correctIndex < 0 || question.correctIndex >= question.options.length) {
      errors.questions[i].options = 'Marca cuál es la opción correcta.'
      ok = false
    }
  })
  return ok
}

function save() {
  if (!validate()) return
  const payload = {
    subtitle: form.subtitle.trim(),
    intro: form.intro,
    closing: form.closing,
    contactEmail: form.contactEmail.trim(),
    company: form.company,
    tips: form.tips.map(t => ({
      headline: t.headline.trim(),
      body: t.body,
      links: t.links
        .filter(l => l.text.trim() && l.url.trim())
        .map(l => ({ text: l.text.trim(), url: l.url.trim() })),
    })),
    questions: form.questions.map(q => ({
      prompt: q.prompt.trim(),
      options: q.options.map(o => o.trim()),
      correctIndex: q.correctIndex,
    })),
  }
  emit('save', payload)
}
</script>

<style scoped>
.editor { height: 100%; display: flex; flex-direction: column; }
.editor-toolbar { display: flex; align-items: center; gap: 0.4rem; padding: 0.5rem 0.85rem; background: var(--surface); border-bottom: 1px solid var(--border); font-size: var(--fs-md); color: var(--text-muted); }
.doc-id { font-weight: 600; color: var(--text-dim); font-family: var(--font-mono); font-size: var(--fs-md); }
.toolbar-spacer { flex: 1; }
.toolbar-btn { padding: 0.25rem 0.7rem; font-size: var(--fs-md); font-weight: 600; border-radius: 5px; border: 1px solid var(--border); background: var(--bg); color: var(--text-dim); cursor: pointer; transition: all 0.2s; }
.toolbar-btn:hover:not(:disabled) { background: var(--accent); color: var(--on-accent); border-color: var(--accent); }
.toolbar-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.toolbar-save { background: var(--accent); color: var(--on-accent); border-color: var(--accent); }

.editor-body { padding: 1.25rem; overflow-y: auto; flex: 1; }
.editor-section { margin-bottom: 1.5rem; }
.section-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem; }

.field-label { display: block; font-size: var(--fs-lg); font-weight: 700; color: var(--accent); margin-bottom: 0.4rem; font-family: var(--font-display); text-transform: uppercase; letter-spacing: 0.04em; }
.field-sublabel { display: block; font-size: var(--fs-md); font-weight: 600; color: var(--text-muted); margin: 0.5rem 0 0.25rem; }
.field-input { width: 100%; box-sizing: border-box; padding: 0.5rem 0.65rem; font-size: var(--fs-input); font-family: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--border); border-radius: 6px; transition: border-color 0.15s; }
.field-input:focus { outline: none; border-color: var(--accent); }
.field-title { font-size: var(--fs-lg); font-weight: 700; font-family: var(--font-display); }
.field-area { resize: vertical; line-height: 1.5; min-height: 3rem; }
.field-error { color: var(--danger); font-size: var(--fs-md); margin: 0.25rem 0 0; }

.add-btn { padding: 0.25rem 0.6rem; font-size: var(--fs-md); font-weight: 600; border-radius: 5px; border: 1px solid var(--accent); background: none; color: var(--accent); cursor: pointer; transition: all 0.15s; }
.add-btn:hover { background: var(--accent); color: var(--on-accent); }
.add-btn--sm { font-size: var(--fs-body); padding: 0.15rem 0.45rem; }
.add-btn--primary { background: var(--accent); color: var(--on-accent); border-color: var(--accent); font-size: var(--fs-lg); font-weight: 700; padding: 0.45rem 1rem; border-radius: 7px; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
.add-btn--primary:hover { background: var(--accent); filter: brightness(1.1); color: var(--on-accent); }
.empty-hint { font-size: var(--fs-md); color: var(--text-muted); padding: 0.5rem 0; }

.tip-card { border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem; margin-bottom: 0.85rem; background: var(--surface); }
.tip-card-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem; }
.tip-num { width: 22px; height: 22px; border-radius: 50%; background: var(--accent); color: var(--on-accent); font-size: var(--fs-md); font-weight: 700; display: flex; align-items: center; justify-content: center; }
.tip-card-actions { display: flex; gap: 0.25rem; }
.icon-btn { width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; font-size: var(--fs-md); border: 1px solid var(--border); border-radius: 5px; background: var(--bg); color: var(--text-dim); cursor: pointer; transition: all 0.15s; }
.icon-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.icon-btn:disabled { opacity: 0.35; cursor: not-allowed; }
.icon-danger:hover:not(:disabled) { border-color: var(--danger); color: var(--danger); }

.links-block { margin-top: 0.65rem; padding-top: 0.5rem; border-top: 1px dashed var(--border); }
.link-row { display: flex; gap: 0.4rem; margin-bottom: 0.35rem; align-items: center; }
.link-text { flex: 1; }
.link-url { flex: 1.4; }

.section-hint { font-size: var(--fs-sm); color: var(--text-muted); margin: -0.25rem 0 0.6rem; }
.option-row { display: flex; gap: 0.4rem; margin-bottom: 0.35rem; align-items: center; }
.option-radio { accent-color: var(--accent); width: 16px; height: 16px; flex: 0 0 auto; cursor: pointer; }
.option-text { flex: 1; }
</style>
