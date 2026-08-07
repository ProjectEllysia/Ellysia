<template>
  <div class="admin-page">
    <StarBackground />
    <Topbar title="Gestor de planes" backTo="/" />

    <main class="main">
      <p class="intro">
        Los planes y sus topes viven en base de datos, no en el código: lo que se
        cambie aquí surte efecto en la siguiente petición, sin desplegar.
      </p>

      <section class="section">
        <div class="section-head">
          <h2>Catálogo</h2>
          <button class="btn btn--primary" @click="startCreate">Nuevo plan</button>
        </div>

        <table class="table">
          <thead>
            <tr><th>Código</th><th>Nombre</th><th>Precio</th><th>Orden</th><th>Estado</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="plan in plans" :key="plan.id" :class="{ 'row--active': plan.id === selectedId }">
              <td class="mono">{{ plan.code }}</td>
              <td>{{ plan.name }}</td>
              <td class="mono">{{ euros(plan.monthlyPriceCents) }}</td>
              <td class="mono">{{ plan.rank }}</td>
              <td>
                <span v-if="plan.isDefault" class="tag tag--default">Por defecto</span>
                <span v-if="!plan.isPublic" class="tag">Oculto</span>
              </td>
              <td class="td-actions">
                <button class="btn-link" @click="select(plan)">Topes</button>
                <button v-if="!plan.isDefault" class="btn-link" @click="makeDefault(plan)">
                  Hacer por defecto
                </button>
                <button v-if="!plan.isDefault" class="btn-link btn-link--danger" @click="remove(plan)">
                  Borrar
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <!-- Alta de un plan -->
      <section v-if="creating" class="section">
        <h2>Nuevo plan</h2>
        <p class="section-desc">
          Nace sin topes: todas sus claves valen 0 hasta que se rellenen. Un plan
          a medio configurar no regala nada.
        </p>
        <form class="grid-form" @submit.prevent="create">
          <div class="form-group"><label>Código</label><input v-model="draft.code" class="inp" required minlength="2" /></div>
          <div class="form-group"><label>Nombre</label><input v-model="draft.name" class="inp" required minlength="2" /></div>
          <div class="form-group form-group--wide"><label>Lema</label><input v-model="draft.tagline" class="inp" /></div>
          <div class="form-group"><label>Precio (céntimos)</label><input v-model.number="draft.monthlyPriceCents" type="number" min="0" class="inp" /></div>
          <div class="form-group"><label>Añadido de organización</label><input v-model.number="draft.orgAddonPriceCents" type="number" min="0" class="inp" /></div>
          <div class="form-group"><label>Orden</label><input v-model.number="draft.rank" type="number" class="inp" /></div>
          <div class="form-actions">
            <button type="button" class="btn" @click="creating = false">Cancelar</button>
            <button type="submit" class="btn btn--primary">Crear</button>
          </div>
        </form>
      </section>

      <!-- Topes del plan seleccionado -->
      <section v-if="selected" class="section">
        <div class="section-head">
          <h2>Topes de {{ selected.name }}</h2>
          <button class="btn btn--primary" @click="saveLimits" :disabled="saving">
            {{ saving ? 'Guardando…' : 'Guardar topes' }}
          </button>
        </div>
        <p class="section-desc">
          Se guarda la tabla entera: lo que se ve aquí es exactamente lo que
          queda. Dejar una casilla vacía significa <strong>ilimitado</strong>;
          poner 0 significa <strong>no incluido</strong>. Una clave que se quite
          de la lista desaparece.
        </p>

        <table class="table">
          <thead>
            <tr><th>Clave</th><th>Periodo</th><th>Titular</th><th>Miembro</th></tr>
          </thead>
          <tbody>
            <tr v-for="key in limitKeys" :key="key.key">
              <td class="mono">{{ key.key }}</td>
              <td class="mono muted">{{ PERIODS[key.period] ?? key.period }}</td>
              <td><input v-model="holder[key.key]" type="number" min="0" class="inp inp--num" placeholder="∞" /></td>
              <td><input v-model="member[key.key]" type="number" min="0" class="inp inp--num" placeholder="∞" /></td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>

    <ConfirmModal
      :show="confirm.open"
      :title="confirm.title"
      :message="confirm.message"
      :danger="true"
      confirm-label="Confirmar"
      @confirm="confirm.action()"
      @cancel="confirm.open = false"
    />
  </div>
</template>

<script setup>
/**
 * Gestor del catálogo, solo para root.
 *
 * Las claves llegan del servidor (`GET /plans/limit-keys`) y se pintan como
 * filas fijas en vez de dejar escribirlas: una errata crearía una fila que
 * nadie consulta y dejaría la característica desactivada en silencio.
 *
 * El periodo tampoco se edita — lo dicta el catálogo de claves. Si lo eligiera
 * quien rellena, un contador mensual podría acabar declarado como existencias y
 * no reiniciarse nunca.
 */
import { ref, onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import { useApi } from '@/composables/useApi'
import { useToastStore } from '@/stores/toastStore'

const { apiFetch, apiError } = useApi()
const toast = useToastStore()

const PERIODS = { month: 'mensual', day: 'diario', stock: 'existencias' }

const plans = ref([])
const limitKeys = ref([])
const selected = ref(null)
const selectedId = ref(null)
const holder = ref({})
const member = ref({})
const creating = ref(false)
const saving = ref(false)
const draft = ref(emptyDraft())
const confirm = ref({ open: false, title: '', message: '', action: () => {} })

function emptyDraft() {
  return { code: '', name: '', tagline: '', monthlyPriceCents: 0, orgAddonPriceCents: 0, rank: 0 }
}

function euros(cents) {
  return `${(cents / 100).toFixed(2)} €`
}

async function loadPlans() {
  // El catálogo público oculta los planes con isPublic=false, así que para
  // gestionarlos hace falta verlos todos: se piden con sesión de root.
  const res = await fetch('/plans')
  if (!res.ok) return
  plans.value = (await res.json()).plans ?? []
}

async function loadKeys() {
  const res = await apiFetch('/plans/limit-keys')
  if (!res?.ok) return
  limitKeys.value = (await res.json()).keys ?? []
}

function select(plan) {
  selected.value = plan
  selectedId.value = plan.id
  holder.value = toForm(plan.limits?.holder)
  member.value = toForm(plan.limits?.member)
}

/** `null` (ilimitado) se representa con la casilla vacía. */
function toForm(limits) {
  const form = {}
  for (const [key, entry] of Object.entries(limits ?? {})) {
    form[key] = entry.value === null ? '' : entry.value
  }
  return form
}

function startCreate() {
  draft.value = emptyDraft()
  creating.value = true
}

async function create() {
  const res = await apiFetch('/plans', { method: 'POST', body: JSON.stringify(draft.value) })
  if (!res?.ok) {
    toast.show(await apiError(res, 'No se pudo crear el plan.'), 'error')
    return
  }
  toast.show('Plan creado.', 'success')
  creating.value = false
  await loadPlans()
}

async function saveLimits() {
  saving.value = true
  try {
    const limits = [
      ...toPayload(holder.value, 'holder'),
      ...toPayload(member.value, 'member'),
    ]
    const res = await apiFetch(`/plans/${selected.value.id}/limits`, {
      method: 'PUT',
      body: JSON.stringify({ limits }),
    })
    if (!res?.ok) {
      toast.show(await apiError(res, 'No se pudieron guardar los topes.'), 'error')
      return
    }
    toast.show('Topes guardados.', 'success')
    await loadPlans()
    select(plans.value.find((plan) => plan.id === selectedId.value) ?? selected.value)
  } finally {
    saving.value = false
  }
}

/**
 * Solo se mandan las claves que alguien tocó. Una casilla que nunca se rellenó
 * no es "ilimitado": es una clave que este plan no declara, y que por tanto
 * vale 0 (fallo cerrado).
 */
function toPayload(form, scope) {
  return Object.entries(form)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([limitKey, value]) => ({
      limitKey,
      scope,
      value: value === '' ? null : Number(value),
    }))
}

function makeDefault(plan) {
  confirm.value = {
    open: true,
    title: `¿Hacer de "${plan.name}" el plan por defecto?`,
    message: 'Lo recibirán todas las cuentas sin suscripción vigente, y las que '
      + 'hoy están en el actual pasarán a este.',
    action: async () => {
      confirm.value.open = false
      const res = await apiFetch(`/plans/${plan.id}/default`, { method: 'PUT' })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo cambiar.'), 'error')
        return
      }
      await loadPlans()
    },
  }
}

function remove(plan) {
  confirm.value = {
    open: true,
    title: `¿Borrar el plan "${plan.name}"?`,
    message: 'Solo se puede si nadie lo tiene contratado.',
    action: async () => {
      confirm.value.open = false
      const res = await apiFetch(`/plans/${plan.id}`, { method: 'DELETE' })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo borrar.'), 'error')
        return
      }
      if (selectedId.value === plan.id) selected.value = null
      await loadPlans()
    },
  }
}

onMounted(async () => {
  await Promise.all([loadPlans(), loadKeys()])
})
</script>

<style scoped>
.admin-page { min-height: 100vh; background: var(--bg); }
.main { max-width: 1080px; margin: 0 auto; padding: 2rem 1.5rem 4rem; display: flex; flex-direction: column; gap: 1.5rem; }
.intro { color: var(--text-muted); font-size: var(--fs-md); max-width: 62ch; }

.section {
  background: var(--surface); border: 1px solid var(--border-solid);
  border-radius: 12px; padding: 1.5rem;
}
.section-head { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
.section h2 { font-size: var(--fs-xl); font-weight: 600; color: var(--text); }
.section-desc { font-size: var(--fs-body); color: var(--text-muted); margin-top: 0.5rem; max-width: 72ch; }

.table { width: 100%; border-collapse: collapse; margin-top: 1.2rem; font-size: var(--fs-md); }
.table th {
  text-align: left; padding: 0.5rem 0.6rem;
  font-size: var(--fs-body); font-weight: 500; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.08em;
  border-bottom: 1px solid var(--border);
}
.table td { padding: 0.55rem 0.6rem; border-bottom: 1px solid var(--border); color: var(--text-dim); }
.row--active { background: var(--accent-dim); }
.mono { font-family: var(--font-mono); font-size: var(--fs-body); }
.muted { color: var(--text-muted); }
.td-actions { text-align: right; display: flex; gap: 0.8rem; justify-content: flex-end; }

.tag {
  display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px;
  font-size: var(--fs-body); color: var(--text-muted);
  border: 1px solid var(--border-med); margin-right: 0.3rem;
}
.tag--default { color: var(--accent-bright); border-color: var(--accent); }

.grid-form {
  margin-top: 1.2rem; display: grid; gap: 0.9rem;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
}
.form-group { display: flex; flex-direction: column; gap: 0.35rem; }
.form-group--wide { grid-column: 1 / -1; }
.form-group label { font-size: var(--fs-body); color: var(--text-dim); }
.form-actions { grid-column: 1 / -1; display: flex; gap: 0.7rem; justify-content: flex-end; }

.inp {
  padding: 0.5rem 0.7rem; border-radius: 6px;
  background: var(--bg); color: var(--text);
  border: 1px solid var(--border-med);
  width: 100%;
}
.inp:focus { outline: none; border-color: var(--accent); }
.inp--num { max-width: 110px; font-family: var(--font-mono); }

.btn {
  font-family: var(--font-epic); font-size: var(--fs-body); font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
  padding: 0.55rem 1.1rem; border-radius: 3px;
  border: 1px solid var(--border-med); color: var(--text-dim);
  transition: all var(--transition);
}
.btn--primary { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); }
.btn--primary:hover { background: var(--accent); color: var(--on-accent); }
.btn:disabled { opacity: 0.6; cursor: not-allowed; }

.btn-link { font-size: var(--fs-body); color: var(--text-muted); }
.btn-link:hover { color: var(--text); }
.btn-link--danger:hover { color: var(--danger); }
</style>
