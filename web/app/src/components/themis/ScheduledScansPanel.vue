<template>
  <div class="scheduled-card">
    <div class="scheduled-header" @click="expanded = !expanded">
      <div class="scheduled-header-left">
        <span class="scheduled-title">Escaneos Programados</span>
        <span class="scheduled-badge">{{ filtered.length }}</span>
      </div>
      <button class="btn-toggle" :class="{ open: expanded }" :aria-label="expanded ? 'Colapsar' : 'Expandir'">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9" /></svg>
      </button>
    </div>
    <transition name="panel-slide">
      <div v-if="expanded" class="scheduled-body">
        <button class="btn-new" @click="$emit('toggleForm')">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
          Nuevo escaneo programado
        </button>
        <transition name="form-fade">
          <div v-if="scheduling.showForm" class="create-form">
            <div class="form-row">
              <div v-for="f in scheduleFields" :key="f.key" class="field" :class="`field-${f.size || 'lg'}`">
                <label>{{ f.label }}</label><input v-model="form.args[f.key]" :placeholder="f.placeholder" />
              </div>
            </div>
            <div class="form-row">
              <div class="field field-sm"><label>Programación</label>
                <select v-model="form.scheduleType"><option value="interval">Intervalo</option><option value="cron">Cron</option></select>
              </div>
            </div>
            <div class="form-row" v-if="form.scheduleType === 'interval'">
              <div class="field field-xs"><label>Cada</label><input v-model.number="form.scheduleConfig.every" type="number" min="1" class="no-spin" /></div>
              <div class="field field-sm"><label>Unidad</label>
                <select v-model="form.scheduleConfig.unit"><option value="minutes">Minutos</option><option value="hours">Horas</option><option value="days">Días</option></select>
              </div>
            </div>
            <div class="form-row" v-if="form.scheduleType === 'cron'">
              <div class="field field-md"><label>Expresión Cron</label><input v-model="form.scheduleConfig.cron" placeholder="0 2 * * *" /></div>
            </div>
            <button class="btn-create" :disabled="scheduling.submitting" @click="handleCreate">
              <span v-if="!scheduling.submitting">Crear</span>
              <span v-else class="btn-spin"></span>
            </button>
          </div>
        </transition>
        <div v-if="scheduled.loading" class="scheduled-loading"><span class="spinner"></span> Cargando...</div>
        <div v-else-if="!filtered.length" class="scheduled-empty">
          <span>No hay escaneos programados de {{ activeTab.toUpperCase() }}</span>
        </div>
        <table v-else class="scheduled-table">
          <thead><tr><th>ID</th><th>Tipo</th><th>Argumentos</th><th>Programación</th><th>Estado</th><th>Prox. ejecución</th><th></th></tr></thead>
          <tbody>
            <tr v-for="ps in filtered" :key="ps.id" :class="{ inactive: !ps.isActive }">
              <td class="mono">{{ ps.id }}</td>
              <td><span class="type-badge" :class="ps.scanType">{{ ps.scanType }}</span></td>
              <td class="args-cell" :title="formatArgs(ps.scanType, ps.arguments)">{{ formatArgs(ps.scanType, ps.arguments) }}</td>
              <td class="mono">{{ formatSchedule(ps.scheduleType, ps.scheduleConfig) }}</td>
              <td><span class="status-dot" :class="ps.isActive ? 'active' : 'revoked'"></span>{{ ps.isActive ? 'Activo' : 'Revocado' }}</td>
              <td class="mono text-muted">{{ formatDate(ps.nextRunAt) }}</td>
              <td class="actions-cell">
                <button v-if="ps.isActive" class="btn-action btn-revoke" title="Revocar" @click="handleDeactivate(ps.id)">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" /><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" /></svg>
                </button>
                <button class="btn-action btn-delete" title="Eliminar" @click="handleDelete(ps.id)">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" /></svg>
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { SCAN_TYPES } from '@/constants/scanTypes'

const props = defineProps({ scheduled: { type: Object, required: true }, scheduling: { type: Object, required: true }, activeTab: { type: String, required: true } })
const emit = defineEmits(['create', 'deactivate', 'delete', 'toggleForm'])
const expanded = ref(false)

const filtered = computed(() => props.scheduled.scans.filter(s => s.scanType === props.activeTab))
const form = reactive({ args: {}, scheduleType: 'interval', scheduleConfig: { every: 60, unit: 'minutes' } })

const scheduleFields = computed(() => SCAN_TYPES[props.activeTab]?.scheduleFields ?? [])
watch(() => props.activeTab, (type) => {
  form.args = { ...(SCAN_TYPES[type]?.defaultArgs ?? {}) }
  form.scheduleType = 'interval'
  form.scheduleConfig = { every: 60, unit: 'minutes' }
}, { immediate: true })

function handleCreate() { emit('create', { scan_type: props.activeTab, arguments: { ...form.args }, schedule_type: form.scheduleType, schedule_config: { ...form.scheduleConfig } }) }
function handleDeactivate(id) { if (confirm('Desactivar este escaneo programado?')) emit('deactivate', id) }
function handleDelete(id) { if (confirm('Eliminar permanentemente este escaneo programado?')) emit('delete', id) }
function formatArgs(type, args) {
  return SCAN_TYPES[type]?.formatArgs?.(args) ?? '—'
}
function formatSchedule(type, config) {
  if (!config) return '—'
  if (type === 'interval') { const u = { minutes: 'min', hours: 'h', days: 'd' }; return `cada ${config.every} ${u[config.unit] || config.unit}` }
  if (type === 'cron') return config.cron
  return '—'
}
function formatDate(iso) { if (!iso) return '—'; return new Date(iso).toLocaleString('es-ES', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) }
</script>

<style scoped>
.scheduled-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 1.1rem; overflow: hidden; }
.scheduled-header { display: flex; align-items: center; justify-content: space-between; padding: 0.85rem 1.25rem; cursor: pointer; user-select: none; transition: background 0.2s; }
.scheduled-header:hover { background: var(--surface-2); }
.scheduled-header-left { display: flex; align-items: center; gap: 0.4rem; }
.scheduled-title { font-weight: 600; color: var(--text); font-size: 1.58rem; font-family: var(--font-display); }
.scheduled-badge { font-size: 1.19rem; color: var(--accent); background: var(--accent-dim); padding: 0.1rem 0.45rem; border-radius: 8px; font-family: var(--font-mono); }
.btn-toggle { background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.2rem; transition: transform 0.25s; }
.btn-toggle.open { transform: rotate(180deg); }
.scheduled-body { padding: 0 1.25rem 1.1rem; }
.panel-slide-enter-active, .panel-slide-leave-active { transition: all 0.25s ease; overflow: hidden; }
.panel-slide-enter-from, .panel-slide-leave-to { max-height: 0; opacity: 0; }
.panel-slide-enter-to, .panel-slide-leave-from { max-height: 2000px; opacity: 1; }
.btn-new { display: inline-flex; align-items: center; gap: 0.35rem; height: 32px; padding: 0 0.85rem; margin-bottom: 0.85rem; background: var(--accent-dim); border: 1px solid var(--accent); color: var(--accent-bright); font-weight: 600; font-size: 1.37rem; border-radius: 6px; cursor: pointer; transition: all 0.2s; }
.btn-new:hover { background: var(--accent); color: var(--on-accent); }
.create-form { background: var(--surface-2); border: 1px solid var(--border-solid); border-radius: 8px; padding: 0.85rem 1.1rem; margin-bottom: 0.85rem; }
.form-fade-enter-active, .form-fade-leave-active { transition: all 0.2s ease; }
.form-fade-enter-from, .form-fade-leave-to { opacity: 0; transform: translateY(-6px); }
.form-row { display: flex; gap: 0.6rem; margin-bottom: 0.65rem; flex-wrap: wrap; }
.field { display: flex; flex-direction: column; gap: 0.25rem; flex: 1; min-width: 110px; }
.field label { font-size: 1.26rem; color: var(--text-muted); font-weight: 500; }
.field input, .field select { padding: 0.45rem 0.6rem; background: var(--surface-3); border: 1px solid var(--border-solid); border-radius: 6px; color: var(--text); font-size: 1.4rem; outline: none; transition: border-color 0.2s; }
.field input:focus, .field select:focus { border-color: var(--accent); }
.field-xs { flex: 0 0 70px; min-width: 60px; }
.field-sm { flex: 0 0 130px; min-width: 110px; }
.field-md { flex: 0 0 170px; min-width: 140px; }
.field-lg { flex: 2; min-width: 190px; }
.no-spin::-webkit-outer-spin-button, .no-spin::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.no-spin { -moz-appearance: textfield; }
.btn-create { height: 32px; padding: 0 1.1rem; background: var(--accent); border: 1px solid var(--accent-bright); color: var(--on-accent); font-weight: 600; font-size: 1.37rem; border-radius: 6px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 0.35rem; transition: opacity 0.2s; margin-top: 0.2rem; min-width: 64px; }
.btn-create:hover:not(:disabled) { opacity: 0.85; }
.btn-create:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-spin { width: 13px; height: 13px; border: 2px solid rgba(0,0,0,0.2); border-top-color: var(--on-accent); border-radius: 50%; animation: seq-spin 0.6s linear infinite; display: inline-block; }
.scheduled-loading, .scheduled-empty { display: flex; align-items: center; justify-content: center; gap: 0.4rem; padding: 2rem 1rem; color: var(--text-muted); font-size: 1.43rem; }
.scheduled-empty { flex-direction: column; }
.spinner { width: 14px; height: 14px; border: 2px solid var(--text-muted); border-top-color: transparent; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }
.scheduled-table { width: 100%; border-collapse: collapse; }
.scheduled-table th { text-align: left; padding: 0.5rem 0.55rem; font-size: 1.19rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); font-weight: 600; background: var(--surface-2); }
.scheduled-table td { padding: 0.5rem 0.55rem; font-size: 1.4rem; color: var(--text); border-top: 1px solid var(--border); }
.scheduled-table tr:hover td { background: var(--surface-2); }
.scheduled-table tr.inactive td { opacity: 0.5; }
.mono { font-family: var(--font-mono); font-size: 1.31rem; }
.text-muted { color: var(--text-muted); }
.args-cell { max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.type-badge { text-transform: uppercase; font-size: 1.09rem; font-weight: 700; letter-spacing: 0.03em; padding: 0.1rem 0.4rem; border-radius: 5px; }
.type-badge.nmap { color: var(--success); background: var(--success-dim); }
.type-badge.nikto { color: var(--warn); background: var(--warn-dim); }
.type-badge.openvas { color: var(--danger); background: var(--danger-dim); }
.type-badge.lybra { color: var(--accent-bright); background: var(--accent-dim); }
.status-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 0.3rem; }
.status-dot.active { background: var(--success); }
.status-dot.revoked { background: var(--text-muted); }
.actions-cell { white-space: nowrap; text-align: right; }
.btn-action { background: none; border: none; padding: 0.3rem 0.35rem; cursor: pointer; border-radius: 5px; transition: all 0.15s; }
.btn-revoke { color: var(--warn); }
.btn-revoke:hover { background: var(--warn-dim); }
.btn-delete { color: var(--danger); }
.btn-delete:hover { background: var(--danger-dim); }
</style>
