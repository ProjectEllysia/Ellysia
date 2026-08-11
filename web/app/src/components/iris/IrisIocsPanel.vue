<template>
  <p class="ioc-hint">
    Valores <em>defanged</em> para pegar de forma segura sin activar enlaces.
  </p>
  <div v-for="cat in iocCategories" :key="cat.key" class="ioc-category">
    <div class="ioc-category-header">
      <span class="ioc-category-title">{{ cat.label }} ({{ data[cat.key].length }})</span>
    </div>
    <ul v-if="data[cat.key].length" class="ioc-list">
      <li v-for="(val, i) in data[cat.key]" :key="i" class="ioc-item">{{ defang(val) }}</li>
    </ul>
    <p v-else class="ioc-empty">Ninguno detectado.</p>
  </div>
  <button type="button" class="btn-export-csv" @click="exportCsv">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
    Exportar CSV
  </button>
</template>

<script setup>
/**
 * Contenido "con datos" del panel de IOCs de IrisReportViewer (A3).
 *
 * El padre conserva el chrome colapsable (botón + Transition) y los estados
 * de carga/vacío: usan clases (.rv-path-loading, .spinner, .rv-path-empty)
 * compartidas con otras secciones del informe (recorrido del correo,
 * resumen IA) — el CSS scoped de un componente no alcanza al árbol que
 * renderiza un hijo, así que moverlas aquí las habría dejado sin estilo en
 * esas otras secciones. Este componente solo recibe el dato ya resuelto.
 */
import { useUtils } from '@/composables/useUtils'

const props = defineProps({
  reportId: { type: [Number, null], default: null },
  data: { type: Object, required: true },
})

const { triggerDownload } = useUtils()

const iocCategories = [
  { key: 'domains', label: 'Dominios' },
  { key: 'urls', label: 'URLs' },
  { key: 'ips', label: 'IPs' },
  { key: 'emails', label: 'Emails' },
  { key: 'hashes', label: 'Hashes (SHA256)' },
]

// Neutraliza dominios/URLs/IPs/emails para que no se conviertan en enlaces
// clicables ni resuelvan accidentalmente al pegarlos en otra herramienta.
function defang(value) {
  return String(value)
    .replace(/https?/gi, (m) => m.replace(/^http/i, 'hxxp'))
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]')
}

function exportCsv() {
  const rows = [['type', 'value']]
  for (const cat of iocCategories) {
    for (const val of props.data[cat.key]) {
      rows.push([cat.key, val])
    }
  }
  const csv = rows.map(r => r.map(f => `"${String(f).replace(/"/g, '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  triggerDownload(blob, `iris_iocs_${props.reportId}.csv`)
}
</script>

<style scoped>
.ioc-hint {
  margin: 0;
  font-size: var(--fs-lg);
  color: var(--text-muted);
}

.ioc-category-header {
  margin-bottom: 0.4rem;
}

.ioc-category-title {
  font-size: var(--fs-lg);
  font-weight: 700;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.ioc-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
}

.ioc-item {
  padding: 0.5rem 0.75rem;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 6px;
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-lg);
  color: var(--text-dim);
  word-break: break-all;
}

.ioc-empty {
  margin: 0;
  font-size: var(--fs-lg);
  color: var(--text-muted);
  font-style: italic;
}

/* Duplicada del padre a propósito: .btn-export-csv también la usa el
   bloque de resumen IA, así que no es una clase exclusiva de IOCs que se
   pudiera mover entera — se mantiene aquí una copia pequeña y estable para
   que este componente sea visualmente autónomo. */
.btn-export-csv {
  align-self: flex-start;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.55rem 1rem;
  border-radius: 8px;
  background: var(--accent);
  color: var(--bg);
  border: none;
  font-size: var(--fs-lg);
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-export-csv:hover {
  opacity: 0.85;
}

.btn-export-csv svg {
  width: 16px;
  height: 16px;
}
</style>
