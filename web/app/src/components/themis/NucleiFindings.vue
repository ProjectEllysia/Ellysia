<template>
  <div class="nuclei-findings">
    <div v-if="!findings.length" class="nf-empty">Sin hallazgos.</div>
    <template v-else>
      <TransitionGroup tag="ul" name="nf-item" class="nf-list">
        <li v-for="f in visible" :key="f.id" class="nf-item" :class="{ potential: !f.confirmed }">
          <span class="nf-prio" :class="(f.priority || 'INFO').toLowerCase()">{{ PRIO_LABEL[f.priority] || f.priority }}</span>
          <div class="nf-main">
            <div class="nf-title-row">
              <span class="nf-conf" :class="f.confirmed ? 'confirmed' : 'hypothesis'"
                :title="f.confirmed ? `Comprobado activamente (QoD ${f.qod})` : `Deducido (QoD ${f.qod})`">
                {{ f.confirmed ? 'Comprobado' : 'Potencial' }}
              </span>
              <span class="nf-title">{{ f.title }}</span>
            </div>
            <div class="nf-meta">
              <span v-if="f.port" class="nf-tag mono">{{ f.service || 'svc' }}:{{ f.port }}</span>
              <span v-for="cve in (f.cveIds || [])" :key="cve" class="nf-tag cve">{{ cve }}</span>
              <span v-if="f.inKev" class="nf-tag kev" title="En la lista CISA de vulnerabilidades explotadas activamente">KEV · explotada</span>
              <span v-if="f.epssScore != null" class="nf-tag epss" title="Probabilidad de explotación en 30 días (EPSS)">EPSS {{ Math.round(f.epssScore * 100) }}%</span>
              <span v-if="f.cvssScore != null" class="nf-tag cvss">CVSS {{ f.cvssScore }}</span>
              <span v-if="f.state && f.state !== 'open'" class="nf-tag state" :class="f.state">{{ STATE_LABEL[f.state] || f.state }}</span>
              <span v-if="f.source && f.source !== 'nuclei'" class="nf-tag src" :title="`Corroborado por ${f.source}`">+{{ f.source }}</span>
            </div>
          </div>
        </li>
      </TransitionGroup>

      <button v-if="visible.length < sorted.length" type="button" class="nf-load-more" @click="page++">
        Ver más ({{ visible.length }} de {{ sorted.length }})
      </button>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'

const props = defineProps({
  findings: { type: Array, default: () => [] },
})

// Mismo orden y vocabulario que LybraResults.vue: la prioridad ya viene
// calculada por el backend (score_finding), aquí solo se ordena y se pinta.
const PRIO_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }
const PRIO_LABEL = { CRITICAL: 'CRÍTICA', HIGH: 'ALTA', MEDIUM: 'MEDIA', LOW: 'BAJA', INFO: 'INFO' }
const STATE_LABEL = { fixed: 'Corregido', regressed: 'Regresado', accepted: 'Aceptado' }

const PAGE_SIZE = 20
const page = ref(1)
watch(() => props.findings, () => { page.value = 1 })

const sorted = computed(() => [...props.findings].sort((a, b) => {
  const pa = PRIO_ORDER[a.priority] ?? 5
  const pb = PRIO_ORDER[b.priority] ?? 5
  if (pa !== pb) return pa - pb
  if (!!a.confirmed !== !!b.confirmed) return a.confirmed ? -1 : 1
  return (b.cvssScore || 0) - (a.cvssScore || 0)
}))
const visible = computed(() => sorted.value.slice(0, page.value * PAGE_SIZE))
</script>

<style scoped>
.nuclei-findings { display: flex; flex-direction: column; gap: 0.5rem; }
.nf-empty { font-size: var(--fs-lg); color: var(--text-muted); padding: 0.85rem 0; text-align: center; }

.nf-list { list-style: none; display: flex; flex-direction: column; gap: 0.35rem; margin: 0; padding: 0; max-height: 340px; overflow-y: auto; }
.nf-item {
  display: flex; align-items: flex-start; gap: 0.6rem;
  padding: 0.55rem 0.7rem; background: var(--surface-2); border: 1px solid var(--border);
  border-left: 3px solid var(--border-solid); border-radius: 7px;
}
.nf-item.potential { border-style: dashed; opacity: 0.92; }
.nf-prio { flex-shrink: 0; font-size: var(--fs-md); font-weight: 700; letter-spacing: 0.02em; text-transform: uppercase; padding: 0.15rem 0.4rem; border-radius: 5px; min-width: 52px; text-align: center; }
.nf-prio.critical { color: var(--danger); background: var(--danger-dim); }
.nf-prio.high     { color: var(--warn);   background: var(--warn-dim); }
.nf-prio.medium   { color: var(--info);   background: var(--info-dim); }
.nf-prio.low      { color: var(--success);background: var(--success-dim); }
.nf-prio.info     { color: var(--text-muted); background: var(--surface); }

.nf-main { display: flex; flex-direction: column; gap: 0.3rem; min-width: 0; flex: 1; }
.nf-title-row { display: flex; align-items: baseline; gap: 0.5rem; flex-wrap: wrap; }
.nf-conf { font-size: var(--fs-body); font-weight: 700; padding: 0.1rem 0.4rem; border-radius: 4px; flex-shrink: 0; text-transform: uppercase; letter-spacing: 0.03em; }
.nf-conf.confirmed { color: var(--success); background: var(--success-dim); }
.nf-conf.hypothesis { color: var(--text-muted); background: var(--surface); border: 1px dashed var(--border-solid); }
.nf-title { font-size: var(--fs-lg); color: var(--text); }
.nf-meta { display: flex; align-items: center; gap: 0.3rem; flex-wrap: wrap; }
.nf-tag { font-size: var(--fs-md); font-family: var(--font-mono); padding: 0.1rem 0.4rem; border-radius: 4px; background: var(--surface); color: var(--text-dim); }
.nf-tag.cve { color: var(--accent-bright); background: var(--accent-dim); }
.nf-tag.kev { color: var(--danger); background: var(--danger-dim); font-weight: 700; }
.nf-tag.epss { color: var(--warn); background: var(--warn-dim); }
.nf-tag.state.fixed { color: var(--success); background: var(--success-dim); }
.nf-tag.state.regressed { color: var(--warn); background: var(--warn-dim); }
.nf-tag.state.accepted { color: var(--text-muted); }
.nf-tag.src { color: var(--info); background: var(--info-dim); }

.nf-load-more {
  display: block; width: 100%; margin-top: 0.2rem; padding: 0.45rem;
  background: none; border: 1px dashed var(--border-solid); border-radius: 7px;
  color: var(--text-dim); font-size: var(--fs-md); font-weight: 600; cursor: pointer;
  transition: all 0.15s;
}
.nf-load-more:hover { border-color: var(--accent); color: var(--text); background: var(--surface-2); }

.nf-item-enter-active { transition: opacity 0.25s ease; }
.nf-item-enter-from { opacity: 0; }
.nf-item-move { transition: transform 0.25s ease; }

@media (prefers-reduced-motion: reduce) {
  .nf-item-enter-active, .nf-item-move { transition: none !important; }
}
</style>
