<template>
  <div class="queue-page">
    <StarBackground />
    <Topbar title="Cola de Tareas" />

    <main class="main">
      <div class="page-header">
        <div><h1>Cola de Tareas</h1><p class="subtitle">Monitoriza y gestiona las tareas asíncronas en segundo plano</p></div>
      </div>

      <div class="status-bar">
        <div class="stat-item">
          <span class="stat-label">Workers</span>
          <span class="stat-value">{{ store.status.aliveWorkers }} / {{ store.status.maxWorkers }}</span>
        </div>
        <div class="stat-item stat-item--running">
          <span class="stat-label">En ejecución</span>
          <span class="stat-value">{{ store.status.runningCount }}</span>
        </div>
        <div class="stat-item stat-item--pending">
          <span class="stat-label">En espera</span>
          <span class="stat-value">{{ store.status.pendingCount }}</span>
        </div>
        <div class="stat-item stat-item--history">
          <span class="stat-label">Historial</span>
          <span class="stat-value">{{ store.status.historyCount }}</span>
        </div>
      </div>

      <div class="tab-bar">
        <button class="tab-btn" :class="{ active: store.activeTab === 'running' }" @click="store.switchTab('running')">
          En ejecución <span class="tab-count">{{ store.status.runningCount }}</span>
        </button>
        <button class="tab-btn" :class="{ active: store.activeTab === 'pending' }" @click="store.switchTab('pending')">
          En espera <span class="tab-count">{{ store.status.pendingCount }}</span>
        </button>
        <button class="tab-btn" :class="{ active: store.activeTab === 'history' }" @click="store.switchTab('history')">
          Historial <span class="tab-count">{{ store.status.historyCount }}</span>
        </button>
      </div>

      <div v-if="store.loading" class="loading-block">
        <div class="skeleton skeleton--row" v-for="i in 5" :key="i"></div>
      </div>

      <div v-else-if="store.tasks.length > 0" class="task-list">
        <div v-for="task in store.tasks" :key="task.id" class="task-row" :class="'task-row--' + task.status">
          <div class="task-icon" :class="'task-icon--' + task.status">
            <svg v-if="task.status === 'running'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            <svg v-else-if="task.status === 'pending'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <svg v-else-if="task.status === 'completed'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
            <svg v-else-if="task.status === 'cancelled'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          </div>
          <div class="task-info">
            <div class="task-name">{{ task.name }}</div>
            <span class="task-category">{{ categoryLabel(task.category) }}</span>
            <span class="task-status-badge" :class="'status--' + task.status">{{ statusLabel(task.status) }}</span>
          </div>
          <div class="task-times">
            <span class="task-time">Creado: {{ formatDate(task.createdAt) }}</span>
            <span v-if="task.startedAt" class="task-time">Inicio: {{ formatDate(task.startedAt) }}</span>
            <span v-if="task.finishedAt" class="task-time">Fin: {{ formatDate(task.finishedAt) }}</span>
            <span v-if="task.error" class="task-error">{{ task.error }}</span>
          </div>
          <div v-if="task.status === 'running'" class="task-progress">
            <div class="progress-track"><div class="progress-fill" :style="{ width: task.progress + '%' }"></div></div>
            <span class="progress-text">{{ task.progress }}%</span>
          </div>
          <button v-if="task.status === 'pending' || task.status === 'running'" class="btn-cancel" @click="handleCancel(task.id)">Cancelar</button>
        </div>
      </div>

      <div v-else class="empty-state">No hay tareas en esta categoría.</div>

      <AppPagination :current="store.currentPage" :total="store.totalCount" :per-page="store.perPage" @go="store.goToPage" />
    </main>

    <AppToast />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import AppPagination from '@/components/shared/AppPagination.vue'
import { useQueueStore } from '@/stores/queueStore'
import { useUtils } from '@/composables/useUtils'

const store = useQueueStore()
const { formatDate } = useUtils()

onMounted(() => { store.loadStatus(); store.loadTasks() })

function categoryLabel(c) { const m = { 'themis.scan': 'Escaneo', 'themis.report': 'Informe PDF', 'aegis.generate': 'IA Aegis' }; return m[c] || c }
function statusLabel(s) { const m = { pending: 'Pendiente', running: 'En ejecución', completed: 'Completado', failed: 'Fallido', cancelled: 'Cancelado' }; return m[s] || s }
async function handleCancel(id) { await store.cancelTask(id) }
</script>

<style scoped>
.queue-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.main { max-width: 960px; margin: 0 auto; padding: 1.75rem 1.1rem 4rem; position: relative; z-index: 1; }
.page-header { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 0.85rem; }
.page-header h1 { font-size: 1.4rem; font-weight: 800; color: var(--text); margin: 0; font-family: var(--font-display); }
.subtitle { font-size: 0.82rem; color: var(--text-dim); margin: 0.2rem 0 0; }
.status-bar { display: flex; align-items: center; gap: 0.65rem; flex-wrap: wrap; padding: 0.85rem 1.1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 1.25rem; }
.stat-item { display: flex; flex-direction: column; gap: 0.1rem; min-width: 90px; }
.stat-label { font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.02em; font-weight: 600; }
.stat-value { font-size: 1.1rem; font-weight: 700; color: var(--text); font-family: var(--font-mono); }
.stat-item--running .stat-value { color: var(--info); }
.stat-item--pending .stat-value { color: var(--warn); }
.stat-item--history .stat-value { color: var(--text-dim); }
.tab-bar { display: flex; gap: 0.25rem; margin-bottom: 1.1rem; border-bottom: 1px solid var(--border); padding-bottom: 0; }
.tab-btn { padding: 0.5rem 0.85rem; border: none; background: none; color: var(--text-dim); font-size: 0.82rem; font-weight: 600; cursor: pointer; border-radius: 6px 6px 0 0; border-bottom: 2px solid transparent; display: flex; align-items: center; gap: 0.35rem; transition: all 0.2s ease; }
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-count { font-size: 0.65rem; padding: 0.1rem 0.4rem; border-radius: 8px; background: var(--surface-2); font-family: var(--font-mono); }
.task-list { display: flex; flex-direction: column; gap: 0.4rem; }
.task-row { display: flex; align-items: center; gap: 0.85rem; padding: 0.85rem 1.1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; transition: border-color 0.2s; flex-wrap: wrap; }
.task-row:hover { border-color: var(--border-med); }
.task-row--running { border-left: 3px solid var(--info); }
.task-row--pending { border-left: 3px solid var(--warn); }
.task-row--completed { border-left: 3px solid var(--success); }
.task-row--failed { border-left: 3px solid var(--danger); }
.task-row--cancelled { border-left: 3px solid var(--text-muted); opacity: 0.6; }
.task-icon { width: 32px; height: 32px; border-radius: 6px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; border: 1px solid var(--border); }
.task-icon svg { width: 16px; height: 16px; }
.task-icon--running { background: var(--info-dim); border-color: var(--info); color: var(--info); }
.task-icon--pending { background: var(--warn-dim); border-color: var(--warn); color: var(--warn); }
.task-icon--completed { background: var(--success-dim); border-color: var(--success); color: var(--success); }
.task-icon--failed { background: var(--danger-dim); border-color: var(--danger); color: var(--danger); }
.task-icon--cancelled { background: var(--surface-2); border-color: var(--border); color: var(--text-muted); }
.task-info { display: flex; flex-direction: column; gap: 0.1rem; flex: 1; min-width: 160px; }
.task-name { font-weight: 700; color: var(--text); font-size: 0.85rem; }
.task-category { font-size: 0.68rem; color: var(--text-muted); font-family: var(--font-mono); }
.task-status-badge { display: inline-block; padding: 0.1rem 0.45rem; border-radius: 4px; font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; width: fit-content; }
.status--pending { background: var(--warn-dim); color: var(--warn); }
.status--running { background: var(--info-dim); color: var(--info); }
.status--completed { background: var(--success-dim); color: var(--success); }
.status--failed { background: var(--danger-dim); color: var(--danger); }
.status--cancelled { background: var(--surface-2); color: var(--text-muted); }
.task-times { display: flex; flex-direction: column; gap: 0.05rem; flex: 1.2; min-width: 140px; }
.task-time { font-size: 0.68rem; color: var(--text-dim); font-family: var(--font-mono); }
.task-error { font-size: 0.65rem; color: var(--danger); margin-top: 0.15rem; word-break: break-word; max-width: 260px; }
.task-progress { display: flex; align-items: center; gap: 0.4rem; width: 110px; flex-shrink: 0; }
.progress-track { flex: 1; height: 3px; background: var(--surface-2); border-radius: 2px; overflow: hidden; }
.progress-fill { height: 100%; background: var(--info); border-radius: 2px; transition: width 0.6s ease; }
.progress-text { font-size: 0.65rem; color: var(--text-muted); font-family: var(--font-mono); min-width: 28px; text-align: right; }
.btn-cancel { padding: 0.35rem 0.7rem; border-radius: 6px; border: 1px solid var(--danger); background: var(--danger-dim); color: var(--danger); font-size: 0.7rem; font-weight: 600; cursor: pointer; transition: all 0.2s ease; flex-shrink: 0; }
.btn-cancel:hover { background: var(--danger); color: #fff; }
.loading-block { display: flex; flex-direction: column; gap: 0.4rem; padding: 1.5rem 0; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--row { width: 100%; height: 56px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.empty-state { text-align: center; padding: 3.5rem 0; color: var(--text-muted); font-size: 0.9rem; }
@media (max-width: 768px) { .status-bar { gap: 0.4rem; } .stat-item { min-width: 60px; } .task-row { flex-direction: column; align-items: flex-start; gap: 0.4rem; } .task-progress { width: 100%; } .btn-cancel { align-self: flex-end; } }
</style>
