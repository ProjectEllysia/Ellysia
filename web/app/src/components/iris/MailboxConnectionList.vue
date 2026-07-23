<template>
  <div class="mailbox-list">
    <header class="toolbar">
      <h3 class="toolbar-title">Buzones conectados</h3>
      <button class="btn-icon" title="Recargar" aria-label="Recargar conexiones" @click="$emit('refresh')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path d="M23 4v6h-6M1 20v-6h6" />
          <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
        </svg>
      </button>
    </header>

    <p v-if="loading" class="state-msg">Cargando conexiones…</p>

    <p v-else-if="error" class="state-msg state-msg--error">
      {{ error }}
      <button type="button" class="retry" @click="$emit('refresh')">Reintentar</button>
    </p>

    <div v-else-if="!connections.length" class="state-empty">
      <p class="empty-title">Ningún buzón conectado todavía</p>
      <p class="empty-sub">Conecta Gmail o Microsoft 365 para que Iris analice tu correo automáticamente.</p>
    </div>

    <ul v-else class="rows">
      <li v-for="conn in connections" :key="conn.connectionId" class="row">
        <span class="row-main">
          <span class="pulse" :class="`pulse--${conn.status}`" aria-hidden="true"></span>
          <span class="row-text">
            <span class="row-host">{{ providerLabel(conn.provider) }} — {{ conn.accountEmail }}</span>
            <span class="row-meta">
              {{ statusLabel(conn.status) }} · último sondeo {{ timeAgo(conn.lastSyncAt) }}
              <template v-if="conn.status === 'reauth_required' && conn.lastError"> · {{ conn.lastError }}</template>
            </span>
          </span>
        </span>

        <span class="row-actions">
          <button
            v-if="conn.status === 'reauth_required'"
            class="btn-icon"
            title="Reconectar"
            :aria-label="`Reconectar ${conn.accountEmail}`"
            @click="$emit('reconnect', conn.provider)"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M21 2v6h-6M3 22v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L21 8M21 15a9 9 0 0 1-14.85 3.36L3 16" />
            </svg>
          </button>
          <button
            v-else
            class="btn-icon"
            :title="conn.status === 'paused' ? 'Reanudar' : 'Pausar'"
            :aria-label="`${conn.status === 'paused' ? 'Reanudar' : 'Pausar'} ${conn.accountEmail}`"
            @click="$emit('toggle-pause', conn)"
          >
            <svg v-if="conn.status === 'paused'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <polygon points="5 3 19 12 5 21 5 3" />
            </svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <rect x="6" y="4" width="4" height="16" />
              <rect x="14" y="4" width="4" height="16" />
            </svg>
          </button>
          <button
            class="btn-icon"
            title="Sincronizar ahora"
            :aria-label="`Sincronizar ${conn.accountEmail} ahora`"
            @click="$emit('sync', conn.connectionId)"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <polyline points="23 4 23 10 17 10" />
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
            </svg>
          </button>
          <button
            class="btn-icon btn-icon--danger"
            title="Eliminar"
            :aria-label="`Eliminar ${conn.accountEmail}`"
            @click="$emit('delete', conn)"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6h14z" />
            </svg>
          </button>
        </span>
      </li>
    </ul>
  </div>
</template>

<script setup>
defineProps({
  connections: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  error: { type: String, default: null },
})
defineEmits(['refresh', 'reconnect', 'toggle-pause', 'sync', 'delete'])

const PROVIDER_LABELS = { gmail: 'Gmail', microsoft: 'Microsoft 365' }
function providerLabel(provider) { return PROVIDER_LABELS[provider] || provider }

const STATUS_LABELS = {
  active: 'Activa',
  reauth_required: 'Requiere reautenticación',
  revoked: 'Revocada',
  paused: 'Pausada',
}
function statusLabel(status) { return STATUS_LABELS[status] || status }

// Antigüedad relativa, igual que components/hygeia/format.js::timeAgo — no
// se comparte porque es la única vista fuera de Hygeia que la necesita.
function timeAgo(iso) {
  if (!iso) return 'nunca'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return '—'
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000))
  if (secs < 5) return 'ahora mismo'
  if (secs < 60) return `hace ${secs} s`
  if (secs < 3600) return `hace ${Math.floor(secs / 60)} min`
  if (secs < 86400) return `hace ${Math.floor(secs / 3600)} h`
  return `hace ${Math.floor(secs / 86400)} d`
}
</script>

<style scoped>
.mailbox-list { display: flex; flex-direction: column; gap: 0.85rem; }

.toolbar { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
.toolbar-title { margin: 0; font-size: var(--fs-xl); font-weight: 600; color: var(--text); }

.btn-icon {
  width: 34px; height: 34px; flex-shrink: 0;
  display: grid; place-items: center;
  background: transparent; border: 1px solid var(--border); border-radius: 6px;
  color: var(--text-muted); cursor: pointer;
  transition: border-color var(--transition), color var(--transition);
}
.btn-icon svg { width: 16px; height: 16px; }
.btn-icon:hover { border-color: var(--accent); color: var(--accent-bright); background: var(--accent-dim); }
.btn-icon--danger:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-dim); }

.rows { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }

.row {
  display: flex; align-items: stretch; gap: 0.3rem;
  border: 1px solid var(--border); border-radius: 7px;
  padding: 0.1rem;
  transition: background var(--transition);
}
.row:hover { background: var(--surface-2); }

.row-main {
  flex: 1; min-width: 0;
  display: flex; align-items: center; gap: 0.7rem;
  padding: 0.65rem 0.75rem;
}
.row-text { min-width: 0; display: flex; flex-direction: column; gap: 0.15rem; }
.row-host {
  font-size: var(--fs-lg); font-weight: 600; color: var(--text);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.row-meta {
  font-size: var(--fs-md); color: var(--text-muted);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

.row-actions { display: flex; align-items: center; gap: 0.3rem; padding-right: 0.5rem; }

.pulse { width: 10px; height: 10px; flex-shrink: 0; border-radius: 50%; background: var(--text-muted); }
.pulse--active { background: var(--success); animation: pulse-ring 2.4s ease-out infinite; }
.pulse--reauth_required { background: var(--warn); }
.pulse--revoked { background: var(--danger); }
.pulse--paused { background: var(--text-muted); box-shadow: inset 0 0 0 1px var(--border-med); }

@keyframes pulse-ring {
  0%        { box-shadow: 0 0 0 0 color-mix(in srgb, var(--success) 55%, transparent); }
  70%, 100% { box-shadow: 0 0 0 7px transparent; }
}

.state-msg { margin: 0; padding: 1.6rem 1rem; text-align: center; color: var(--text-muted); font-size: var(--fs-md); }
.state-msg--error { color: var(--danger); }
.retry {
  margin-left: 0.5rem; padding: 0.25rem 0.7rem;
  background: transparent; border: 1px solid var(--danger); border-radius: 6px;
  color: var(--danger); font-size: var(--fs-md); cursor: pointer;
}

.state-empty {
  padding: 2rem 1rem; text-align: center;
  border: 1px dashed var(--border-med); border-radius: 8px;
}
.empty-title { margin: 0 0 0.25rem; font-size: var(--fs-lg); color: var(--text-dim); }
.empty-sub { margin: 0; font-size: var(--fs-md); color: var(--text-muted); }

.btn-icon:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }

@media (prefers-reduced-motion: reduce) {
  .pulse--active { animation: none; }
}
</style>
