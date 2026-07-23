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
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" class="empty-icon" aria-hidden="true">
        <rect x="2" y="4" width="20" height="16" rx="2" />
        <path d="m2 7 10 6 10-6" />
      </svg>
      <p class="empty-title">Ningún buzón conectado todavía</p>
      <p class="empty-sub">Conecta Gmail o Microsoft 365 arriba para que Iris analice tu correo automáticamente.</p>
    </div>

    <template v-else>
      <!-- Las conexiones que requieren reautenticación son el único estado
           que exige al usuario, así que se destacan a ancho completo en vez
           de esconderse como un icono más dentro de una fila. -->
      <div v-if="reauthConnections.length" class="reauth-stack">
        <div v-for="conn in reauthConnections" :key="conn.connectionId" class="reauth-banner">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="reauth-icon" aria-hidden="true">
            <path d="M12 9v4M12 17h.01" /><circle cx="12" cy="12" r="10" />
          </svg>
          <div class="reauth-text">
            <p class="reauth-title">{{ providerLabel(conn.provider) }} — {{ conn.accountEmail }} necesita reconectarse</p>
            <p class="reauth-sub">{{ conn.lastError || 'El acceso concedido ha caducado o fue revocado.' }} Iris dejó de sondear este buzón.</p>
          </div>
          <button type="button" class="btn-primary" @click="$emit('reconnect', conn)">Reconectar</button>
        </div>
      </div>

      <TransitionGroup name="card-pop" tag="div" class="connection-grid">
        <article v-for="(conn, index) in normalConnections" :key="conn.connectionId" class="connection-card"
          :style="{ '--card-delay': Math.min(index, 8) * 40 + 'ms' }">
          <div class="card-top">
            <span class="pulse" :class="`pulse--${conn.status}`" aria-hidden="true"></span>
            <span class="card-provider">{{ providerLabel(conn.provider) }}</span>
            <span class="card-status">{{ statusLabel(conn.status) }}</span>
          </div>

          <p class="card-email">{{ conn.accountEmail }}</p>

          <div class="card-meta">
            <span class="meta-chip" :title="conn.folder ? `Carpeta vigilada: ${conn.folder}` : 'Vigila la bandeja de entrada por defecto'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 7l9-4 9 4-9 4-9-4z" /><path d="M3 7v10l9 4 9-4V7" /></svg>
              {{ conn.folder || 'Bandeja de entrada' }}
            </span>
            <span class="meta-chip" :class="{ 'meta-chip--full': conn.fullMessageMode }"
              :title="conn.fullMessageMode ? 'Iris lee el correo completo (cuerpo y adjuntos incluidos)' : 'Iris solo lee las cabeceras'">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 8h10M7 12h10M7 16h6" /></svg>
              {{ conn.fullMessageMode ? 'Correo completo' : 'Solo cabeceras' }}
            </span>
          </div>

          <p class="card-sync">Último sondeo: {{ timeAgo(conn.lastSyncAt) }}</p>

          <div class="card-actions">
            <button
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
              :class="{ 'btn-icon--busy': syncingIds.has(conn.connectionId) }"
              :disabled="syncingIds.has(conn.connectionId)"
              title="Sondear ahora"
              :aria-label="`Sondear ${conn.accountEmail} ahora`"
              @click="$emit('sync', conn)"
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
          </div>
        </article>
      </TransitionGroup>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  connections: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  error: { type: String, default: null },
  // IDs con un sondeo manual en curso (store.irisMailboxStore.syncingIds) —
  // deshabilita el botón de esa tarjeta y lo marca girando en vez de dejar
  // que parezca que "Sondear ahora" no hizo nada.
  syncingIds: { type: Set, default: () => new Set() },
})
defineEmits(['refresh', 'reconnect', 'toggle-pause', 'sync', 'delete'])

// Los emits llevan siempre el objeto `conn` completo — antes `reconnect`
// mandaba solo el provider y `sync` solo el id, una inconsistencia sin
// motivo real ya que el padre siempre tenía el objeto entero a mano.
const reauthConnections = computed(() => props.connections.filter(c => c.status === 'reauth_required'))
const normalConnections = computed(() => props.connections.filter(c => c.status !== 'reauth_required'))

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
.mailbox-list { display: flex; flex-direction: column; gap: 1rem; }

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
.btn-icon--busy { color: var(--accent); pointer-events: none; }
.btn-icon--busy svg { animation: seq-spin 0.8s linear infinite; }
.btn-icon:disabled { opacity: 0.6; cursor: default; }
.btn-icon:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 2px; }

.btn-primary {
  padding: 0.45rem 0.9rem; border-radius: 7px; border: 1px solid var(--accent);
  background: var(--accent); color: var(--on-accent); font-size: var(--fs-md); font-weight: 600;
  cursor: pointer; transition: opacity 0.15s; flex-shrink: 0;
}
.btn-primary:hover { opacity: 0.88; }

/* ── Aviso de reautenticación — a ancho completo, imposible de ignorar ── */
.reauth-stack { display: flex; flex-direction: column; gap: 0.5rem; margin-bottom: 0.85rem; }
.reauth-banner {
  display: flex; align-items: center; gap: 0.85rem;
  padding: 0.85rem 1rem;
  border: 1px solid var(--warn); border-radius: 9px;
  background: var(--warn-dim);
}
.reauth-icon { width: 22px; height: 22px; flex-shrink: 0; color: var(--warn); }
.reauth-text { flex: 1; min-width: 0; }
.reauth-title { margin: 0; font-size: var(--fs-lg); font-weight: 700; color: var(--text); }
.reauth-sub { margin: 0.15rem 0 0; font-size: var(--fs-md); color: var(--text-dim); }

/* ── Tarjetas de conexión ────────────────────────────────────────────── */
.connection-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 0.75rem;
}

.connection-card {
  display: flex; flex-direction: column; gap: 0.55rem;
  padding: 0.9rem 1rem;
  border: 1px solid var(--border); border-radius: 10px;
  background: var(--surface);
  transition: border-color 0.15s, transform 0.15s, box-shadow 0.15s;
  animation: seq-fade-up 0.3s cubic-bezier(0.22, 1, 0.36, 1) backwards;
  animation-delay: var(--card-delay, 0ms);
}
.connection-card:hover { border-color: var(--border-med); box-shadow: 0 6px 18px rgba(0,0,0,0.18); }

.card-top { display: flex; align-items: center; gap: 0.5rem; }
.card-provider { font-size: var(--fs-md); font-weight: 700; color: var(--text); }
.card-status { margin-left: auto; font-size: var(--fs-sm); color: var(--text-muted); }

.card-email {
  margin: 0; font-size: var(--fs-lg); font-weight: 500; color: var(--text-dim);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

.card-meta { display: flex; flex-wrap: wrap; gap: 0.4rem; }
.meta-chip {
  display: inline-flex; align-items: center; gap: 0.3rem;
  padding: 0.15rem 0.5rem; border-radius: 999px;
  background: var(--surface-2); color: var(--text-muted); font-size: var(--fs-sm);
}
.meta-chip svg { width: 12px; height: 12px; flex-shrink: 0; }
.meta-chip--full { background: var(--accent-dim); color: var(--accent-bright); }

.card-sync { margin: 0; font-size: var(--fs-sm); color: var(--text-muted); font-family: var(--font-mono); }

.card-actions { display: flex; align-items: center; gap: 0.35rem; margin-top: 0.1rem; }

.pulse { width: 9px; height: 9px; flex-shrink: 0; border-radius: 50%; background: var(--text-muted); transition: background 0.3s; }
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
  display: flex; flex-direction: column; align-items: center; gap: 0.3rem;
  padding: 2.5rem 1rem; text-align: center;
  border: 1px dashed var(--border-med); border-radius: 8px;
}
.empty-icon { width: 30px; height: 30px; color: var(--text-muted); opacity: 0.5; margin-bottom: 0.3rem; }
.empty-title { margin: 0 0 0.25rem; font-size: var(--fs-lg); color: var(--text-dim); }
.empty-sub { margin: 0; font-size: var(--fs-md); color: var(--text-muted); max-width: 36ch; }

.card-pop-enter-active { transition: opacity 0.3s ease, transform 0.3s cubic-bezier(0.22, 1, 0.36, 1); }
.card-pop-leave-active { transition: opacity 0.18s ease, transform 0.18s ease; position: absolute; }
.card-pop-enter-from, .card-pop-leave-to { opacity: 0; transform: scale(0.96); }
.card-pop-move { transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1); }

@media (prefers-reduced-motion: reduce) {
  .pulse--active { animation: none; }
  .btn-icon--busy svg { animation: none; }
  .connection-card { animation: none; }
  .card-pop-enter-active, .card-pop-leave-active, .card-pop-move { transition: none !important; }
}
</style>
