<template>
  <div class="connections-page" data-module="iris">
    <StarBackground />
    <Topbar title="Iris" badge="Conexiones de buzón" back-to="/iris/analisis" back-label="Análisis" />

    <div class="connections-layout">
      <section class="connect-panel">
        <h2 class="panel-title">Conectar un buzón</h2>
        <p class="panel-sub">
          Iris no te deja "entrar" a tu bandeja desde aquí — nunca muestra el correo en sí. Cada pocos
          minutos revisa los mensajes nuevos del buzón conectado, analiza sus cabeceras igual que si las
          hubieras pegado a mano, y el resultado aparece automáticamente en tu
          <router-link to="/iris/analisis" class="inline-link">historial de Análisis</router-link>.
          Puedes pausar o desconectar la cuenta en cualquier momento.
        </p>
        <div class="connect-actions">
          <button
            v-for="provider in store.providers"
            :key="provider"
            type="button"
            class="btn btn--primary"
            :disabled="store.connecting"
            @click="store.connect(provider)"
          >
            Conectar {{ providerLabel(provider) }}
          </button>
        </div>
      </section>

      <section class="list-panel">
        <MailboxConnectionList
          :connections="store.connections"
          :loading="store.loading"
          :error="store.listError"
          @refresh="store.fetchConnections"
          @reconnect="(provider) => store.connect(provider)"
          @toggle-pause="handleTogglePause"
          @sync="handleSync"
          @delete="handleDeleteRequest"
        />
      </section>
    </div>

    <ConfirmModal
      :show="pendingDelete !== null"
      title="Eliminar conexión"
      danger
      confirm-label="Eliminar"
      :message="pendingDelete ? `Se eliminará la conexión con ${pendingDelete.accountEmail}. Iris dejará de analizar este buzón automáticamente.` : ''"
      @confirm="confirmDelete"
      @cancel="pendingDelete = null"
    />

    <AppToast />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import MailboxConnectionList from '@/components/iris/MailboxConnectionList.vue'
import { useIrisMailboxStore } from '@/stores/irisMailboxStore'
import { useToastStore } from '@/stores/toastStore'

const store = useIrisMailboxStore()
const toast = useToastStore()
const route = useRoute()
const router = useRouter()

const pendingDelete = ref(null)

const PROVIDER_LABELS = { gmail: 'Gmail', microsoft: 'Microsoft 365' }
function providerLabel(provider) { return PROVIDER_LABELS[provider] || provider }

const CALLBACK_ERROR_MESSAGES = {
  consent_denied: 'Cancelaste el proceso de conexión en el proveedor.',
  missing_code: 'El proveedor no devolvió un código de autorización válido.',
  invalid_state: 'El enlace de conexión caducó o no es válido. Inténtalo de nuevo.',
  connection_failed: 'No se pudo completar la conexión. Inténtalo de nuevo.',
}

onMounted(async () => {
  // El backend redirige aquí tras el callback OAuth con ?connected=1 o
  // ?error=... en la URL (no hay Bearer token disponible en esa navegación
  // de servidor, así que el resultado viaja por query string). Se limpia
  // con router.replace para que un refresco de página no repita el toast.
  if (route.query.connected) {
    toast.show('Buzón conectado correctamente.', 'success')
    router.replace({ query: {} })
  } else if (route.query.error) {
    toast.show(CALLBACK_ERROR_MESSAGES[route.query.error] || 'No se pudo conectar el buzón.', 'error')
    router.replace({ query: {} })
  }

  await store.fetchProviders()
  await store.fetchConnections()
})

function handleTogglePause(connection) {
  const nextStatus = connection.status === 'paused' ? 'active' : 'paused'
  store.updateConnection(connection.connectionId, { status: nextStatus })
}

function handleSync(connectionId) {
  store.syncConnection(connectionId)
}

function handleDeleteRequest(connection) {
  pendingDelete.value = connection
}

async function confirmDelete() {
  if (!pendingDelete.value) return
  await store.deleteConnection(pendingDelete.value.connectionId)
  pendingDelete.value = null
}
</script>

<style scoped>
.connections-page {
  min-height: 100vh;
  background: var(--bg);
  padding-top: var(--topbar-h);
  position: relative;
}

.connections-layout {
  position: relative;
  z-index: 1;
  max-width: 760px;
  margin: 0 auto;
  padding: 2rem 1.25rem 3rem;
  display: flex;
  flex-direction: column;
  gap: 1.75rem;
}

.connect-panel {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface);
  padding: 1.25rem 1.5rem;
}
.panel-title { margin: 0 0 0.35rem; font-size: var(--fs-xl); font-weight: 600; color: var(--text); }
.panel-sub { margin: 0 0 1rem; font-size: var(--fs-md); line-height: 1.5; color: var(--text-dim); }
.inline-link { color: var(--accent-bright); text-decoration: underline; text-underline-offset: 2px; }

.connect-actions { display: flex; flex-wrap: wrap; gap: 0.6rem; }

.list-panel {
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--surface);
  padding: 1.25rem 1.5rem;
}
</style>
