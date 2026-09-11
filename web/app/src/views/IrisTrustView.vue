<template>
  <div class="trust-page" data-module="iris">
    <StarBackground />
    <Topbar title="Iris" badge="Remitentes de confianza" back-to="/iris/analisis" back-label="Análisis" />

    <div class="trust-layout">
      <section class="panel">
        <p class="panel-eyebrow">Excepciones de confianza</p>
        <h2 class="panel-title">Quitar un falso positivo que se repite</h2>
        <p class="panel-sub">
          Si un remitente que conoces dispara siempre la misma alerta —un proveedor que responde desde
          otra dirección, un banco que escribe «urgente»—, declara aquí que confías en él. Solo te afecta
          a ti, caduca sola y cada análisis en que se aplica lo dice.
        </p>
        <IrisTrustForm @saved="store.fetchTrustedSenders(showInactive)" />
      </section>

      <section class="panel">
        <div class="list-header">
          <h3 class="list-title">Tus excepciones</h3>
          <label class="list-toggle">
            <input v-model="showInactive" type="checkbox" @change="store.fetchTrustedSenders(showInactive)" />
            Mostrar caducadas y revocadas
          </label>
        </div>

        <p v-if="store.trustedSendersLoading" class="list-empty">Cargando…</p>
        <p v-else-if="!store.trustedSenders.length" class="list-empty">No tienes ninguna excepción {{ showInactive ? '' : 'activa' }}.</p>
        <ul v-else class="trust-list">
          <li v-for="entry in store.trustedSenders" :key="entry.trustedSenderId" class="trust-item">
            <div class="trust-main">
              <span class="trust-value">{{ entry.value }}</span>
              <span class="trust-kind">{{ entry.kind === 'domain' ? 'dominio' : 'dirección' }}</span>
              <span class="trust-status" :class="`trust-status--${entry.status}`">{{ STATUS_LABELS[entry.status] }}</span>
            </div>
            <p class="trust-reason">«{{ entry.reason }}»</p>
            <p class="trust-dates">
              Creada {{ formatDate(entry.createdAt) }} ·
              <template v-if="entry.revokedAt">revocada {{ formatDate(entry.revokedAt) }}</template>
              <template v-else>caduca {{ formatDate(entry.expiresAt) }}</template>
            </p>
            <button
              v-if="entry.status === 'active'"
              type="button"
              class="trust-revoke"
              @click="pendingRevoke = entry"
            >Revocar</button>
          </li>
        </ul>
      </section>
    </div>

    <ConfirmModal
      :show="pendingRevoke !== null"
      title="Revocar excepción"
      danger
      confirm-label="Revocar"
      :message="pendingRevoke ? `Los próximos correos de ${pendingRevoke.value} se analizarán sin excepción. La excepción seguirá en la auditoría.` : ''"
      @confirm="confirmRevoke"
      @cancel="pendingRevoke = null"
    />
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import IrisTrustForm from '@/components/iris/IrisTrustForm.vue'
import { useIrisStore } from '@/stores/irisStore'
import { useUtils } from '@/composables/useUtils'

const store = useIrisStore()
const { formatDate } = useUtils()

const STATUS_LABELS = { active: 'activa', expired: 'caducada', revoked: 'revocada' }
const showInactive = ref(false)
const pendingRevoke = ref(null)

async function confirmRevoke() {
  if (!pendingRevoke.value) return
  await store.revokeTrustedSender(pendingRevoke.value.trustedSenderId)
  pendingRevoke.value = null
  await store.fetchTrustedSenders(showInactive.value)
}

onMounted(() => store.fetchTrustedSenders(false))
</script>

<style scoped>
.trust-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.trust-layout {
  position: relative; z-index: 1;
  max-width: 820px; margin: 0 auto; padding: 2rem 1.25rem 3rem;
  display: flex; flex-direction: column; gap: 1.75rem;
}
.panel { border: 1px solid var(--border); border-radius: 12px; background: var(--surface); padding: 1.4rem 1.6rem; }
.panel-eyebrow {
  margin: 0 0 0.3rem; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-xs); letter-spacing: 0.28em; text-transform: uppercase; color: var(--accent);
}
.panel-title { margin: 0 0 0.5rem; font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: var(--fs-2xl); font-weight: 700; color: var(--text); }
.panel-sub { margin: 0 0 1.2rem; font-size: var(--fs-md); line-height: 1.55; color: var(--text-dim); max-width: 62ch; }

.list-header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 0.9rem; }
.list-title { margin: 0; font-size: var(--fs-lg); color: var(--text); }
.list-toggle { display: flex; align-items: center; gap: 0.4rem; font-size: var(--fs-sm); color: var(--text-dim); }
.list-empty { margin: 0; color: var(--text-muted); font-size: var(--fs-md); }

.trust-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.6rem; }
.trust-item { position: relative; padding: 0.75rem 0.9rem; border: 1px solid var(--border-med); border-radius: 8px; background: var(--surface-2); }
.trust-main { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; padding-right: 5.5rem; }
.trust-value { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-md); color: var(--text); }
.trust-kind { font-size: var(--fs-xs); color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em; }
.trust-status { font-size: var(--fs-xs); font-weight: 600; padding: 2px 8px; border-radius: 5px; text-transform: uppercase; }
.trust-status--active { background: var(--success-dim); color: var(--success); }
.trust-status--expired { background: rgba(100, 116, 139, 0.12); color: var(--text-muted); }
.trust-status--revoked { background: var(--danger-dim); color: var(--danger); }
.trust-reason { margin: 0.35rem 0 0; font-size: var(--fs-md); color: var(--text-dim); }
.trust-dates { margin: 0.2rem 0 0; font-size: var(--fs-sm); color: var(--text-muted); }
.trust-revoke {
  position: absolute; top: 0.7rem; right: 0.8rem;
  padding: 0.25rem 0.7rem; font-size: var(--fs-sm); font-weight: 600;
  border: 1px solid var(--danger); border-radius: 6px; background: transparent; color: var(--danger); cursor: pointer;
}
.trust-revoke:hover { background: var(--danger); color: #fff; }
</style>
