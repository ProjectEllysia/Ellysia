<template>
  <Teleport to="body">
    <div class="modal-overlay" data-module="aegis" @click.self="close">
      <div ref="boxRef" class="modal--lists" role="dialog" aria-modal="true" aria-labelledby="lists-modal-title" tabindex="-1">
        <header class="lists-header">
          <div class="lists-header-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
          </div>
          <div class="lists-header-text">
            <h2 id="lists-modal-title">Listas de distribución</h2>
            <p>Destinatarios de las campañas de concienciación</p>
          </div>
          <button type="button" class="modal-close" @click="close" aria-label="Cerrar">&times;</button>
        </header>

        <div class="lists-body">
          <p v-if="store.loadingLists" class="hint">Cargando listas…</p>
          <p v-else-if="!store.distributionLists.length" class="hint">
            Aún no tienes listas de distribución — crea la primera abajo.
          </p>

          <div v-for="list in store.distributionLists" :key="list.id" class="list-block">
            <div class="list-row" :class="{ 'list-row--open': store.expandedListId === list.id }">
              <button
                type="button"
                class="list-row-main"
                :aria-expanded="store.expandedListId === list.id"
                @click="store.toggleListRecipients(list.id)"
              >
                <span class="list-chevron" aria-hidden="true">›</span>
                <span class="list-name">{{ list.name }}</span>
                <span class="list-count">
                  {{ list.recipientCount }} destinatario{{ list.recipientCount === 1 ? '' : 's' }}
                </span>
              </button>
              <button
                type="button"
                class="list-delete"
                title="Eliminar lista"
                aria-label="Eliminar lista"
                @click="deleteTarget = list"
              >✕</button>
            </div>

            <div v-if="store.expandedListId === list.id" class="list-detail">
              <div v-if="store.listRecipients.length" class="recipient-rows">
                <div v-for="recipient in store.listRecipients" :key="recipient.id" class="recipient-row">
                  <span class="recipient-email">{{ recipient.email }}</span>
                  <button
                    type="button"
                    class="recipient-remove"
                    :title="`Quitar ${recipient.email}`"
                    :aria-label="`Quitar ${recipient.email}`"
                    @click="store.removeRecipientFromList(list.id, recipient.id)"
                  >✕</button>
                </div>
              </div>
              <p v-else class="hint">Esta lista está vacía.</p>

              <div class="form-group">
                <label :for="`add-${list.id}`">Añadir destinatarios</label>
                <textarea
                  :id="`add-${list.id}`"
                  v-model="addRaw"
                  rows="2"
                  class="input textarea"
                  placeholder="Un email por línea (o separados por coma)"
                ></textarea>
                <div class="row-end">
                  <span class="recipient-count" :class="{ 'recipient-count--empty': !addParsed.length }">
                    {{ addParsed.length }} detectado{{ addParsed.length === 1 ? '' : 's' }}
                  </span>
                  <button type="button" class="btn btn--secondary btn--sm" :disabled="!addParsed.length" @click="handleAdd(list.id)">
                    Añadir
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- Crear lista nueva: mismo formulario que el modo "Nueva lista" del
               modal de campaña, pero aquí sin lanzar nada. -->
          <div class="new-list">
            <span class="new-list-label">Nueva lista</span>
            <div class="form-group">
              <input v-model="newListName" type="text" maxlength="128" class="input" placeholder="Nombre de la lista" />
            </div>
            <div class="form-group">
              <textarea
                v-model="newListRaw"
                rows="3"
                class="input textarea"
                placeholder="Un email por línea (o separados por coma)"
              ></textarea>
              <div class="row-end">
                <span class="recipient-count" :class="{ 'recipient-count--empty': !newListParsed.length }">
                  {{ newListParsed.length }} destinatario{{ newListParsed.length === 1 ? '' : 's' }}
                </span>
                <button type="button" class="btn btn--primary btn--sm" :disabled="!canCreate || store.creatingList" @click="handleCreate">
                  <span v-if="store.creatingList" class="btn-spin-inline"></span>
                  {{ store.creatingList ? 'Creando…' : 'Crear lista' }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <footer class="lists-footer">
          <button type="button" class="btn btn--secondary" @click="close">Cerrar</button>
        </footer>
      </div>
    </div>

    <ConfirmModal
      :show="!!deleteTarget"
      title="Eliminar lista"
      :message="`¿Eliminar «${deleteTarget?.name}» y sus destinatarios? Las campañas lanzadas con esta lista se borran también, con sus resultados, y sus enlaces de quiz dejarán de funcionar.`"
      confirm-label="Eliminar"
      danger
      @confirm="confirmDelete"
      @cancel="deleteTarget = null"
    />
  </Teleport>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { useAegisStore } from '@/stores/aegisStore'
import { useUtils } from '@/composables/useUtils'
import { useModalA11y } from '@/composables/useModalA11y'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'

const emit = defineEmits(['close'])

const store = useAegisStore()
const { parseEmails } = useUtils()

const boxRef = ref(null)

/* Una sola caja de "añadir": solo hay una lista desplegada a la vez. */
const addRaw = ref('')
const addParsed = computed(() => parseEmails(addRaw.value))
watch(() => store.expandedListId, () => { addRaw.value = '' })

const newListName = ref('')
const newListRaw = ref('')
const newListParsed = computed(() => parseEmails(newListRaw.value))
const canCreate = computed(() => newListName.value.trim().length > 0)

async function handleAdd(listId) {
  if (await store.addRecipientsToList(listId, addParsed.value)) addRaw.value = ''
}

async function handleCreate() {
  if (!canCreate.value || store.creatingList) return
  const created = await store.createDistributionListWithRecipients(newListName.value.trim(), newListParsed.value)
  if (created) { newListName.value = ''; newListRaw.value = '' }
}

const deleteTarget = ref(null)
async function confirmDelete() {
  const list = deleteTarget.value
  deleteTarget.value = null
  if (list) await store.deleteDistributionList(list.id)
}

function close() { emit('close') }

useModalA11y(() => true, { boxRef, onClose: close })
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; z-index: 9999; padding: 1rem; }
.modal--lists { background: var(--surface); border: 1px solid var(--border-solid); border-radius: var(--radius); max-width: 460px; width: 100%; max-height: 88vh; display: flex; flex-direction: column; overflow: hidden; outline: none; }

.lists-header { display: flex; align-items: flex-start; gap: 0.75rem; padding: 1.1rem 1.25rem 0.9rem; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.lists-header-icon { width: 34px; height: 34px; border-radius: 9px; background: var(--accent-dim); color: var(--accent-bright); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
.lists-header-text { flex: 1; min-width: 0; }
.lists-header-text h2 { font-size: var(--fs-lg); font-weight: 800; color: var(--text); margin: 0 0 0.15rem; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.lists-header-text p { font-size: var(--fs-lg); color: var(--text-dim); margin: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.modal-close { background: none; border: none; color: var(--text-muted); font-size: var(--fs-xl); line-height: 1; cursor: pointer; padding: 0.1rem 0.3rem; flex-shrink: 0; border-radius: 5px; transition: all 0.15s; }
.modal-close:hover { color: var(--text); background: var(--bg); }

.lists-body { padding: 1.1rem 1.25rem; overflow-y: auto; display: flex; flex-direction: column; gap: 0.4rem; }
.hint { font-size: var(--fs-lg); color: var(--text-muted); margin: 0; }

.list-row { display: flex; align-items: stretch; gap: 0.25rem; border-radius: 6px; transition: background var(--transition); }
.list-row:hover, .list-row--open { background: var(--bg); }
.list-row-main { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem; flex: 1; min-width: 0; background: none; border: none; font-family: inherit; text-align: left; cursor: pointer; }
.list-row-main:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 1px; }
.list-chevron { color: var(--text-muted); flex-shrink: 0; transition: transform var(--transition); font-size: var(--fs-xl);}
.list-row--open .list-chevron { transform: rotate(90deg); color: var(--accent);  }
.list-name { flex: 1; min-width: 0; color: var(--text); font-size: var(--fs-md); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.list-count { color: var(--text-muted); font-size: var(--fs-sm); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); flex-shrink: 0; }
.list-delete { flex-shrink: 0; width: 24px; margin: 0.25rem 0.3rem 0.25rem 0; border: none; border-radius: 5px; background: none; color: var(--text-muted); font-size: var(--fs-md); cursor: pointer; transition: all 0.15s; }
.list-delete:hover { background: var(--danger-dim); color: var(--danger); }

.list-detail { padding: 0.5rem 0.4rem 0.9rem; display: flex; flex-direction: column; gap: 0.6rem; border-bottom: 1px solid var(--border); }
.recipient-rows { display: flex; flex-direction: column; max-height: 11rem; overflow-y: auto; }
.recipient-row { display: flex; align-items: center; gap: 0.5rem; padding: 0.25rem 0; font-size: var(--fs-md); }
.recipient-email { flex: 1; min-width: 0; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.recipient-remove { flex-shrink: 0; width: 20px; border: none; border-radius: 4px; background: none; color: var(--text-muted); font-size: var(--fs-sm); cursor: pointer; transition: all 0.15s; }
.recipient-remove:hover { background: var(--danger-dim); color: var(--danger); }

.form-group { display: flex; flex-direction: column; gap: 0.3rem; }
.form-group label { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); }
.input { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.45rem 0.6rem; color: var(--text); font-size: var(--fs-input); outline: none; width: 100%; box-sizing: border-box; transition: border-color 0.2s; font-family: inherit; }
.input:focus { border-color: var(--accent); }
.textarea { resize: vertical; min-height: 2.6rem; line-height: 1.5; font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); font-size: var(--fs-input); }

.row-end { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
.recipient-count { font-size: var(--fs-md); font-weight: 600; color: var(--accent-bright); }
.recipient-count--empty { color: var(--text-muted); }
.btn--sm { padding: 0.3rem 0.7rem; font-size: var(--fs-md); }

.new-list { margin-top: 0.4rem; padding-top: 0.75rem; border-top: 1px solid var(--border); display: flex; flex-direction: column; gap: 0.5rem; }
.new-list-label { font-size: var(--fs-md); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); }

.lists-footer { display: flex; justify-content: flex-end; gap: 0.5rem; padding: 0.9rem 1.25rem; border-top: 1px solid var(--border); flex-shrink: 0; }
.btn-spin-inline { width: 12px; height: 12px; border: 2px solid rgba(0,0,0,0.2); border-top-color: currentColor; border-radius: 50%; animation: seq-spin 0.6s linear infinite; }

@media (prefers-reduced-motion: reduce) {
  .list-chevron { transition: none !important; }
}
</style>
