<template>
  <Teleport to="body">
    <div v-if="show" class="modal-overlay" @click.self="$emit('close')">
      <div class="modal-box">
        <div class="modal-header">
          <h3>Detalles del Usuario</h3>
          <button class="modal-close" @click="$emit('close')">&times;</button>
        </div>
        <div v-if="loadingUser" class="modal-loading">Cargando…</div>
        <template v-else-if="user">
          <div class="detail-header">
            <div class="detail-avatar" :class="`role-avatar--${roleClass}`">{{ initials }}</div>
            <div class="detail-names"><h4>{{ user.first_name || '—' }} {{ user.last_name || '' }}</h4><p>@{{ user.username }}</p></div>
            <span class="detail-role-badge" :class="`role-badge--${roleClass}`">{{ roleLabel }}</span>
          </div>
          <div class="detail-grid">
            <div class="detail-item"><span class="detail-label">Nombre</span><span class="detail-value">{{ user.first_name || '—' }} {{ user.last_name || '' }}</span></div>
            <div class="detail-item"><span class="detail-label">Email</span><span class="detail-value">{{ user.email }}</span></div>
            <div class="detail-item"><span class="detail-label">Rol</span><span class="detail-value">{{ roleLabel }}</span></div>
            <div class="detail-item"><span class="detail-label">Creado</span><span class="detail-value">{{ formatDate(user.created_at) }}</span></div>
          </div>
          <div class="detail-section">
            <h4>Atributos ABAC</h4>
            <div class="attr-tags">
              <span v-for="attr in attributes" :key="attr" class="attr-tag">
                {{ attr }}
                <button v-if="canManage" class="attr-remove" @click="handleRemoveAttribute(attr)" title="Eliminar">&times;</button>
              </span>
              <span v-if="attributes.length === 0" class="attr-empty">Sin atributos</span>
            </div>
            <div v-if="canManage" class="attr-manage">
              <button v-if="!showAttrForm" class="btn btn--sm btn--secondary" @click="showAttrForm = true">+ Añadir atributo</button>
              <div v-else class="attr-form">
                <div v-for="mod in ALL_ATTRIBUTES" :key="mod.module" class="attr-module">
                  <h5>{{ mod.module }}</h5>
                  <div class="attr-checks">
                    <label v-for="a in mod.attrs" :key="a.name" class="attr-check">
                      <input type="checkbox" :value="a.name" v-model="selectedAttrs" :disabled="attributes.includes(a.name)" />
                      <span>{{ a.desc }}</span>
                    </label>
                  </div>
                </div>
                <div class="attr-form-actions">
                  <button type="button" class="btn btn--sm btn--secondary" @click="showAttrForm = false; selectedAttrs = []">Cancelar</button>
                  <button type="button" class="btn btn--sm btn--primary" :disabled="selectedAttrs.length === 0" @click="handleAddAttributes">Guardar</button>
                </div>
              </div>
            </div>
          </div>
          <div v-if="canDelete" class="detail-section danger-zone">
            <h4>Dar de baja</h4>
            <p class="danger-note">
              Se borra la cuenta y todo lo que cuelga de ella: escaneos, campañas,
              informes y su bóveda. No hay vuelta atrás.
            </p>
            <button class="btn btn--sm btn--danger" @click="showDeleteConfirm = true">
              Eliminar usuario
            </button>
          </div>
        </template>
      </div>
    </div>

    <ConfirmModal
      :show="showDeleteConfirm"
      title="Eliminar usuario"
      emphasis="Esta acción no se puede deshacer."
      :message="deleteMessage"
      confirm-label="Eliminar"
      danger
      @confirm="handleDelete"
      @cancel="showDeleteConfirm = false"
    />
  </Teleport>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useUtils } from '@/composables/useUtils'
import { useAuthStore } from '@/stores/authStore'
import { useUsersStore } from '@/stores/usersStore'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'

const { formatDate, getInitials } = useUtils()
const auth = useAuthStore()
const store = useUsersStore()

const props = defineProps({ show: { type: Boolean, default: false }, userId: { type: [Number, String], default: null } })
const emit = defineEmits(['close', 'refresh'])

const user = ref(null)
const attributes = ref([])
const loadingUser = ref(false)
const showAttrForm = ref(false)
const selectedAttrs = ref([])
const showDeleteConfirm = ref(false)

const canManage = computed(() => auth.isAdmin)

/** La jerarquía real la aplica el backend; aquí solo se evita ofrecer un 403.
 *  Un admin llega a los usuarios normales, el root llega a todos, y nadie se
 *  da de baja a sí mismo desde aquí: para eso está el perfil. */
const canDelete = computed(() => {
  if (!canManage.value || !user.value) return false
  if (user.value.username === auth.username()) return false
  return auth.isRoot || (user.value.role || 'role_user') === 'role_user'
})
const deleteMessage = computed(
  () => `Vas a eliminar la cuenta de @${user.value?.username} y todos sus datos.`,
)
const ALL_ATTRIBUTES = [
  { module: 'Aegis', attrs: [{ name: 'aegis_read', desc: 'Lectura' }, { name: 'aegis_write', desc: 'Escritura' }, { name: 'aegis_create', desc: 'Creación' }, { name: 'aegis_delete', desc: 'Eliminación' }] },
  { module: 'Themis', attrs: [{ name: 'themis_read', desc: 'Lectura' }, { name: 'themis_write', desc: 'Escritura' }, { name: 'themis_create', desc: 'Creación' }, { name: 'themis_delete', desc: 'Eliminación' }] },
  { module: 'Acheron', attrs: [{ name: 'acheron_read', desc: 'Lectura' }, { name: 'acheron_write', desc: 'Escritura' }, { name: 'acheron_create', desc: 'Creación' }, { name: 'acheron_delete', desc: 'Eliminación' }] },
]

const initials = computed(() => getInitials(user.value?.first_name || '', user.value?.last_name || ''))
const roleClass = computed(() => { const r = user.value?.role || 'role_user'; if (r === 'role_root') return 'root'; if (r === 'role_admin') return 'admin'; return 'user' })
const roleLabel = computed(() => { const r = user.value?.role || 'role_user'; if (r === 'role_root') return 'Root'; if (r === 'role_admin') return 'Admin'; return 'Usuario' })

watch(() => props.show, async (v) => {
  if (!v || !props.userId) return
  loadingUser.value = true; showAttrForm.value = false; selectedAttrs.value = []; showDeleteConfirm.value = false
  try { user.value = store.users.find(u => u.id == props.userId) || null; attributes.value = await store.loadUserAttributes(props.userId) } finally { loadingUser.value = false }
})

async function handleRemoveAttribute(attr) { const ok = await store.removeAttributes(props.userId, [attr]); if (ok) attributes.value = await store.loadUserAttributes(props.userId) }
/** El store ya recarga la lista al terminar, así que aquí solo queda cerrar. */
async function handleDelete() {
  showDeleteConfirm.value = false
  if (await store.deleteUser(props.userId)) emit('close')
}
async function handleAddAttributes() { if (selectedAttrs.value.length === 0) return; const ok = await store.addAttributes(props.userId, selectedAttrs.value); if (ok) { showAttrForm.value = false; selectedAttrs.value = []; attributes.value = await store.loadUserAttributes(props.userId) } }
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; z-index: 100; background: rgba(0,0,0,.6); display: flex; align-items: center; justify-content: center; padding: 1.5rem; backdrop-filter: blur(4px); }
.modal-box { background: var(--surface); border: 1px solid var(--border-solid); border-radius: 12px; width: 100%; max-width: 540px; max-height: 90vh; overflow-y: auto; padding: 1.5rem; }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.1rem; }
.modal-header h3 { font-size: var(--fs-xl); font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.modal-close { background: none; border: none; font-size: var(--fs-lg); color: var(--text-muted); cursor: pointer; padding: 0 0.2rem; line-height: 1; }
.modal-close:hover { color: var(--text); }
.modal-loading { text-align: center; padding: 2.5rem 0; color: var(--text-muted); font-size: var(--fs-lg); }
.detail-header { display: flex; align-items: center; gap: 0.85rem; margin-bottom: 1.1rem; }
.detail-avatar { width: 48px; height: 48px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-size: var(--fs-2xl); font-weight: 700; background: var(--accent-dim); color: var(--accent-bright); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.role-avatar--root  { background: rgba(217,108,108,0.15); color: var(--danger); }
.role-avatar--admin { background: rgba(212,160,74,0.15); color: var(--warn); }
.role-avatar--user  { background: rgba(96,128,224,0.15); color: var(--info); }
.detail-names { flex: 1; min-width: 0; }
.detail-names h4 { font-size: var(--fs-xl); font-weight: 700; color: var(--text); margin: 0 0 0.1rem; }
.detail-names p { font-size: var(--fs-lg); color: var(--text-dim); margin: 0; }
.detail-role-badge { font-size: var(--fs-body); font-weight: 700; text-transform: uppercase; letter-spacing: 0.02em; padding: 0.1rem 0.45rem; border-radius: 4px; }
.role-badge--root  { background: rgba(217,108,108,0.15);  color: var(--danger); }
.role-badge--admin { background: rgba(212,160,74,0.15); color: var(--warn); }
.role-badge--user  { background: rgba(96,128,224,0.12); color: var(--info); }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.65rem; margin-bottom: 1.25rem; padding: 0.85rem; background: var(--bg); border-radius: 8px; }
.detail-item { display: flex; flex-direction: column; gap: 0.1rem; }
.detail-label { font-size: var(--fs-md); font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.03em; }
.detail-value { font-size: var(--fs-lg); color: var(--text); word-break: break-word; }
.detail-section { margin-top: 1.25rem; }
.detail-section h4 { font-size: var(--fs-lg); font-weight: 600; color: var(--text); margin: 0 0 0.65rem; }
.attr-tags { display: flex; flex-wrap: wrap; gap: 0.35rem; margin-bottom: 0.65rem; }
.attr-tag { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.2rem 0.45rem; font-size: var(--fs-md); font-weight: 500; background: var(--bg); border: 1px solid var(--border); border-radius: 5px; color: var(--text); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.attr-remove { background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: var(--fs-sm); line-height: 1; padding: 0; display: flex; }
.attr-remove:hover { color: var(--danger); }
.attr-empty { font-size: var(--fs-lg); color: var(--text-muted); }
.attr-manage { margin-top: 0.65rem; }
.attr-form { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 8px; padding: 0.85rem; margin-top: 0.4rem; }
.attr-module { margin-bottom: 0.65rem; }
.attr-module h5 { font-size: var(--fs-md); font-weight: 700; color: var(--accent); margin: 0 0 0.3rem; }
.attr-checks { display: flex; flex-wrap: wrap; gap: 0.35rem; }
.attr-check { display: flex; align-items: center; gap: 0.25rem; font-size: var(--fs-md); color: var(--text); cursor: pointer; }
.attr-check input { accent-color: var(--accent); cursor: pointer; }
.attr-form-actions { display: flex; gap: 0.4rem; justify-content: flex-end; margin-top: 0.65rem; }
.danger-zone { border-top: 1px solid var(--border); padding-top: 1rem; }
.danger-zone h4 { color: var(--danger); }
.danger-note { font-size: var(--fs-md); color: var(--text-muted); margin: 0 0 0.65rem; }
</style>
