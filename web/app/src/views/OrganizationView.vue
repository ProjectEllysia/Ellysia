<template>
  <div class="org-page">
    <StarBackground />
    <Topbar title="Mi organización" />

    <main class="main">
      <!-- Sin organización: crearla, o explicar por qué no se puede -->
      <section v-if="!account.organization" class="section section--empty">
        <h1>Aún no tienes organización</h1>
        <p class="lede">
          Una organización deja que tu gente use Ellysia bajo tu plan, sin pagar
          una licencia por cabeza. Comparte plan y factura — nunca datos: no verás
          sus bóvedas, ni sus correos analizados, ni sus escaneos.
        </p>

        <form v-if="canCreate" class="create-form" @submit.prevent="create">
          <div class="form-group">
            <label for="org-name">Nombre de la organización</label>
            <input id="org-name" v-model="newName" type="text" required minlength="2"
                   maxlength="128" class="inp" placeholder="Acme S.L." />
          </div>
          <button type="submit" class="btn btn--primary" :disabled="creating">
            {{ creating ? 'Creando…' : 'Crear organización' }}
          </button>
        </form>

        <p v-else class="hint">
          Tu plan no incluye la gestión de una organización.
          <router-link to="/planes" class="link">Ver planes</router-link>.
        </p>
      </section>

      <template v-else>
        <section class="head">
          <div>
            <span class="head-eyebrow">{{ account.isOwner ? 'Gestionas' : 'Perteneces a' }}</span>
            <h1 class="head-name">{{ account.organization.name }}</h1>
            <p class="head-meta">{{ account.organization.memberCount }} miembro(s)</p>
          </div>
          <button v-if="!account.isOwner" class="btn btn--danger" @click="leave">
            Salir de la organización
          </button>
        </section>

        <p v-if="!account.isOwner" class="hint">
          Tu plan personal sigue siendo tuyo: lo que la organización incluye se
          suma a lo que ya tienes, y si te vas te lo llevas intacto.
        </p>

        <template v-if="account.isOwner">
          <section class="section">
            <h2>Invitar</h2>
            <p class="section-desc">
              Si esa dirección ya tiene cuenta, recibirá un enlace y no entrará
              hasta que acepte. Si no la tiene, se le crea una y se le mandan las
              credenciales.
            </p>
            <form class="invite-form" @submit.prevent="invite">
              <input v-model="inviteEmail" type="email" required class="inp"
                     placeholder="persona@empresa.com" />
              <button type="submit" class="btn btn--primary" :disabled="inviting">
                {{ inviting ? 'Enviando…' : 'Invitar' }}
              </button>
            </form>
          </section>

          <section class="section">
            <h2>Miembros</h2>
            <table class="table">
              <thead>
                <tr><th>Usuario</th><th>Correo</th><th>Rol</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="member in members" :key="member.userId">
                  <td>{{ member.fullName || member.username }}</td>
                  <td class="mono">{{ member.email }}</td>
                  <td>{{ member.role === 'owner' ? 'Dueño' : 'Miembro' }}</td>
                  <td class="td-actions">
                    <button v-if="member.role !== 'owner'" class="btn-link btn-link--danger"
                            @click="expel(member)">
                      Expulsar
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </section>

          <section class="section">
            <h2>Invitaciones</h2>
            <p v-if="!invitations.length" class="hint">No hay invitaciones.</p>
            <table v-else class="table">
              <thead>
                <tr><th>Correo</th><th>Estado</th><th>Caduca</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="invitation in invitations" :key="invitation.id">
                  <td class="mono">{{ invitation.email }}</td>
                  <td>{{ STATUS[invitation.status] ?? invitation.status }}</td>
                  <td>{{ account.formatDate(invitation.expiresAt) }}</td>
                  <td class="td-actions">
                    <button v-if="invitation.status === 'pending'" class="btn-link btn-link--danger"
                            @click="revoke(invitation)">
                      Revocar
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </section>
        </template>
      </template>
    </main>

    <ConfirmModal
      :show="confirm.open"
      :title="confirm.title"
      :message="confirm.message"
      :danger="true"
      confirm-label="Confirmar"
      @confirm="confirm.action()"
      @cancel="confirm.open = false"
    />
  </div>
</template>

<script setup>
/**
 * Gestión de la organización.
 *
 * Lo que el dueño ve de su gente es identidad y nada más — ni sus escaneos, ni
 * sus análisis, ni sus bóvedas. No es una carencia de esta pantalla: es la
 * garantía que se vende, y la API tampoco lo devuelve.
 */
import { ref, computed, onMounted } from 'vue'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import ConfirmModal from '@/components/shared/ConfirmModal.vue'
import { useApi } from '@/composables/useApi'
import { useAccountStore } from '@/stores/accountStore'
import { useToastStore } from '@/stores/toastStore'

const { apiFetch, apiError } = useApi()
const account = useAccountStore()
const toast = useToastStore()

const STATUS = {
  pending: 'Pendiente',
  accepted: 'Aceptada',
  revoked: 'Revocada',
  expired: 'Caducada',
}

const members = ref([])
const invitations = ref([])
const newName = ref('')
const inviteEmail = ref('')
const creating = ref(false)
const inviting = ref(false)
const confirm = ref({ open: false, title: '', message: '', action: () => {} })

const canCreate = computed(() => account.plan?.organizationEnabled === true)

async function load() {
  await account.loadOrganization()
  if (!account.organization || !account.isOwner) return

  const id = account.organization.id
  const [membersRes, invitationsRes] = await Promise.all([
    apiFetch(`/organizations/${id}/members`),
    apiFetch(`/organizations/${id}/invitations`),
  ])
  if (membersRes?.ok) members.value = (await membersRes.json()).members ?? []
  if (invitationsRes?.ok) invitations.value = (await invitationsRes.json()).invitations ?? []
}

async function create() {
  creating.value = true
  try {
    if (await account.createOrganization(newName.value)) {
      newName.value = ''
      await load()
    }
  } finally {
    creating.value = false
  }
}

async function invite() {
  inviting.value = true
  try {
    const res = await apiFetch(`/organizations/${account.organization.id}/invitations`, {
      method: 'POST',
      body: JSON.stringify({ email: inviteEmail.value }),
    })
    if (!res?.ok) {
      // El 402 ya lo avisa useApi; aquí solo el resto.
      if (res?.status !== 402) {
        toast.show(await apiError(res, 'No se pudo invitar.'), 'error')
      }
      return
    }
    toast.show('Invitación enviada.', 'success')
    inviteEmail.value = ''
    await load()
  } finally {
    inviting.value = false
  }
}

function expel(member) {
  confirm.value = {
    open: true,
    title: `¿Expulsar a ${member.username}?`,
    message: 'Conservará su cuenta, sus datos y su plan personal. Solo perderá '
      + 'lo que la organización le daba.',
    action: async () => {
      confirm.value.open = false
      const res = await apiFetch(
        `/organizations/${account.organization.id}/members/${member.userId}`,
        { method: 'DELETE' },
      )
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo expulsar.'), 'error')
        return
      }
      toast.show('Miembro expulsado.', 'success')
      await load()
    },
  }
}

function revoke(invitation) {
  confirm.value = {
    open: true,
    title: '¿Revocar la invitación?',
    message: `El enlace enviado a ${invitation.email} dejará de funcionar.`,
    action: async () => {
      confirm.value.open = false
      const res = await apiFetch(`/organizations/invitations/${invitation.id}`, {
        method: 'DELETE',
      })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo revocar.'), 'error')
        return
      }
      await load()
    },
  }
}

function leave() {
  confirm.value = {
    open: true,
    title: '¿Salir de la organización?',
    message: 'Conservarás tu cuenta, tus datos y tu plan personal. Perderás lo '
      + 'que la organización te daba, y lo que quede por encima de tu plan se '
      + 'quedará en solo lectura — no se borra nada.',
    action: async () => {
      confirm.value.open = false
      const res = await apiFetch('/organizations/mine', { method: 'DELETE' })
      if (!res?.ok) {
        toast.show(await apiError(res, 'No se pudo salir.'), 'error')
        return
      }
      toast.show('Has salido de la organización.', 'success')
      await load()
    },
  }
}

onMounted(async () => {
  await account.loadPlan()
  await load()
})
</script>

<style scoped>
.org-page { min-height: 100vh; background: var(--bg); }
.main { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem 4rem; display: flex; flex-direction: column; gap: 1.5rem; }

.head { display: flex; align-items: flex-end; justify-content: space-between; gap: 1.5rem; flex-wrap: wrap; }
.head-eyebrow {
  font-family: var(--font-epic); font-size: var(--fs-body); font-weight: 500;
  letter-spacing: 0.3em; text-transform: uppercase; color: var(--accent);
}
.head-name {
  font-family: var(--font-display); font-size: clamp(1.8rem, 4vw, 2.4rem);
  font-weight: 600; color: var(--text); margin-top: 0.3rem;
}
.head-meta { color: var(--text-muted); margin-top: 0.2rem; }

.section {
  background: var(--surface); border: 1px solid var(--border-solid);
  border-radius: 12px; padding: 1.5rem;
}
.section h1 { font-size: var(--fs-xl); font-weight: 600; color: var(--text); }
.section h2 { font-size: var(--fs-xl); font-weight: 600; color: var(--text); }
.section-desc, .lede { font-size: var(--fs-md); color: var(--text-muted); margin-top: 0.5rem; max-width: 62ch; }
.hint { font-size: var(--fs-body); color: var(--text-muted); }
.link { color: var(--accent); text-decoration: underline; }

.create-form { margin-top: 1.4rem; display: flex; flex-direction: column; gap: 0.9rem; max-width: 380px; }
.invite-form { margin-top: 1.2rem; display: flex; gap: 0.7rem; flex-wrap: wrap; }
.invite-form .inp { flex: 1; min-width: 220px; }

.form-group { display: flex; flex-direction: column; gap: 0.35rem; }
.form-group label { font-size: var(--fs-body); color: var(--text-dim); }
.inp {
  padding: 0.6rem 0.8rem; border-radius: 6px;
  background: var(--bg); color: var(--text);
  border: 1px solid var(--border-med);
}
.inp:focus { outline: none; border-color: var(--accent); }

.table { width: 100%; border-collapse: collapse; margin-top: 1.2rem; font-size: var(--fs-md); }
.table th {
  text-align: left; padding: 0.5rem 0.6rem;
  font-size: var(--fs-body); font-weight: 500; color: var(--text-muted);
  text-transform: uppercase; letter-spacing: 0.08em;
  border-bottom: 1px solid var(--border);
}
.table td { padding: 0.65rem 0.6rem; border-bottom: 1px solid var(--border); color: var(--text-dim); }
.mono { font-family: var(--font-mono); font-size: var(--fs-body); }
.td-actions { text-align: right; }

.btn {
  font-family: var(--font-epic); font-size: var(--fs-body); font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
  padding: 0.6rem 1.2rem; border-radius: 3px;
  border: 1px solid var(--border-med); color: var(--text-dim);
  transition: all var(--transition);
}
.btn--primary { background: var(--accent-dim); border-color: var(--accent); color: var(--accent-bright); }
.btn--primary:hover { background: var(--accent); color: var(--on-accent); }
.btn--danger { border-color: var(--danger); color: var(--danger); }
.btn--danger:hover { background: var(--danger-dim); }
.btn:disabled { opacity: 0.6; cursor: not-allowed; }

.btn-link { font-size: var(--fs-body); color: var(--text-muted); }
.btn-link:hover { color: var(--text); }
.btn-link--danger:hover { color: var(--danger); }
</style>
