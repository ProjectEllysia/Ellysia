<template>
  <div class="account-menu" ref="rootRef">
    <button class="avatar-btn" :aria-expanded="open" aria-haspopup="menu"
            :aria-label="`Cuenta de ${name}`" @click="open = !open">
      {{ initials }}
      <span v-if="hasNotice" class="avatar-dot" aria-hidden="true"></span>
    </button>

    <Transition name="drop">
      <div v-if="open" class="drop" role="menu">
        <div class="drop-header">
          <div class="drop-avatar">{{ initials }}</div>
          <div class="drop-name-wrap">
            <h3 class="drop-name">{{ name }}</h3>
            <span class="drop-role">{{ roleLabel }}</span>
          </div>
        </div>

        <router-link v-if="account.plan" to="/mi-plan" class="drop-plan" @click="open = false">
          <span class="drop-plan-name">{{ account.plan.plan.name }}</span>
          <span v-if="notice" class="drop-plan-notice">{{ notice.text }}</span>
          <span v-else class="drop-plan-hint">Ver consumo y límites</span>
        </router-link>

        <nav class="drop-menu">
          <router-link to="/profile" class="drop-item" @click="open = false">Perfil</router-link>
          <router-link to="/mi-plan" class="drop-item" @click="open = false">Mi plan</router-link>

          <router-link v-if="account.organization" to="/organizacion" class="drop-item"
                       @click="open = false">
            {{ account.isOwner ? 'Gestionar organización' : 'Mi organización' }}
          </router-link>
          <router-link v-else-if="canCreateOrganization" to="/organizacion" class="drop-item"
                       @click="open = false">
            Crear organización
          </router-link>

          <template v-if="auth.isAdmin">
            <div class="drop-divider"></div>
            <router-link to="/users" class="drop-item" @click="open = false">Usuarios</router-link>
            <router-link v-if="auth.isRoot" to="/config" class="drop-item" @click="open = false">Configuración</router-link>
            <router-link v-if="auth.isRoot" to="/admin/planes" class="drop-item" @click="open = false">Gestor de planes</router-link>
            <router-link to="/queue" class="drop-item" @click="open = false">Cola de tareas</router-link>
          </template>

          <div class="drop-divider"></div>
          <button class="drop-item drop-item--danger" @click="logout">Cerrar sesión</button>
        </nav>
      </div>
    </Transition>
  </div>
</template>

<script setup>
/**
 * Menú de cuenta, compartido por toda la aplicación.
 *
 * Vivía dentro de `LandingView.vue`, así que las opciones de cuenta solo
 * existían en la portada: desde cualquier herramienta no había forma de llegar
 * a Configuración ni, ahora, a la organización. Al extraerlo aquí, `SiteHeader`
 * y `Topbar` lo montan igual y las opciones están en todas las vistas.
 */
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import { useProfileStore } from '@/stores/profileStore'
import { useAccountStore } from '@/stores/accountStore'

const auth = useAuthStore()
const profileStore = useProfileStore()
const account = useAccountStore()

const open = ref(false)
const rootRef = ref(null)

const name = computed(() => {
  const first = profileStore.profile.first_name
  const last = profileStore.profile.last_name
  if (first || last) return `${first} ${last}`.trim()
  return auth.username() || 'Usuario'
})

const initials = computed(() => {
  const parts = name.value.split(' ').filter(Boolean)
  return parts.length >= 2
    ? (parts[0][0] + parts[1][0]).toUpperCase()
    : (parts[0]?.[0] || 'U').toUpperCase()
})

const roleLabel = computed(() => {
  const role = profileStore.profile.role || auth.role
  if (role === 'role_root') return 'Root'
  if (role === 'role_admin') return 'Admin'
  return 'Usuario'
})

const notice = computed(() => account.notice)
const hasNotice = computed(() => notice.value !== null || account.exceededKeys.length > 0)

/** El toggle de organización es lo único que el plan sí "concede" (§5.1). */
const canCreateOrganization = computed(() => account.plan?.organizationEnabled === true)

function logout() {
  open.value = false
  account.reset()
  auth.logout()
}

let clickOutside = null

onMounted(() => {
  clickOutside = (event) => {
    if (rootRef.value && !rootRef.value.contains(event.target)) open.value = false
  }
  document.addEventListener('click', clickOutside)
})

onUnmounted(() => {
  if (clickOutside) document.removeEventListener('click', clickOutside)
})
</script>

<style scoped>
.account-menu { position: relative; }

.avatar-btn {
  position: relative;
  width: 40px; height: 40px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--accent-dim);
  border: 1.5px solid var(--border-med);
  color: var(--accent-bright);
  font-size: var(--fs-md); font-weight: 700;
  transition: all var(--transition);
}
.avatar-btn:hover { border-color: var(--accent); box-shadow: 0 0 12px var(--accent-dim); }
.avatar-btn:focus-visible { outline: 2px solid var(--accent-bright); outline-offset: 3px; }

/* Punto de aviso: hay algo que mirar en el plan (impago, caducidad, tope
   superado). Sin él, un corte por plan sería una sorpresa cada vez. */
.avatar-dot {
  position: absolute; top: -2px; right: -2px;
  width: 10px; height: 10px; border-radius: 50%;
  background: var(--warning, #d4a04a);
  border: 2px solid var(--bg);
}

.drop {
  position: absolute; top: calc(100% + 0.7rem); right: 0; z-index: 60;
  width: 300px;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 10px;
  padding: 0.85rem;
  box-shadow: 0 24px 56px rgba(0, 0, 0, 0.35);
}
.drop-enter-active, .drop-leave-active { transition: opacity 0.14s ease, transform 0.14s ease; }
.drop-enter-from, .drop-leave-to { opacity: 0; transform: translateY(-6px); }

.drop-header {
  display: flex; align-items: center; gap: 0.65rem;
  padding-bottom: 0.75rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 0.45rem;
}
.drop-avatar {
  width: 38px; height: 38px; border-radius: 50%;
  background: var(--accent-dim); color: var(--accent-bright);
  font-size: var(--fs-sm); font-weight: 700; flex-shrink: 0;
  display: grid; place-items: center;
  border: 1px solid var(--border-med);
}
.drop-name {
  font-size: var(--fs-xl); font-weight: 600; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.drop-role {
  font-family: var(--font-mono); font-size: var(--fs-body); color: var(--accent);
  letter-spacing: 0.06em; text-transform: uppercase;
}

.drop-plan {
  display: block;
  padding: 0.6rem;
  margin-bottom: 0.45rem;
  border-radius: 7px;
  background: var(--accent-dim);
  border: 1px solid var(--border-med);
}
.drop-plan:hover { border-color: var(--accent); }
.drop-plan-name {
  display: block;
  font-family: var(--font-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.12em; text-transform: uppercase;
  color: var(--accent-bright);
}
.drop-plan-hint, .drop-plan-notice {
  display: block; margin-top: 0.2rem;
  font-size: var(--fs-body); color: var(--text-muted);
}
.drop-plan-notice { color: var(--warning, #d4a04a); }

.drop-menu { display: flex; flex-direction: column; gap: 0.15rem; }
.drop-item {
  display: block;
  padding: 0.5rem 0.6rem; border-radius: 7px;
  color: var(--text-dim); font-size: var(--fs-lg); font-weight: 500;
  transition: all 0.15s ease; text-align: left; width: 100%;
}
.drop-item:hover { background: var(--accent-dim); color: var(--text); }
.drop-item--danger { color: var(--danger); }
.drop-item--danger:hover { background: var(--danger-dim); }
.drop-divider { height: 1px; background: var(--border); margin: 0.3rem 0; }
</style>
