<template>
  <div class="profile-page">
    <StarBackground />
    <Topbar title="Perfil de Usuario" />

    <main class="main">
      <div v-if="store.loading" class="loading-block"><div class="skeleton skeleton--lg"></div></div>

      <template v-else>
        <section class="profile-header">
          <div class="profile-avatar">{{ initials }}</div>
          <h1 class="profile-display-name">{{ store.profile.first_name }} {{ store.profile.last_name }}</h1>
          <p class="profile-username">@{{ store.profile.username }}</p>
        </section>

        <section class="profile-section">
          <h2>Información Personal</h2>
          <form class="profile-form" @submit.prevent="handleProfileSubmit">
            <div class="form-row">
              <div class="form-group"><label for="first-name">Nombre</label><input id="first-name" v-model="firstName" type="text" required class="inp" placeholder="Tu nombre" /></div>
              <div class="form-group"><label for="last-name">Apellido</label><input id="last-name" v-model="lastName" type="text" required class="inp" placeholder="Tu apellido" /></div>
            </div>
            <div class="form-row">
              <div class="form-group"><label for="profile-email">Email</label><input id="profile-email" type="email" :value="store.profile.email" disabled class="inp inp--disabled" /></div>
              <div class="form-group"><label for="profile-username">Usuario</label><input id="profile-username" type="text" :value="store.profile.username" disabled class="inp inp--disabled" /></div>
            </div>
            <div class="form-actions">
              <button type="button" class="btn btn--secondary" @click="$router.push('/')">Cancelar</button>
              <button type="submit" class="btn btn--primary" :disabled="savingProfile">{{ savingProfile ? 'Guardando…' : 'Guardar Cambios' }}</button>
            </div>
          </form>
        </section>

        <section class="profile-section">
          <h2>Seguridad</h2>
          <form class="profile-form" @submit.prevent="handlePasswordSubmit">
            <div class="form-row form-row--single">
              <div class="form-group"><label for="current-pwd">Contraseña actual</label><input id="current-pwd" v-model="currentPassword" type="password" required class="inp" placeholder="••••••••" /></div>
            </div>
            <div class="form-row">
              <div class="form-group"><label for="new-pwd">Nueva contraseña</label><input id="new-pwd" v-model="newPassword" type="password" required minlength="8" class="inp" placeholder="Mínimo 8 caracteres" /></div>
              <div class="form-group"><label for="confirm-pwd">Confirmar contraseña</label><input id="confirm-pwd" v-model="confirmPassword" type="password" required minlength="8" class="inp" placeholder="Repite la contraseña" /></div>
            </div>
            <p v-if="passwordError" class="form-error">{{ passwordError }}</p>
            <div class="form-actions">
              <button type="submit" class="btn btn--danger" :disabled="savingPassword">{{ savingPassword ? 'Cambiando…' : 'Cambiar Contraseña' }}</button>
            </div>
          </form>
        </section>

        <section class="profile-section">
          <h2>Verificación en dos pasos (MFA)</h2>

          <Transition name="mfa-fade" mode="out-in">
            <!-- Códigos de recuperación: se muestran una sola vez tras confirmar -->
            <div v-if="recoveryCodes.length" key="recovery" class="mfa-recovery-codes">
              <p class="mfa-recovery-warning">Guarda estos códigos en un lugar seguro: cada uno sirve para un solo inicio de sesión de emergencia si pierdes tu app autenticadora. No se volverán a mostrar.</p>
              <ul class="mfa-recovery-list">
                <li v-for="c in recoveryCodes" :key="c"><code>{{ c }}</code></li>
              </ul>
              <div class="form-actions">
                <button type="button" class="btn btn--secondary" @click="downloadRecoveryCodes">Descargar .txt</button>
                <button type="button" class="btn btn--primary" @click="recoveryCodes = []">Ya los guardé</button>
              </div>
            </div>

            <!-- Activado -->
            <div v-else-if="mfa.status.enabled" key="enabled">
              <p class="mfa-status-text mfa-status-text--on">✓ Verificación en dos pasos activada.</p>
              <form class="profile-form" @submit.prevent="handleDisableMfa">
                <div class="form-row form-row--single">
                  <div class="form-group">
                    <label for="disable-code">Código de la app o de recuperación</label>
                    <input id="disable-code" v-model="disableCode" type="text" class="inp" placeholder="123456 o XXXX-XXXX" required />
                  </div>
                </div>
                <div class="form-actions">
                  <button type="submit" class="btn btn--danger" :disabled="disabling">{{ disabling ? 'Desactivando…' : 'Desactivar MFA' }}</button>
                </div>
              </form>
            </div>

            <!-- Sin activar -->
            <div v-else key="disabled">
              <p class="mfa-status-text">No tienes la verificación en dos pasos activada.</p>
              <div class="form-actions">
                <button type="button" class="btn btn--primary" :disabled="startingSetup" @click="handleStartSetup">{{ startingSetup ? 'Generando…' : 'Activar MFA' }}</button>
              </div>
            </div>
          </Transition>
        </section>
      </template>
    </main>

    <MfaSetupModal
      :open="!!mfa.pendingSetup.secret"
      :secret="mfa.pendingSetup.secret"
      :provisioning-uri="mfa.pendingSetup.provisioningUri"
      :confirming="confirming"
      @confirm="handleConfirmMfa"
      @cancel="mfa.cancelSetup()"
    />

    <AppToast />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import Topbar from '@/components/shared/Topbar.vue'
import StarBackground from '@/components/shared/StarBackground.vue'
import AppToast from '@/components/shared/AppToast.vue'
import MfaSetupModal from '@/components/shared/MfaSetupModal.vue'
import { useProfileStore } from '@/stores/profileStore'
import { useAuthStore } from '@/stores/authStore'
import { useMfaStore } from '@/stores/mfaStore'
import { useUtils } from '@/composables/useUtils'

const store = useProfileStore()
const auth = useAuthStore()
const mfa = useMfaStore()
const router = useRouter()
const { getInitials } = useUtils()
const firstName = ref('')
const lastName = ref('')
const savingProfile = ref(false)
const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const savingPassword = ref(false)
const passwordError = ref('')
const initials = computed(() => getInitials(store.profile.first_name, store.profile.last_name))

/* ── MFA (TOTP) ── */
const startingSetup = ref(false)
const confirming = ref(false)
const disableCode = ref('')
const disabling = ref(false)
const recoveryCodes = ref([])

onMounted(async () => {
  await store.loadProfile()
  firstName.value = store.profile.first_name
  lastName.value = store.profile.last_name
  await mfa.loadStatus()
})

async function handleProfileSubmit() { if (!firstName.value.trim() || !lastName.value.trim()) return; savingProfile.value = true; await store.updateProfile(firstName.value.trim(), lastName.value.trim()); savingProfile.value = false }
async function handlePasswordSubmit() {
  passwordError.value = ''
  if (newPassword.value.length < 8) { passwordError.value = 'La contraseña debe tener al menos 8 caracteres.'; return }
  if (newPassword.value !== confirmPassword.value) { passwordError.value = 'Las contraseñas no coinciden.'; return }
  if (newPassword.value === currentPassword.value) { passwordError.value = 'La nueva contraseña debe ser diferente de la actual.'; return }
  savingPassword.value = true
  const ok = await store.changePassword(newPassword.value)
  savingPassword.value = false
  if (ok) { currentPassword.value = ''; newPassword.value = ''; confirmPassword.value = ''; setTimeout(() => auth.logout(), 2000) }
}

async function handleStartSetup() {
  startingSetup.value = true
  await mfa.setupTotp()
  startingSetup.value = false
}

async function handleConfirmMfa(code) {
  confirming.value = true
  const codes = await mfa.confirmTotp(code)
  confirming.value = false
  if (codes) recoveryCodes.value = codes
}

async function handleDisableMfa() {
  const value = disableCode.value.trim()
  if (!value) return
  disabling.value = true
  const payload = value.includes('-') ? { recoveryCode: value } : { code: value }
  const ok = await mfa.disableTotp(payload)
  disabling.value = false
  if (ok) disableCode.value = ''
}

function downloadRecoveryCodes() {
  const content = `CÓDIGOS DE RECUPERACIÓN MFA - ELLYSIA\n\nGuarda estos códigos en un lugar seguro. Cada uno sirve para un solo inicio de sesión de emergencia si pierdes tu app autenticadora.\n\n${recoveryCodes.value.join('\n')}\n\nNota: Estos códigos no se volverán a mostrar. Si los pierdes, deberás desactivar y reconfigurar MFA.`
  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `ellysia-recovery-codes-${new Date().toISOString().split('T')[0]}.txt`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
.profile-page { min-height: 100vh; background: var(--bg); padding-top: var(--topbar-h); position: relative; }
.main { max-width: 1020px; margin: 0 auto; padding: 1.75rem 1.1rem; position: relative; z-index: 1; }
.profile-header { text-align: center; margin-bottom: 2rem; }
.profile-avatar { width: 72px; height: 72px; border-radius: 50%; background: var(--accent); color: var(--on-accent); font-size: var(--fs-3xl); font-weight: 700; font-family: var(--font-display); display: flex; align-items: center; justify-content: center; margin: 0 auto 0.75rem; }
.profile-display-name { font-size: var(--fs-2xl); font-weight: 700; color: var(--text); margin: 0 0 0.2rem; font-family: var(--font-display); }
.profile-username { font-size: var(--fs-lg); color: var(--text-muted); margin: 0; }
.profile-section { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; margin-bottom: 1.1rem; }
.profile-section h2 { font-size: var(--fs-xl); font-weight: 600; margin: 0 0 0.85rem; color: var(--text); font-family: var(--font-display); }
.profile-form { display: flex; flex-direction: column; gap: 0.85rem; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.85rem; }
.form-row--single { grid-template-columns: 1fr; }
.form-group { display: flex; flex-direction: column; gap: 0.3rem; }
.form-group label { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); }
.inp { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.5rem 0.65rem; color: var(--text); font-size: var(--fs-input); outline: none; transition: border-color 0.2s; }
.inp:focus { border-color: var(--accent); }
.inp--disabled { opacity: 0.55; cursor: not-allowed; }
.form-error { color: var(--danger); font-size: var(--fs-lg); margin: 0; }
.form-actions { display: flex; gap: 0.6rem; justify-content: flex-end; padding-top: 0.35rem; }
.mfa-status-text { font-size: var(--fs-lg); color: var(--text-dim); margin: 0 0 0.85rem; }
.mfa-status-text--on { color: var(--success, #2e9c5b); }
.mfa-fade-enter-active, .mfa-fade-leave-active { transition: opacity 0.18s ease, transform 0.18s ease; }
.mfa-fade-enter-from { opacity: 0; transform: translateY(4px); }
.mfa-fade-leave-to { opacity: 0; transform: translateY(-4px); }
.mfa-recovery-warning { font-size: var(--fs-lg); color: var(--text-dim); margin: 0 0 0.75rem; }
.mfa-recovery-list {
  display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem 1rem;
  list-style: none; margin: 0 0 1rem; padding: 0.75rem; background: var(--bg);
  border: 1px solid var(--border-solid); border-radius: 6px;
}
.mfa-recovery-list code { font-family: monospace; font-size: var(--fs-lg); color: var(--text); }
.loading-block { padding: 3.5rem 0; display: flex; justify-content: center; }
.skeleton { background: var(--surface); border-radius: 8px; animation: pulse 1.4s ease-in-out infinite; }
.skeleton--lg { width: 100%; height: 240px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
</style>
