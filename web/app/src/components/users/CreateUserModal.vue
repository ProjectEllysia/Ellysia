<template>
  <Teleport to="body">
    <div v-if="show" class="modal-overlay" @click.self="$emit('close')">
      <div class="modal-box">
        <div class="modal-header">
          <h3>Nuevo Usuario</h3>
          <button class="modal-close" @click="$emit('close')">&times;</button>
        </div>

        <form @submit.prevent="handleSubmit">
          <div class="modal-section">
            <h4>Información personal</h4>
            <div class="form-row">
              <div class="form-group"><label for="cu-first">Nombre</label><input id="cu-first" v-model="form.first_name" type="text" required class="inp" /></div>
              <div class="form-group"><label for="cu-last">Apellido</label><input id="cu-last" v-model="form.last_name" type="text" required class="inp" /></div>
            </div>
          </div>

          <div class="modal-section">
            <h4>Credenciales</h4>
            <div class="form-row">
              <div class="form-group"><label for="cu-username">Usuario</label><input id="cu-username" v-model="form.username" type="text" required class="inp" /></div>
              <div class="form-group"><label for="cu-email">Email</label><input id="cu-email" v-model="form.email" type="email" required class="inp" /></div>
            </div>
            <div class="form-group" style="margin-top:0.65rem">
              <label for="cu-password">Contraseña</label>
              <div class="password-wrap">
                <input :id="'cu-password'" v-model="form.password" :type="pwVisible ? 'text' : 'password'" required class="inp" placeholder="Mínimo 8 caracteres" />
                <button type="button" class="pw-toggle" @click="pwVisible = !pwVisible" tabindex="-1">
                  <svg v-if="pwVisible" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                  <svg v-else width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                </button>
              </div>
              <div v-if="form.password" class="pw-strength">
                <div class="strength-bar" :class="`strength--${strengthLevel}`"><div class="strength-fill" :style="{ width: strengthPct + '%' }"></div></div>
                <span class="strength-label">{{ strengthLabel }}</span>
              </div>
            </div>
          </div>

          <div v-if="auth.isRoot" class="modal-section">
            <h4>Rol</h4>
            <div class="form-group"><select v-model="form.role" class="inp select"><option value="role_user">Usuario</option><option value="role_admin">Administrador</option></select></div>
          </div>

          <p v-if="errorMsg" class="form-error">{{ errorMsg }}</p>

          <div class="modal-actions">
            <button type="button" class="btn btn--secondary" @click="$emit('close')">Cancelar</button>
            <button type="submit" class="btn btn--primary" :disabled="submitting">{{ submitting ? 'Creando…' : 'Crear Usuario' }}</button>
          </div>
        </form>
      </div>
    </div>
  </Teleport>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { useAuthStore } from '@/stores/authStore'

defineProps({ show: { type: Boolean, default: false } })
const emit = defineEmits(['close', 'created'])
const auth = useAuthStore()
const form = reactive({ first_name: '', last_name: '', username: '', email: '', password: '', role: 'role_user' })
const pwVisible = ref(false)
const submitting = ref(false)
const errorMsg = ref('')

const strengthLevel = computed(() => { const p = form.password; if (!p) return ''; if (p.length < 8) return 'weak'; if (p.length >= 10 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) return 'strong'; return 'medium' })
const strengthPct = computed(() => ({ weak: 25, medium: 55, strong: 100 }[strengthLevel.value] || 0))
const strengthLabel = computed(() => ({ weak: 'Débil', medium: 'Media', strong: 'Fuerte' }[strengthLevel.value] || ''))

function reset() { Object.assign(form, { first_name: '', last_name: '', username: '', email: '', password: '', role: 'role_user' }); pwVisible.value = false; errorMsg.value = ''; submitting.value = false }
async function handleSubmit() { errorMsg.value = ''; if (form.password.length < 8) { errorMsg.value = 'La contraseña debe tener al menos 8 caracteres.'; return }; submitting.value = true; emit('created', { ...form }) }
defineExpose({ reset })
</script>

<style scoped>
.modal-overlay { position: fixed; inset: 0; z-index: 100; background: rgba(0,0,0,.6); display: flex; align-items: center; justify-content: center; padding: 1.5rem; backdrop-filter: blur(4px); }
.modal-box { background: var(--surface); border: 1px solid var(--border-solid); border-radius: 12px; width: 100%; max-width: 500px; max-height: 90vh; overflow-y: auto; padding: 1.5rem; }
.modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.1rem; }
.modal-header h3 { font-size: var(--fs-xl); font-weight: 700; color: var(--text); margin: 0; font-family: var(--font-display); font-size-adjust: var(--fsa-display); }
.modal-close { background: none; border: none; font-size: var(--fs-lg); color: var(--text-muted); cursor: pointer; padding: 0 0.2rem; line-height: 1; }
.modal-close:hover { color: var(--text); }
.modal-section { margin-bottom: 0.85rem; }
.modal-section h4 { font-size: var(--fs-lg); font-weight: 600; color: var(--text-dim); margin: 0 0 0.4rem; }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.65rem; }
.form-group { display: flex; flex-direction: column; gap: 0.25rem; }
.form-group label { font-size: var(--fs-md); font-weight: 600; color: var(--text-dim); margin-bottom: 0; }
.inp { background: var(--bg); border: 1px solid var(--border-solid); border-radius: 6px; padding: 0.45rem 0.6rem; color: var(--text); font-size: var(--fs-input); outline: none; width: 100%; box-sizing: border-box; transition: border-color 0.2s; }
.inp:focus { border-color: var(--accent); }
.select { cursor: pointer; appearance: auto; }
.password-wrap { position: relative; }
.password-wrap .inp { padding-right: 2.3rem; }
.pw-toggle { position: absolute; right: 0.4rem; top: 50%; transform: translateY(-50%); background: none; border: none; color: var(--text-muted); cursor: pointer; padding: 0.15rem; display: flex; }
.pw-toggle:hover { color: var(--text); }
.pw-strength { display: flex; align-items: center; gap: 0.4rem; margin-top: 0.25rem; }
.strength-bar { flex: 1; height: 4px; background: var(--border-solid); border-radius: 2px; overflow: hidden; }
.strength-fill { height: 100%; border-radius: 2px; transition: width 0.25s, background 0.25s; }
.strength--weak .strength-fill { background: var(--danger); }
.strength--medium .strength-fill { background: var(--warn); }
.strength--strong .strength-fill { background: var(--success); }
.strength-label { font-size: var(--fs-md); font-weight: 600; color: var(--text-muted); min-width: 38px; }
.form-error { color: var(--danger); font-size: var(--fs-lg); margin: 0.4rem 0; }
.modal-actions { display: flex; gap: 0.6rem; justify-content: flex-end; margin-top: 1.1rem; }
</style>
