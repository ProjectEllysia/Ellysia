<script setup>
import { useToastStore } from '@/stores/toastStore'
const toast = useToastStore()
</script>

<template>
  <Teleport to="body">
    <Transition name="toast">
      <div v-if="toast.visible" :key="toast.id" class="toast"
           :class="toast.type ? `toast--${toast.type}` : ''"
           role="alert" aria-live="assertive">
        <span class="toast__message">{{ toast.message }}</span>
        <RouterLink v-if="toast.action?.to" class="toast__action" :to="toast.action.to"
                    @click="toast.dismiss">
          {{ toast.action.label }}
        </RouterLink>
        <button type="button" class="toast__close" aria-label="Cerrar notificación"
                @click="toast.dismiss">&times;</button>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.toast {
  position: fixed; bottom: 2rem; right: 2rem;
  display: flex; align-items: center; gap: 0.75rem;
  padding: 0.8rem 0.8rem 0.8rem 1.1rem; border-radius: 8px;
  font-size: var(--fs-body); font-weight: 500; line-height: 1.35;
  background: var(--surface-3); border: 1px solid var(--border);
  color: var(--text); z-index: 9999;
  max-width: min(460px, calc(100vw - 2rem)); max-height: 7.5rem; overflow-y: auto;
  overflow-wrap: anywhere; word-break: break-word; white-space: pre-wrap;
  backdrop-filter: blur(12px);
  box-shadow: 0 12px 32px rgba(0,0,0,0.34);
}

.toast__message { flex: 1 1 auto; min-width: 0; }

.toast__action {
  flex: 0 0 auto;
  color: var(--accent-bright);
  font-weight: 700;
  text-decoration: underline;
  text-underline-offset: 0.16em;
  white-space: nowrap;
}

.toast__action:focus-visible,
.toast__close:focus-visible {
  outline: 2px solid var(--accent-bright);
  outline-offset: 2px;
}

.toast__close {
  flex: 0 0 auto;
  width: 1.8rem; height: 1.8rem;
  display: grid; place-items: center;
  padding: 0; border: 0; border-radius: 50%;
  background: transparent; color: var(--text-muted);
  font-size: 1.35rem; line-height: 1; cursor: pointer;
  transition: color 0.2s, background-color 0.2s;
}

.toast__close:hover { color: var(--text); background: var(--surface-2); }

.toast-enter-active {
  animation: toast-in 0.42s cubic-bezier(0.22, 1, 0.36, 1) both;
}

.toast-leave-active {
  animation: toast-out 0.22s ease-in both;
}

@keyframes toast-in {
  0% { opacity: 0; transform: translate3d(0, 1.2rem, 0) scale(0.96); filter: blur(4px); }
  65% { opacity: 1; transform: translate3d(0, -0.15rem, 0) scale(1.005); filter: blur(0); }
  100% { opacity: 1; transform: translate3d(0, 0, 0) scale(1); filter: blur(0); }
}

@keyframes toast-out {
  0% { opacity: 1; transform: translate3d(0, 0, 0); }
  100% { opacity: 0; transform: translate3d(0, 0.6rem, 0) scale(0.98); }
}

@media (max-width: 560px) {
  .toast {
    right: 1rem; bottom: 1rem;
    align-items: flex-start;
    max-width: calc(100vw - 2rem);
  }
  .toast__action { white-space: normal; }
}

@media (prefers-reduced-motion: reduce) {
  .toast-enter-active, .toast-leave-active { animation: none; transition: opacity 0.12s ease; }
}
.toast--success { border-color: var(--success); }
.toast--error { border-color: var(--danger); }
.toast--warn { border-color: var(--warn); }
.toast--info { border-color: var(--info); }
</style>
