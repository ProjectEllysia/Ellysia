import { ref, watch } from 'vue'

const STORAGE_PREFIX = 'ellysia:panel-collapsed:'

/**
 * Estado colapsado/expandido de un panel lateral, persistido en localStorage
 * por clave para que se recuerde entre sesiones (p.ej. un panel de perfil ya
 * configurado que el usuario prefiere mantener contraído).
 *
 * @param {string} key - Clave única del panel (ej. 'aegis-left').
 * @param {boolean} [defaultCollapsed=false] - Estado inicial si no hay nada guardado.
 * @returns {{collapsed: import('vue').Ref<boolean>, toggle: () => void}}
 */
export function usePanelCollapse(key, defaultCollapsed = false) {
  const storageKey = STORAGE_PREFIX + key
  const stored = localStorage.getItem(storageKey)
  const collapsed = ref(stored !== null ? stored === '1' : defaultCollapsed)

  watch(collapsed, (value) => {
    localStorage.setItem(storageKey, value ? '1' : '0')
  })

  function toggle() {
    collapsed.value = !collapsed.value
  }

  return { collapsed, toggle }
}
