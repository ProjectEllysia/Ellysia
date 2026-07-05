import { defineStore } from 'pinia'
import { ref } from 'vue'

/**
 * Clave en localStorage para persistir la iluminación elegida.
 * @type {string}
 */
const STORAGE_KEY = 'ellysia_theme'

/** Iluminaciones válidas del sistema Elysium. */
const THEMES = ['dusk', 'dawn']

/**
 * Aplica la iluminación guardada ANTES de montar la app para evitar el
 * destello del tema por defecto. Se llama desde main.js.
 */
export function applyStoredTheme() {
  const saved = localStorage.getItem(STORAGE_KEY)
  const theme = THEMES.includes(saved) ? saved : 'dusk'
  document.documentElement.setAttribute('data-theme', theme)
}

/**
 * Store del tema — gestiona la iluminación del sistema Elysium.
 *
 * Un solo diseño con dos iluminaciones:
 * - 'dusk' (Ocaso): noche índiga y oro. Por defecto.
 * - 'dawn' (Amanecer): mármol, cielo cristalino y oro viejo.
 *
 * El tema se aplica como atributo `data-theme` en <html> y las variables
 * CSS de shared.css hacen el resto.
 */
export const useThemeStore = defineStore('theme', () => {
  /** @type {import('vue').Ref<string>} Iluminación activa: 'dusk' | 'dawn' */
  const theme = ref(document.documentElement.getAttribute('data-theme') || 'dusk')

  /**
   * Cambia la iluminación y la persiste en localStorage.
   * @param {string} value - 'dusk' o 'dawn'
   */
  function setTheme(value) {
    if (!THEMES.includes(value)) return
    theme.value = value
    localStorage.setItem(STORAGE_KEY, value)
    document.documentElement.setAttribute('data-theme', value)
  }

  /** Alterna entre Ocaso y Amanecer. */
  function toggleTheme() {
    setTheme(theme.value === 'dusk' ? 'dawn' : 'dusk')
  }

  return { theme, setTheme, toggleTheme }
})
