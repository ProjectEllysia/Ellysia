/**
 * main.js — Punto de entrada de la aplicación.
 *
 * Inicializa la instancia de Vue con los plugins necesarios:
 * - Pinia: estado global reactivo (auth, toast, etc.)
 * - Vue Router: navegación SPA
 *
 * También importa el archivo CSS compartido del proyecto legacy
 * (shared.css) para reutilizar los tokens de diseño (colores, fuentes,
 * espaciados) definidos como custom properties en :root.
 */
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { useAuthStore } from '@/stores/authStore'
import { applyStoredTheme } from '@/stores/themeStore'
import { resolveError } from '@/views/errorCatalog'

import './assets/css/shared.css'

// Aplica la iluminación (dusk/dawn) antes de montar para evitar destellos.
applyStoredTheme()

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)

// Errores de render no atrapados (un fallo en cualquier componente) → vista
// de error 500 en vez de dejar la pantalla rota. La guarda evita el bucle si
// el fallo ocurre en la propia vista de error.
app.config.errorHandler = (error, _instance, info) => {
  console.error('[Ellysia] Error no controlado:', error, info)
  const name = router.currentRoute.value.name
  if (name !== 'Error' && name !== 'NotFound') {
    router.replace({ name: 'Error', params: { code: '500' } })
  }
}

// La sesión se restaura ANTES de instalar el router, y no en el `onMounted` de
// App.vue: `app.use(router)` lanza ya la primera navegación, así que su guard
// debe conocer el resultado de la comprobación del JWT y, si hace falta, de su
// renovación. Toda carga dura de una ruta protegida (F5, URL escrita a mano,
// enlace de un correo) espera a esta decisión antes de poder rebotar a /login.
async function bootstrap() {
  try {
    await useAuthStore().restoreSession()
    app.use(router)
    app.mount('#app')
  } catch (error) {
    // La app no pudo arrancar (p. ej. falla la restauración de la sesión): no
    // hay router que renderizar, así que se pinta un fallback mínimo con la
    // copia del catálogo de errores — shared.css ya está cargado, las
    // variables de diseño existen — en vez de una pantalla en blanco.
    console.error('[Ellysia] No se pudo arrancar la aplicación:', error)
    const entry = resolveError(500).entry
    document.getElementById('app').innerHTML = `
      <style>
        .fatal { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1rem; padding: 2rem; text-align: center; background: var(--bg); color: var(--text); font-family: var(--font-body); }
        .fatal-eyebrow { font-family: var(--font-epic); font-size-adjust: var(--fsa-epic); font-size: var(--fs-md); font-weight: 600; letter-spacing: 0.32em; text-transform: uppercase; color: var(--accent); }
        .fatal-title { font-family: var(--font-display); font-size-adjust: var(--fsa-display); font-size: clamp(2.2rem, 5vw, 3rem); font-weight: 600; margin: 0; line-height: 1.15; }
        .fatal-body { color: var(--text-dim); max-width: 540px; line-height: 1.75; margin: 0; }
        .fatal-reload { font-family: var(--font-body); font-size-adjust: var(--fsa-body); font-size: var(--fs-md); font-weight: 600; color: var(--text); background: var(--accent-dim); border: 1px solid var(--accent); border-radius: var(--radius-sm); padding: 0.55rem 1.2rem; cursor: pointer; }
      </style>
      <span class="fatal-eyebrow">Error 500</span>
      <h1 class="fatal-title">${entry.title}</h1>
      <p class="fatal-body">${entry.paragraphs.join(' ')}</p>
      <button class="fatal-reload" type="button" onclick="location.reload()">Volver a intentar</button>`
  }
}

bootstrap()
