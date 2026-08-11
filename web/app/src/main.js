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

import './assets/css/shared.css'

// Aplica la iluminación (dusk/dawn) antes de montar para evitar destellos.
applyStoredTheme()

const app = createApp(App)
app.use(createPinia())

// La sesión se restaura ANTES de instalar el router, y no en el `onMounted` de
// App.vue: `app.use(router)` lanza ya la primera navegación, así que su guard
// leía `isAuthenticated` cuando todavía valía false. Toda carga dura de una
// ruta protegida (F5, URL escrita a mano, enlace de un correo) rebotaba a
// /login y además borraba la sesión de camino.
useAuthStore().loadFromStorage()

app.use(router)
app.mount('#app')
