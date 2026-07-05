import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'

/**
 * Configuración de rutas de la SPA.
 *
 * Cada ruta corresponde a una vista (página) que se carga bajo demanda
 * mediante lazy loading (`() => import(...)`). El guard de navegación
 * (`beforeEach`) protege las rutas que requieren autenticación y redirige
 * al dashboard si el usuario ya está logueado e intenta ir al login.
 *
 * @type {import('vue-router').RouteRecordRaw[]}
 */
const routes = [
  {
    path: '/',
    name: 'Landing',
    component: () => import('@/views/LandingView.vue'),
    // Pública: es la portada de ellysia.es. Si hay sesión, muestra los
    // accesos directos a las herramientas; si no, invita a entrar.
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/LoginView.vue'),
    meta: { guest: true },
  },
  {
    path: '/sentinel',
    name: 'Sentinel',
    component: () => import('@/views/SentinelView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/aegis',
    name: 'Aegis',
    component: () => import('@/views/AegisView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/iris',
    name: 'Iris',
    component: () => import('@/views/IrisView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/acheron',
    name: 'Acheron',
    component: () => import('@/views/AcheronView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/config',
    name: 'Config',
    component: () => import('@/views/ConfigView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/profile',
    name: 'Profile',
    component: () => import('@/views/ProfileView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/users',
    name: 'Users',
    component: () => import('@/views/UsersView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/queue',
    name: 'Queue',
    component: () => import('@/views/QueueView.vue'),
    meta: { requiresAuth: true },
  },
]

/**
 * Instancia del router con historial HTML5 (sin # en las URLs).
 * Usa createWebHistory para rutas limpias: /, /sentinel, etc.
 */
const router = createRouter({
  history: createWebHistory(),
  routes,
})

/**
 * Guard de navegación global.
 *
 * - Si la ruta requiere auth y no hay sesión → redirige a /login.
 * - Si la ruta es de invitado (login) y ya hay sesión → redirige a la landing.
 * - En cualquier otro caso, deja pasar la navegación.
 */
router.beforeEach((to) => {
  const auth = useAuthStore()
  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    return '/login'
  } else if (to.meta.guest && auth.isAuthenticated) {
    return '/'
  }
})

export default router
