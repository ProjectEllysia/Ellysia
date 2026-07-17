<template>
  <header class="site-header">
    <router-link to="/" class="brand" aria-label="Ellysia — inicio">
      <span class="brand-glyph" aria-hidden="true"></span>
      <span class="brand-text">Ellysia</span>
    </router-link>

    <nav class="site-nav" aria-label="Módulos">
      <router-link v-for="m in modules" :key="m.id" :to="m.route" class="nav-link">{{ m.name }}</router-link>
    </nav>

    <div class="header-actions">
      <button
        class="icon-btn"
        :title="theme.theme === 'dusk' ? 'Amanecer' : 'Ocaso'"
        :aria-label="theme.theme === 'dusk' ? 'Cambiar a Amanecer' : 'Cambiar a Ocaso'"
        @click="theme.toggleTheme()"
      >
        <svg v-if="theme.theme === 'dusk'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
          <circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="8" opacity="0.45" />
        </svg>
        <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
          <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
        </svg>
      </button>

      <router-link v-if="!auth.isAuthenticated" to="/login" class="enter-btn">Entrar</router-link>
      <router-link v-else to="/profile" class="avatar-btn" :aria-label="`Perfil de ${auth.username()}`">
        {{ initial }}
      </router-link>
    </div>
  </header>
</template>

<script setup>
import { computed } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import { useThemeStore } from '@/stores/themeStore'

const auth = useAuthStore()
const theme = useThemeStore()

const modules = [
  { id: 'themis', name: 'Themis', route: '/themis' },
  { id: 'aegis', name: 'Aegis', route: '/aegis' },
  { id: 'iris', name: 'Iris', route: '/iris' },
  { id: 'acheron', name: 'Acheron', route: '/acheron' },
]

const initial = computed(() => (auth.username()?.[0] || 'U').toUpperCase())
</script>

<style scoped>
.site-header {
  position: sticky;
  top: 0;
  z-index: 40;
  height: 72px;
  display: flex; align-items: center; justify-content: space-between;
  gap: 1.5rem;
  padding: 0 2rem;
  background: color-mix(in srgb, var(--bg) 80%, transparent);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
}

/* ── Marca ── */
.brand { display: inline-flex; align-items: center; gap: 0.65rem; flex-shrink: 0; }
.brand-glyph {
  width: 10px; height: 10px; border-radius: 50%;
  border: 1.5px solid var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim), 0 0 10px var(--accent-dim);
}
.brand-text {
  font-family: var(--font-epic);
  font-size: var(--fs-xl); font-weight: 600;
  letter-spacing: 0.32em; text-transform: uppercase;
  color: var(--text);
}

/* ── Navegación de módulos ── */
.site-nav { display: flex; gap: 1.5rem; margin-left: auto; }
.nav-link {
  font-family: var(--font-epic);
  font-size: var(--fs-md); font-weight: 500;
  letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--text-dim);
  padding: 0.3rem 0;
  border-bottom: 1px solid transparent;
  transition: color var(--transition), border-color var(--transition);
}
.nav-link:hover { color: var(--text); border-color: var(--accent); }
.nav-link.router-link-exact-active { color: var(--accent); border-color: var(--accent); }

/* ── Acciones ── */
.header-actions { display: flex; align-items: center; gap: 0.8rem; flex-shrink: 0; }
.icon-btn {
  width: 40px; height: 40px; border-radius: 50%;
  display: grid; place-items: center;
  color: var(--accent);
  border: 1px solid var(--border-med);
  transition: all var(--transition);
}
.icon-btn:hover { border-color: var(--accent); box-shadow: 0 0 12px var(--accent-dim); }
.icon-btn svg { width: 18px; height: 18px; }
.enter-btn {
  font-family: var(--font-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--accent-bright);
  padding: 0.5rem 1.3rem;
  border: 1px solid var(--accent);
  border-radius: 3px;
  background: var(--accent-dim);
  transition: all var(--transition);
}
.enter-btn:hover { background: var(--accent); color: var(--on-accent); }
.avatar-btn {
  width: 40px; height: 40px; border-radius: 50%;
  display: grid; place-items: center;
  background: var(--accent-dim);
  border: 1.5px solid var(--border-med);
  color: var(--accent-bright);
  font-size: var(--fs-md); font-weight: 700;
  transition: all var(--transition);
}
.avatar-btn:hover { border-color: var(--accent); box-shadow: 0 0 12px var(--accent-dim); }

.icon-btn:focus-visible, .enter-btn:focus-visible,
.avatar-btn:focus-visible, .nav-link:focus-visible, .brand:focus-visible {
  outline: 2px solid var(--accent-bright);
  outline-offset: 3px;
}

@media (max-width: 720px) {
  .site-nav { display: none; }
  .site-header { padding: 0 1.2rem; }
  .brand-text { letter-spacing: 0.22em; }
}
</style>
