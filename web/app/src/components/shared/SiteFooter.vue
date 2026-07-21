<template>
  <footer class="site-footer">
    <div class="footer-top">
      <div class="footer-brand">
        <img class="footer-mark" :src="ellysiaIcon" alt="" aria-hidden="true" />
        <span class="footer-wordmark">Ellysia</span>
      </div>

      <nav class="footer-cols" aria-label="Enlaces del pie">
        <div class="footer-col">
          <h3 class="footer-heading">Herramientas</h3>
          <ul>
            <li><router-link to="/themis">Themis</router-link></li>
            <li><router-link to="/aegis">Aegis</router-link></li>
            <li><router-link to="/iris">Iris</router-link></li>
            <li><router-link to="/acheron">Acheron</router-link></li>
          </ul>
        </div>
        <div class="footer-col">
          <h3 class="footer-heading">Ellysia</h3>
          <ul>
            <li><router-link to="/sobre">Sobre nosotros</router-link></li>
            <li>
              <a href="https://github.com/ProjectEllysia/Ellysia" target="_blank" rel="noopener noreferrer">Código ↗</a>
            </li>
          </ul>
        </div>
        <div class="footer-col">
          <h3 class="footer-heading">Documentación</h3>
          <ul>
            <li><router-link to="/docs/uso">Documentación de uso</router-link></li>
            <li><router-link to="/docs/tecnica">Documentación técnica</router-link></li>
          </ul>
        </div>
        <div class="footer-col">
          <h3 class="footer-heading">Legal</h3>
          <ul>
            <li><router-link to="/privacidad">Privacidad</router-link></li>
            <li><router-link to="/terminos">Términos</router-link></li>
          </ul>
        </div>
      </nav>
    </div>

    <div class="footer-bottom">
      <span>© {{ year }} Ellysia · ellysia.es</span>
      <span class="footer-version">v{{ appVersion }}</span>
    </div>
  </footer>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import ellysiaIcon from '@/assets/images/ellysia/Ellysia-BgN.png'

const year = new Date().getFullYear()
const appVersion = ref('—')

onMounted(() => {
  // Endpoint público (no requiere sesión); silencioso si falla.
  fetch('/system/say-hello')
    .then((r) => r.json())
    .then((d) => { if (d.version) appVersion.value = d.version })
    .catch(() => {})
})
</script>

<style scoped>
.site-footer {
  position: relative;
  z-index: 1;
  border-top: 1px solid var(--border);
  background: var(--surface);
  padding: 3.5rem 2rem 2rem;
}
.footer-top {
  max-width: 1100px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 2.2rem;
}

/* ── Marca — fila propia encima de las columnas ── */
.footer-brand { display: flex; align-items: center; gap: 0.7rem; }
.footer-mark {
  width: 30px; height: 30px; object-fit: contain;
  filter: drop-shadow(0 0 7px var(--accent-dim));
  /* Alineación óptica con las mayúsculas del wordmark (ver LandingView). */
  transform: translateY(-2px);
}
.footer-wordmark {
  font-family: var(--font-epic);
  font-size: var(--fs-xl); font-weight: 600;
  letter-spacing: 0.3em; text-transform: uppercase;
  color: var(--text);
}

/* ── Columnas ──
   flex:1 + space-between reparte las columnas de enlaces por todo el ancho
   restante, sin dejar hueco muerto a la derecha (antes iban agrupadas). */
.footer-cols { flex: 1; display: flex; justify-content: space-between; gap: 2.5rem; flex-wrap: wrap; }
.footer-heading {
  font-family: var(--font-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 0.9rem;
}
.footer-col ul { list-style: none; display: flex; flex-direction: column; gap: 0.55rem; }
.footer-col a {
  font-size: var(--fs-xl);
  color: var(--text-dim);
  transition: color var(--transition);
}
.footer-col a:hover { color: var(--accent-bright); }
.footer-col a:focus-visible {
  outline: 2px solid var(--accent-bright);
  outline-offset: 2px;
}

/* ── Barra inferior ── */
.footer-bottom {
  max-width: 1100px;
  margin: 2.6rem auto 0;
  padding-top: 1.4rem;
  border-top: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: 0.5rem;
  font-family: var(--font-mono);
  font-size: var(--fs-md);
  color: var(--text-muted);
  letter-spacing: 0.04em;
}

@media (max-width: 640px) {
  .footer-top { gap: 2rem; }
  .footer-cols { gap: 2.2rem; }
}
</style>
