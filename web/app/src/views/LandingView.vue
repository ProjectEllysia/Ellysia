<template>
  <div class="ely-stage">
    <!-- ═══════════ HERO — la vista elísea ═══════════ -->
    <section class="vista">
      <ElysianScene />

      <!-- Cabecera -->
      <header class="ely-header">
        <a class="wordmark" href="/" @click.prevent="scrollTop">
          <img class="wordmark-mark" :src="ellysiaIcon" alt="" aria-hidden="true" />
          <span class="wordmark-text">Ellysia</span>
        </a>
        <nav class="ely-nav" aria-label="Navegación principal">
          <div class="nav-dd" :class="{ open: toolsOpen }" @keyup.esc="toolsOpen = false">
            <button class="nav-link nav-trigger" @click="toggleDropdown('tools')"
                    :aria-expanded="toolsOpen" aria-haspopup="menu">
              Herramientas
              <svg class="nav-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
            </button>
            <Transition name="drop">
              <div v-if="toolsOpen" class="nav-panel nav-panel--tools" role="menu">
                <router-link v-for="t in tools" :key="t.id" :to="t.route" class="nav-panel-item nav-panel-item--tool" role="menuitem" @click="toolsOpen = false">
                  <img :src="t.icon" :alt="t.name" class="nav-panel-icon" />
                  <span class="nav-panel-text">
                    <span class="nav-panel-name">{{ t.name }}</span>
                    <span class="nav-panel-blurb">{{ t.blurb }}</span>
                  </span>
                </router-link>
              </div>
            </Transition>
          </div>

          <div class="nav-dd" :class="{ open: docsOpen }" @keyup.esc="docsOpen = false">
            <button class="nav-link nav-trigger" @click="toggleDropdown('docs')"
                    :aria-expanded="docsOpen" aria-haspopup="menu">
              Documentación
              <svg class="nav-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
            </button>
            <Transition name="drop">
              <div v-if="docsOpen" class="nav-panel" role="menu">
                <router-link v-for="d in docsLinks" :key="d.to" :to="d.to" class="nav-panel-item" role="menuitem" @click="docsOpen = false">
                  {{ d.label }}
                </router-link>
              </div>
            </Transition>
          </div>

          <router-link to="/planes" class="nav-link nav-link--plain">Planes</router-link>
        </nav>

        <div class="header-actions">
          <!-- Botón del menú móvil: por debajo de 960px la navegación de arriba
               desaparece, y hasta ahora no la sustituía nada — desde un móvil no
               había forma de llegar a las herramientas. -->
          <button
            class="menu-toggle"
            :aria-expanded="mobileOpen"
            aria-controls="menu-movil"
            :aria-label="mobileOpen ? 'Cerrar el menú' : 'Abrir el menú'"
            @click="mobileOpen = !mobileOpen"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
              <path v-if="mobileOpen" d="M6 6l12 12M18 6L6 18" />
              <g v-else><path d="M4 7h16" /><path d="M4 12h16" /><path d="M4 17h16" /></g>
            </svg>
          </button>

          <button
            class="theme-toggle"
            @click="themeStore.toggleTheme()"
            :aria-label="themeStore.theme === 'dusk' ? 'Cambiar a Amanecer' : 'Cambiar a Ocaso'"
            :title="themeStore.theme === 'dusk' ? 'Amanecer' : 'Ocaso'"
          >
            <!-- Ocaso activo → ofrece el sol -->
            <svg v-if="themeStore.theme === 'dusk'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
              <circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="8" opacity="0.45" />
            </svg>
            <!-- Amanecer activo → ofrece la noche -->
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
              <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
            </svg>
          </button>

          <router-link v-if="!auth.isAuthenticated" to="/login" class="enter-btn">Entrar</router-link>
          <AccountMenu v-else />
        </div>

        <!-- Menú móvil. Lista plana a propósito: en una pantalla estrecha,
             desplegables anidados dentro de un desplegable son una trampa. -->
        <Transition name="drop">
          <nav v-if="mobileOpen" id="menu-movil" class="mobile-menu" aria-label="Navegación principal">
            <span class="mobile-heading">Herramientas</span>
            <router-link
              v-for="t in tools" :key="t.id" :to="t.route"
              class="mobile-item mobile-item--tool" @click="mobileOpen = false"
            >
              <!-- Decorativo: el nombre de la herramienta va justo al lado. -->
              <img :src="t.icon" alt="" aria-hidden="true" class="mobile-icon" />
              <span class="mobile-text">
                <span class="mobile-name">{{ t.name }}</span>
                <span class="mobile-blurb">{{ t.blurb }}</span>
              </span>
            </router-link>

            <span class="mobile-heading">Documentación</span>
            <router-link
              v-for="d in docsLinks" :key="d.to" :to="d.to"
              class="mobile-item" @click="mobileOpen = false"
            >{{ d.label }}</router-link>

            <router-link to="/planes" class="mobile-item" @click="mobileOpen = false">Planes</router-link>

            <router-link
              v-if="!auth.isAuthenticated" to="/login?registro"
              class="mobile-cta" @click="mobileOpen = false"
            >Crear cuenta gratis</router-link>
          </nav>
        </Transition>
      </header>

      <!-- Contenido del héroe -->
      <div class="hero-copy">
        <span class="eyebrow">Security Operations Suite</span>
        <h1 class="hero-title">Ellysia</h1>
        <p class="verse">Vigila. Conciencia. Verifica. Guarda.</p>
        <p class="lede">Herramientas de seguridad bajo un mismo cielo.</p>
        <div class="hero-actions">
          <router-link v-if="!auth.isAuthenticated" to="/login" class="cta cta--solid">Entrar</router-link>
          <button class="cta cta--line" @click="scrollToSection('tools')">Conocer las herramientas</button>
        </div>
      </div>

      <button class="scroll-cue" @click="scrollToSection('tools')" aria-label="Bajar a las herramientas">
        <span></span>
      </button>
    </section>

    <!-- ═══════════ FRISO — banda dorada entre el hero y las estelas ═══════════ -->
    <div class="greek-banner" aria-hidden="true">
      <div class="banner-rule"></div>
      <div class="banner-emblem">
        <span class="emblem-ring emblem-ring--inner"></span>
        <span class="emblem-ring emblem-ring--outer"></span>
      </div>
      <div class="banner-rule"></div>
    </div>

    <!-- ═══════════ FILOSOFÍA — la inscripción ═══════════ -->
    <section id="filosofia" class="philosophy">
      <div class="philosophy-inner">
        <img class="philo-figure" :src="socratesIcon" alt="" aria-hidden="true" />

        <div class="philosophy-copy">
          <span class="philo-eyebrow">Razón de ser</span>
          <h2 class="philo-title">La filosofía detrás de Ellysia</h2>

          <!-- Pauta vertical: el margen de una inscripción, no un adorno -->
          <div class="philo-text" ref="philosophyTextRef">
            <p class="philo-para">
              La seguridad en la red dejó de ser asunto de unos pocos. Hoy basta con
              abrir un correo, guardar una contraseña o encender un servidor para
              quedar expuesto. Lo que cambió no fue la amenaza: fue quién la recibe.
            </p>
            <p class="philo-para">
              Defenderse, en cambio, sigue siendo caro. Media docena de productos,
              cada uno con su licencia y su consola, al alcance de quien puede pagar
              un equipo que los maneje. Ellysia reúne esas piezas
              <em class="philo-gold">bajo un mismo cielo</em> — detectar, formar,
              verificar, guardar, vigilar — para quien no tiene un departamento de
              seguridad detrás.
            </p>
            <p class="philo-para philo-para--close">
              No prometemos invulnerabilidad; nadie honesto lo hace. Prometemos que
              <em class="philo-gold">defenderse deje de ser un privilegio</em>.
            </p>
          </div>
        </div>
      </div>
    </section>

    <!-- ═══════════ HERRAMIENTAS — estelas ═══════════ -->
    <section id="tools" class="stelae">
      <!-- Cabecera de sección -->
      <div class="stelae-intro">
        <h2 class="stelae-title">Las cinco herramientas</h2>
        <p class="stelae-bajada">Cada una guarda un aspecto de tu seguridad.</p>
        <div class="horizon-divider"></div>
      </div>

      <template v-for="(t, index) in tools" :key="t.id">
        <article
          :id="t.id"
          class="stele"
          :data-module="t.id"
          :data-numeral="t.numeral"
          ref="steleRefs"
        >
          <div class="stele-medallion">
            <span class="medallion-ring" aria-hidden="true"></span>
            <img :src="t.icon" :alt="t.name" />
          </div>
          <div class="stele-body">
            <span class="stele-kicker">{{ t.numeral }} · {{ t.name }}</span>
            <p class="stele-myth">{{ t.myth }}</p>
            <span class="stele-epigraph">{{ t.epigraph }}</span>
            <h2 class="stele-title">{{ t.title }}</h2>
            <p class="stele-desc">{{ t.desc }}</p>
            <ul class="stele-chips">
              <li v-for="c in t.chips" :key="c">{{ c }}</li>
            </ul>
            <router-link :to="t.route" class="stele-cta">
              Explorar {{ t.name }}
              <span aria-hidden="true">→</span>
            </router-link>
          </div>
        </article>

        <!-- Divisor «horizonte» entre estelas -->
        <div
          v-if="index < tools.length - 1"
          class="horizon-divider stele-divider"
          aria-hidden="true"
        ></div>
      </template>
    </section>

    <!-- ═══════════ LA SENDA — cómo se empieza ═══════════ -->
    <!-- Aquí el orden SÍ es información: son tres pasos que van uno detrás de
         otro. Por eso llevan una línea que los une, y no los numerales romanos
         de las estelas: allí I-V identifican herramientas, y reusarlos para
         pasos sería el mismo signo diciendo dos cosas distintas. -->
    <section id="empezar" class="path-section">
      <div class="path-intro">
        <span class="path-eyebrow">Cómo se empieza</span>
        <h2 class="path-title">Tres pasos hasta el primer veredicto</h2>
      </div>

      <ol class="path">
        <li v-for="step in steps" :key="step.title" class="path-step">
          <span class="path-mark" aria-hidden="true">
            <span class="path-ring"></span>
          </span>
          <h3 class="path-step-title">{{ step.title }}</h3>
          <p class="path-step-desc">{{ step.desc }}</p>
        </li>
      </ol>
    </section>

    <!-- ═══════════ PLANES ═══════════ -->
    <section id="planes" class="plans-section">
      <div class="plans-intro">
        <span class="path-eyebrow">Planes</span>
        <h2 class="path-title">Empieza gratis; crece si te hace falta</h2>
        <p class="plans-bajada">Sin tarjeta para empezar. El plan gratuito no caduca.</p>
        <div class="horizon-divider"></div>
      </div>

      <!-- Si el catálogo no llega (API caída), la sección entera se calla en vez
           de enseñar una rejilla vacía: en una portada, un hueco con "no hay
           planes" es peor que no tener sección. -->
      <div v-if="account.catalog.length" class="plans-grid">
        <article
          v-for="plan in account.catalog" :key="plan.code"
          class="plan-card" :class="{ 'plan-card--default': plan.isDefault }"
        >
          <span v-if="plan.isDefault" class="plan-tag">Para empezar</span>
          <h3 class="plan-name">{{ plan.name }}</h3>
          <p class="plan-tagline">{{ plan.tagline }}</p>
          <p class="plan-price">
            <span class="plan-amount">{{ euros(plan.monthlyPriceCents) }}</span>
            <span class="plan-period">/mes</span>
          </p>
          <ul class="plan-limits">
            <li v-for="item in headlineLimits(plan)" :key="item.label">
              <span class="plan-limit-label">{{ item.label }}</span>
              <span class="plan-limit-value">{{ item.value }}</span>
            </li>
          </ul>
          <!-- Solo el plan gratuito se contrata solo: no hay pasarela de pago,
               así que el resto lleva a la tabla completa, donde ya se explica
               cómo se asigna. Prometer un "Contratar" que no existe sería
               mentir en el sitio donde más caro sale. -->
          <router-link v-if="plan.isDefault" to="/login?registro" class="plan-cta plan-cta--solid">
            Empezar gratis
          </router-link>
          <router-link v-else to="/planes" class="plan-cta">Ver detalles</router-link>
        </article>
      </div>

      <p v-if="account.catalog.length" class="plans-foot">
        <router-link to="/planes">Comparar todos los límites de cada plan →</router-link>
      </p>
    </section>

    <!-- ═══════════ PREGUNTAS ═══════════ -->
    <!-- <details>/<summary> nativos: accesibles por teclado y sin una línea de
         JS que mantener. -->
    <section id="preguntas" class="faq-section">
      <div class="plans-intro">
        <span class="path-eyebrow">Antes de que preguntes</span>
        <h2 class="path-title">Lo que suele costar decidir</h2>
      </div>

      <div class="faq-list">
        <details v-for="item in faqs" :key="item.q" class="faq-item" v-animate-details>
          <summary class="faq-q">
            {{ item.q }}
            <svg class="faq-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>
          </summary>
          <p class="faq-a">{{ item.a }}</p>
        </details>
      </div>
    </section>

    <!-- ═══════════ CIERRE ═══════════ -->
    <!-- La página terminaba en la placa de versión y un enlace a GitHub: un
         final de proyecto, no de producto. Aquí se pide algo, por fin.
         La pauta dorada hace de costura con la cinta de tecnologías, en vez
         de un borde recto — es el mismo recurso que ya separa las estelas. -->
    <div class="horizon-divider closing-seam" aria-hidden="true"></div>
    <section class="closing">
      <h2 class="closing-title">Defenderse no debería ser un privilegio</h2>
      <p class="closing-lede">
        Crea tu cuenta y lanza tu primer análisis hoy. Gratis, sin tarjeta.
      </p>
      <div class="closing-actions">
        <router-link v-if="!auth.isAuthenticated" to="/login?registro" class="cta cta--solid">
          Crear cuenta gratis
        </router-link>
        <router-link v-else to="/themis" class="cta cta--solid">Ir a mis herramientas</router-link>
        <router-link to="/planes" class="cta cta--line">Ver los planes</router-link>
      </div>
    </section>

    <!-- ═══════════ TECNOLOGÍAS — cinta en marcha ═══════════ -->
    <section class="forge" aria-label="Tecnologías con las que está construida Ellysia">
      <span class="forge-eyebrow">Construida con</span>
      <div class="forge-viewport">
        <!-- Dos copias de la lista: cuando la primera termina de entrar, la
             segunda ocupa su sitio exacto y el bucle no tiene costura. -->
        <div class="forge-track" aria-hidden="true">
          <span v-for="(tech, index) in techMarquee" :key="index" class="forge-item">{{ tech }}</span>
        </div>
      </div>
      <!-- Lista real para lectores de pantalla (la cinta visual está oculta) -->
      <ul class="sr-only">
        <li v-for="tech in technologies" :key="tech">{{ tech }}</li>
      </ul>
    </section>

    <!-- ═══════════ PLACA ═══════════ -->
    <section class="plaque">
      <span class="plaque-item"><i class="plaque-dot"></i>Operativo — {{ tools.length }} herramientas</span>
      <span class="plaque-sep" aria-hidden="true">·</span>
      <span class="plaque-item">v{{ appVersion }}</span>
      <span class="plaque-sep" aria-hidden="true">·</span>
      <a class="plaque-item plaque-link" href="https://github.com/ProjectEllysia/Ellysia" target="_blank" rel="noopener noreferrer">
        ProjectEllysia / Ellysia ↗
      </a>
    </section>

    <!-- ═══════════ PIE ═══════════ -->
    <SiteFooter />
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { useAuthStore } from '@/stores/authStore'
import { useProfileStore } from '@/stores/profileStore'
import { useThemeStore } from '@/stores/themeStore'
import { useAccountStore } from '@/stores/accountStore'
import { useDismissable } from '@/composables/useDismissable'
import { useAppVersion } from '@/composables/useAppVersion'
import { vAnimateDetails } from '@/composables/useAnimatedDetails'
import { HEADLINE, SHORT_LABELS, euros, describe } from '@/constants/planFormat'
import ElysianScene from '@/components/shared/ElysianScene.vue'
import SiteFooter from '@/components/shared/SiteFooter.vue'
import AccountMenu from '@/components/shared/AccountMenu.vue'

import ellysiaIcon from '@/assets/images/ellysia/Ellysia-BgN.png'
import themisIcon from '@/assets/images/themis/Themis-Turqoise-BgN.png'
import aegisIcon from '@/assets/images/aegis/Ellysia-Aegis-Blue-BgN.png'
import irisIcon from '@/assets/images/iris/Iris-Red-BgN.png'
import acheronIcon from '@/assets/images/acheron/Acheron-Purple-BgN.png'
import hygeiaIcon from '@/assets/images/hygeia/Hygeia-DarkGreen-BgN.png'
import socratesIcon from '@/assets/images/socrastes/Socrates-BgN.png'

const auth = useAuthStore()
const profileStore = useProfileStore()
const themeStore = useThemeStore()

const account = useAccountStore()

const toolsOpen = ref(false)
const docsOpen = ref(false)
const mobileOpen = ref(false)
const steleRefs = ref([])
const philosophyTextRef = ref(null)

// Compartida con el pie, que también la enseña: antes cada uno pedía la suya y
// la misma página gastaba dos peticiones para pintar el mismo número.
const { version: appVersion } = useAppVersion()

/* Cerrar al pulsar fuera y con Escape, con el composable de la Fase 5 en vez
   del listener a mano que había en onMounted. El menú móvil se cierra también
   al pulsar su propio botón, así que el selector cubre los dos. */
useDismissable('.nav-dd', () => { toolsOpen.value = false; docsOpen.value = false })
useDismissable('.mobile-menu, .menu-toggle', () => { mobileOpen.value = false })

/** Tecnologías con las que está construida la plataforma, en la cinta del pie. */
const technologies = [
  'Python', 'Flask', 'Flask-Smorest', 'SQLAlchemy', 'Alembic', 'PostgreSQL',
  'Redis', 'RQ', 'Marshmallow', 'Argon2id', 'PyJWT', 'Pytest',
  'Vue 3', 'Vite', 'Pinia', 'Vue Router', 'Docker', 'Ollama', 'OpenAI',
  'Nmap', 'Nikto', 'Nuclei', 'Kotlin', 'Android',
]
/* La cinta lleva la lista dos veces: cuando la primera copia termina de
   entrar, la segunda ocupa su sitio exacto y el bucle no tiene costura. */
const techMarquee = [...technologies, ...technologies]

/**
 * Los tres pasos hasta el primer resultado. Descritos por lo que el producto
 * hace de verdad: la cuenta nace en el plan gratuito sin pedir tarjeta, y el
 * primer objetivo es o un dominio en Themis o un agente de Hygeia.
 */
const steps = [
  {
    title: 'Crea tu cuenta',
    desc: 'Gratis y sin tarjeta. El plan de entrada no caduca ni pide datos de pago.',
  },
  {
    title: 'Apunta tu primer objetivo',
    desc: 'Un dominio en Themis, o el agente de Hygeia en el servidor que quieras vigilar.',
  },
  {
    title: 'Recibe el veredicto',
    desc: 'El motor pesa cada indicio y redacta el informe, listo para leer o entregar.',
  },
]

/**
 * Las objeciones que de verdad frenan una decisión, respondidas sin adornos.
 *
 * La de Acheron dice que no hay recuperación porque no la hay: el servidor es
 * zero-knowledge (`src/acheron/crypto.js`), la clave se deriva en el navegador
 * y lo que se guarda es la bóveda ya cifrada. Suavizarlo aquí sería vender una
 * red de seguridad inexistente a quien va a guardar sus credenciales.
 */
const faqs = [
  {
    q: '¿Mis contraseñas salen de mi navegador?',
    a: 'No. Acheron cifra en tu navegador antes de enviar nada: el servidor solo '
     + 've texto cifrado y nunca recibe tu contraseña maestra ni la clave que se '
     + 'deriva de ella.',
  },
  {
    q: '¿Qué pasa si pierdo mi contraseña maestra de Acheron?',
    a: 'Se pierde el contenido de la bóveda, y no hay forma de recuperarlo. Es la '
     + 'consecuencia directa de que la clave no viaje: si nosotros pudiéramos '
     + 'devolvértela, también podríamos leer tus secretos. Guárdala donde guardarías '
     + 'la llave de tu casa.',
  },
  {
    q: '¿Necesito ser técnico para usarlo?',
    a: 'Para lanzar un análisis y leer el informe, no: eliges un objetivo y recibes '
     + 'el resultado redactado. Instalar el agente de Hygeia en un servidor sí pide '
     + 'acceso a esa máquina.',
  },
  {
    q: '¿Qué necesita el agente de Hygeia?',
    a: 'Un servicio ligero en la máquina que quieras vigilar. Es él quien envía los '
     + 'datos hacia fuera cada pocos segundos, así que no hace falta abrir ningún '
     + 'puerto entrante.',
  },
  {
    q: '¿Cuánto cuesta empezar?',
    a: 'Nada. El plan de entrada es gratuito, no pide tarjeta y no caduca. Si te '
     + 'quedas corto de cupo, los planes de pago están más arriba.',
  },
]

/** Los tres límites que mejor resumen un plan en la portada. */
function headlineLimits(plan) {
  return HEADLINE.map(key => ({ label: SHORT_LABELS[key], value: describe(plan, key) }))
}

/** Enlaces del desplegable "Documentación" — de momento apuntan a páginas placeholder. */
const docsLinks = [
  { label: 'Documentación de uso', to: '/docs/uso' },
  { label: 'Documentación técnica', to: '/docs/tecnica' },
]

/** Abre uno de los desplegables del nav y cierra el otro (mutuamente excluyentes). */
function toggleDropdown(which) {
  if (which === 'tools') {
    toolsOpen.value = !toolsOpen.value
    docsOpen.value = false
  } else {
    docsOpen.value = !docsOpen.value
    toolsOpen.value = false
  }
}

const reduceMotion =
  typeof window !== 'undefined' &&
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

/** Las cinco herramientas, con su epígrafe mitológico y su función real. */
const tools = [
  {
    id: 'themis',
    numeral: 'I',
    epigraph: 'IUDICIUM',
    name: 'Themis',
    icon: themisIcon,
    route: '/themis',
    blurb: 'Detección de vulnerabilidades',
    myth: 'La que sostiene la balanza y no dicta sentencia sin pesar antes cada indicio.',
    title: 'Pesa cada amenaza antes de que golpee',
    desc: 'Motor de detección propio (Lybra) con Nmap, Nikto y Nuclei como corroboradores opcionales, e informes redactados por IA listos para entregar.',
    chips: ['Lybra', 'Nmap', 'Nikto', 'Nuclei', 'Informes IA'],
  },
  {
    id: 'aegis',
    numeral: 'II',
    epigraph: 'PRAESIDIO',
    name: 'Aegis',
    icon: aegisIcon,
    route: '/aegis',
    blurb: 'Concienciación con IA',
    myth: 'El escudo de Zeus y Atenea, forjado para proteger antes del golpe.',
    title: 'Concienciación que llega antes que el ataque',
    desc: 'Boletines de inteligencia de seguridad generados por IA para formar a tu organización.',
    chips: ['Newsletter IA', 'Markdown', 'JSON'],
  },
  {
    id: 'iris',
    numeral: 'III',
    epigraph: 'VERITAS',
    name: 'Iris',
    icon: irisIcon,
    route: '/iris',
    blurb: 'Análisis anti-phishing',
    myth: 'La mensajera de los dioses; ningún mensaje falso cruza su arco.',
    title: 'Verifica quién firma cada correo',
    desc: 'Análisis de cabeceras de correo para detectar phishing mediante reglas de verificación.',
    chips: ['SPF', 'DKIM', 'DMARC', 'Anti-phishing'],
  },
  {
    id: 'acheron',
    numeral: 'IV',
    epigraph: 'CUSTODIA',
    name: 'Acheron',
    icon: acheronIcon,
    route: '/acheron',
    blurb: 'Bóveda cifrada',
    myth: 'El río que nadie cruza sin la llave.',
    title: 'Guarda lo que no debe perderse',
    desc: 'Bóveda cifrada de credenciales y tarjetas para tu organización. El cifrado ocurre en tu navegador: la llave nunca viaja.',
    chips: ['Cifrado en navegador', 'Credenciales', 'Tarjetas'],
  },
  {
    id: 'hygeia',
    numeral: 'V',
    epigraph: 'SALUS',
    name: 'Hygeia',
    icon: hygeiaIcon,
    route: '/hygeia',
    blurb: 'Monitorización de activos',
    myth: 'La diosa de la salud; vigila los signos vitales de cada activo.',
    title: 'Vigila el pulso de cada activo',
    desc: 'Agentes ligeros empujan telemetría de hardware; los umbrales con histéresis abren y resuelven anomalías solos, con aviso por correo en lo crítico.',
    chips: ['Push', 'Umbrales', 'Host caído', 'Alertas'],
  },
]

function scrollTop() {
  window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' })
}

function scrollToSection(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth' })
}

/* ── Revelado de estelas al hacer scroll ── */
let observer = null

onMounted(() => {
  if (auth.isAuthenticated) profileStore.loadProfile()

  // Catálogo público de planes: no necesita sesión (GET /plans es la tabla de
  // precios de la web). La store lo cachea, así que ir y volver no lo re-pide.
  account.loadCatalog()

  observer = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) {
          e.target.classList.add('revealed')
          observer.unobserve(e.target)
        }
      }
    },
    { threshold: 0.2 }
  )
  for (const el of steleRefs.value) observer.observe(el)
  // Los párrafos de la filosofía se revelan uno a uno, con el mismo observador.
  for (const el of Array.from(philosophyTextRef.value?.children ?? [])) observer.observe(el)

})

onUnmounted(() => {
  observer?.disconnect()
})
</script>

<style scoped>
.ely-stage {
  position: relative;
  background: var(--bg);
  transition: background-color 0.4s ease;
}

/* ═══════════ HERO — la vista ═══════════ */
.vista {
  position: relative;
  height: 100vh;
  min-height: 640px;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
}

/* ═══════════ Cabecera ═══════════ */
.ely-header {
  position: absolute;
  top: 0; left: 0; right: 0;
  z-index: 20;
  /* Grid en vez de flex + space-between: con 3 hijos de anchos distintos
     (wordmark vs. header-actions), space-between deja el elemento central
     descentrado respecto a la página — su posición depende de cuánto pesen
     los otros dos, no del centro real. Con columnas 1fr/auto/1fr, la columna
     central queda centrada de verdad sin importar lo que pese cada lado. */
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  align-items: center;
  padding: 1.4rem 2.6rem;
}
.wordmark {
  display: inline-flex; align-items: center; gap: 0.7rem;
  justify-self: start;
}
.wordmark-mark {
  width: 34px; height: 34px;
  object-fit: contain;
  /* La corona de laurel es el emblema de Elysium — hereda el halo del sol
     del hero (--sun-glow) en vez de un borde plano. */
  filter: drop-shadow(0 0 9px var(--sun-glow));
  /* Óptica: la palabra va en mayúsculas y "se sienta" en la parte alta de su
     caja de línea (el hueco de los descendentes queda abajo); la corona, en
     cambio, se centra en la caja entera y parece caída. La subimos 2px para
     alinearla con la altura de las mayúsculas. */
  transform: translateY(-2px);
  transition: filter var(--transition), transform var(--transition);
}
.wordmark:hover .wordmark-mark { filter: drop-shadow(0 0 14px var(--sun-glow)); transform: translateY(-3px); }
.wordmark-text {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-xl); font-weight: 600;
  letter-spacing: 0.38em; text-transform: uppercase;
  color: var(--text);
}
.ely-nav { display: flex; align-items: center; gap: 2.2rem; justify-self: center; }
.nav-link {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-lg); font-weight: 900;
  letter-spacing: 0.22em; text-transform: uppercase;
  color: var(--text-dim);
  padding: 0.3rem 0.1rem;
  border-bottom: 1px solid transparent;
  transition: color var(--transition), border-color var(--transition);
}
.nav-link:hover { color: var(--text); border-color: var(--accent); }

/* ── Desplegables del nav (Herramientas / Documentación) ── */
.nav-dd { position: relative; }
.nav-trigger {
  display: inline-flex; align-items: center; gap: 0.4rem;
  background: none; border: none; cursor: pointer;
}
.nav-chevron { width: 11px; height: 11px; transition: transform var(--transition); }
.nav-dd.open .nav-link { color: var(--text); border-color: var(--accent); }
.nav-dd.open .nav-chevron { transform: rotate(180deg); }

.nav-panel {
  position: absolute; top: 100%; left: 50%; transform: translateX(-50%);
  margin-top: 0.9rem; z-index: 30;
  min-width: 210px;
  display: flex; flex-direction: column; gap: 0.15rem;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: 10px;
  padding: 0.6rem;
  box-shadow: 0 24px 56px rgba(0,0,0,0.35);
}
.nav-panel-item {
  display: flex; align-items: center; gap: 0.6rem;
  padding: 0.5rem 0.6rem; border-radius: 7px;
  font-size: var(--fs-md); font-weight: 500;
  color: var(--text-dim);
  transition: all 0.15s ease;
}
.nav-panel-item:hover { background: var(--accent-dim); color: var(--text); }
.nav-panel-icon { width: 18px; height: 18px; object-fit: contain; flex-shrink: 0; }

/* Mega-menú de herramientas: icono + nombre + descriptor de una línea */
.nav-panel--tools { min-width: 268px; }
.nav-panel-item--tool { gap: 0.85rem; padding: 0.6rem; }
.nav-panel-item--tool .nav-panel-icon { width: 28px; height: 28px; }
.nav-panel-text { display: flex; flex-direction: column; gap: 0.1rem; min-width: 0; }
.nav-panel-name { font-size: var(--fs-lg); font-weight: 600; color: var(--text); letter-spacing: 0.02em; }
.nav-panel-blurb { font-size: var(--fs-body); color: var(--text-muted); font-weight: 400; }
.nav-panel-item--tool:hover .nav-panel-blurb { color: var(--text-dim); }

.header-actions { display: flex; align-items: center; gap: 0.9rem; justify-self: end; }
.theme-toggle {
  width: 36px; height: 36px; border-radius: 50%;
  display: grid; place-items: center;
  color: var(--accent);
  border: 1px solid var(--border-med);
  transition: all var(--transition);
}
.theme-toggle:hover { border-color: var(--accent); box-shadow: 0 0 14px var(--accent-dim); }
.theme-toggle svg { width: 17px; height: 17px; }
.enter-btn {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.2em; text-transform: uppercase;
  color: var(--accent-bright);
  padding: 0.55rem 1.4rem;
  border: 1px solid var(--accent);
  border-radius: 3px;
  background: var(--accent-dim);
  transition: all var(--transition);
}
.enter-btn:hover { background: var(--accent); color: var(--surface); }
/* Transición de los desplegables del nav (`<Transition name="drop">`).
   Lo demás que había aquí —.avatar-btn, .profile-drop y toda la familia
   .drop-*— eran restos del menú de cuenta cuando vivía dentro de esta vista;
   se extrajo a AccountMenu.vue y el CSS se quedó atrás, sin un solo consumidor
   en la plantilla. */
.drop-enter-active, .drop-leave-active { transition: opacity 0.14s ease, transform 0.14s ease; }
.drop-enter-from, .drop-leave-to { opacity: 0; transform: translateY(-6px); }

/* ═══════════ Contenido del héroe ═══════════ */
.hero-copy {
  position: relative; z-index: 10;
  text-align: center;
  padding: 0 1.5rem;
  margin-top: -10vh;
  animation: hero-rise 1.1s ease-out both;
}
@keyframes hero-rise {
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: translateY(0); }
}
.eyebrow {
  display: inline-block;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-lg); font-weight: 500;
  letter-spacing: 0.42em; text-transform: uppercase;
  color: var(--accent);
  margin-top: 2.5rem;
}
.hero-title {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  /* Antes: clamp(6rem, 6vw, 7.5rem). El mínimo de 96px le ganaba al tramo
     fluido hasta ~1600px de ancho, así que el clamp no fluía NUNCA: en un
     móvil de 375px "Ellysia" se pintaba al mismo tamaño que en un portátil y
     se salía de la pantalla. El máximo se conserva; lo que se baja es el
     mínimo, que era el que rompía. No usa --fs-4xl porque ese token se calibró
     para los titulares del hub (máx. 3.4rem) y aquí encogería el elemento más
     grande de la página a la mitad. */
  font-size: clamp(3.2rem, 1.6rem + 6.8vw, 7.5rem);
  font-weight: 600;
  letter-spacing: 0.14em;
  line-height: 1.05;
  color: var(--text);
  text-shadow: 0 0 60px var(--sun-glow);
}
.verse {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-style: italic;
  font-size: clamp(1.5rem, 2.6vw, 1.75rem);
  color: var(--text-dim);
  letter-spacing: 0.04em;
}
.lede {
  font-size: var(--fs-xl);
  color: var(--text-muted);
  margin-top: 0.6rem;
}
.hero-actions {
  display: flex; align-items: center; justify-content: center; gap: 1rem;
  margin-top: 2.4rem; flex-wrap: wrap;
}
.cta {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-body); font-weight: 600;
  letter-spacing: 0.2em; text-transform: uppercase;
  padding: 0.95rem 2.3rem;
  border-radius: 3px;
  transition: all var(--transition);
}
.cta--solid {
  background: var(--accent);
  color: var(--surface);
  border: 1px solid var(--accent);
}
.cta--solid:hover { background: var(--accent-bright); border-color: var(--accent-bright); box-shadow: 0 0 26px var(--sun-glow); }
.cta--line {
  color: var(--text);
  border: 1px solid var(--accent);
  background: var(--accent-dim);
}
.cta--line:hover { background: var(--accent); color: var(--surface); border-color: var(--accent-bright); box-shadow: 0 0 20px var(--sun-glow); }

.scroll-cue {
  position: absolute; bottom: calc(20vh + 2rem); left: 50%;
  transform: translateX(-50%);
  z-index: 10;
  width: 30px; height: 48px;
  display: flex; justify-content: center;
}
.scroll-cue span {
  display: block; width: 1px; height: 100%;
  background: linear-gradient(to bottom, transparent, var(--accent));
  animation: cue-fall 2.4s ease-in-out infinite;
}
@keyframes cue-fall {
  0%   { transform: scaleY(0); transform-origin: top; }
  55%  { transform: scaleY(1); transform-origin: top; }
  56%  { transform-origin: bottom; }
  100% { transform: scaleY(0); transform-origin: bottom; }
}

/* ═══════════ Friso — banda dorada entre el hero y las estelas ═══════════ */
.greek-banner {
  position: relative;
  height: 36px;
  display: flex; align-items: center;
  background: var(--accent);
  z-index: 5;
  overflow: hidden;
}
.banner-rule {
  height: 2px; width: 100%;
  background: var(--bg);
}

/* Emblema central — sol de doble anillo */
.banner-emblem {
  position: absolute;
  left: 50%; top: 50%;
  transform: translate(-50%, -50%);
  width: 18px; height: 18px;
  background: var(--accent);
  display: grid; place-items: center;
  z-index: 2;
}
.emblem-ring {
  position: absolute;
  border-radius: 50%;
  border: 1px solid var(--bg);
}
.emblem-ring--inner { width: 7px; height: 7px; }
.emblem-ring--outer {
  width: 18px; height: 18px;
  border-style: dashed;
}

/* ═══════════ Filosofía — la inscripción ═══════════ */
/* Sala propia entre el hero y las estelas: fondo distinto (--surface, no
   --bg) y un aliento del ocaso del héroe en degradado, para que se lea como
   un espacio con carácter propio y no como una continuación de las estelas. */
.philosophy {
  position: relative;
  padding: 6rem 3rem;
  background:
    radial-gradient(ellipse 900px 500px at 15% 0%, var(--sun-glow) 0%, transparent 60%),
    var(--surface);
  border-bottom: 1px solid var(--border);
}
.philosophy-inner {
  max-width: 1080px;
  margin: 0 auto;
  display: grid;
  grid-template-columns: 240px 1fr;
  gap: 4rem;
  align-items: center;
}

/* Sócrates, a la izquierda — testigo silencioso de la sección, del mismo
   trazo dorado que los medallones de las herramientas, pero sin marco: una
   presencia junto al texto, no un icono más. */
.philo-figure {
  width: 100%;
  max-width: 220px;
  height: auto;
  margin: 0 auto;
  opacity: 0.8;
  filter: drop-shadow(0 0 18px var(--sun-glow));
}

.philosophy-copy { max-width: 62ch; }

.philo-eyebrow {
  display: block;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-md); font-weight: 500;
  letter-spacing: 0.42em; text-transform: uppercase;
  color: var(--accent);
}
.philo-title {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: clamp(1.8rem, 4vw, 2.7rem);
  font-weight: 600;
  letter-spacing: 0.14em;
  line-height: 1.25;
  color: var(--text);
  margin-top: 1.1rem;
}

/* La pauta dorada a la izquierda: el margen de una inscripción. Se dibuja
   creciendo de arriba abajo a la vez que se revelan los párrafos. */
.philo-text {
  position: relative;
  margin-top: 2.8rem;
  padding-left: 2.4rem;
  display: flex; flex-direction: column; gap: 1.9rem;
}
.philo-text::before {
  content: '';
  position: absolute;
  left: 0; top: 0.5rem; bottom: 0.5rem;
  width: 1px;
  background: linear-gradient(to bottom, var(--accent), transparent);
  transform: scaleY(0);
  transform-origin: top;
  transition: transform 1.6s ease-out;
}
.philo-text:has(.revealed)::before { transform: scaleY(1); }

.philo-para {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: clamp(1.3rem, 2.1vw, 1.7rem);
  line-height: 1.6;
  color: var(--text-dim);
  opacity: 0;
  transform: translateY(14px);
  transition: opacity 0.9s ease, transform 0.9s ease;
}
.philo-para.revealed { opacity: 1; transform: translateY(0); }

/* Cierre: la frase que sostiene el resto sube de peso y de tinta. */
.philo-para--close {
  font-size: clamp(1.45rem, 2.4vw, 1.95rem);
  color: var(--text);
  margin-top: 0.6rem;
}

/* Las dos frases que cargan el argumento — oro, cinceladas, sin cursiva. */
.philo-gold {
  font-style: normal;
  font-weight: 600;
  color: var(--accent);
  letter-spacing: 0.01em;
}

/* ═══════════ Estelas ═══════════ */
.stelae {
  max-width: 1320px;
  margin: 0 auto;
  padding: 4rem 3rem 3rem;
  display: flex; flex-direction: column; gap: 4.5rem;
}

/* ── Cabecera de sección ── */
.stelae-intro {
  text-align: center;
  margin-bottom: 2rem;
}
.stelae-title {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: clamp(1.9rem, 4.2vw, 2.8rem);
  font-weight: 600;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--text);
}
.stelae-bajada {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-style: italic;
  font-size: var(--fs-xl);
  color: var(--text-muted);
  margin-top: 0.8rem;
  padding-bottom: 2.5rem;
}

/* ── Estela ── */
.stele {
  position: relative;
  display: grid;
  grid-template-columns: 240px 1fr;
  gap: 4.5rem;
  align-items: center;
  opacity: 0;
  transform: translateY(26px);
  transition: opacity 0.8s ease, transform 0.4s ease;
}
.stele.revealed { opacity: 1; transform: translateY(0); }
.stele:nth-of-type(even) { grid-template-columns: 1fr 240px; }
.stele:nth-of-type(even) .stele-medallion { order: 2; }
.stele:nth-of-type(even) .stele-body { order: 1; text-align: right; }
.stele:nth-of-type(even) .stele-chips { justify-content: flex-end; }

/* Numeral gigante — marca de agua al fondo de la estela */
.stele::before {
  content: attr(data-numeral);
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: clamp(8rem, 22vw, 16rem);
  font-weight: 700;
  color: var(--text);
  opacity: 0.05;
  pointer-events: none;
  z-index: 0;
  line-height: 1;
  user-select: none;
}
.stele:nth-of-type(even)::before { left: 50%; }

/* ── Medallón ── */
.stele-medallion {
  position: relative;
  width: 200px; height: 200px;
  margin: 0 auto;
  border-radius: 50%;
  display: grid; place-items: center;
  background: var(--surface);
  border: 1px solid var(--accent);
  box-shadow: 0 0 0 7px var(--bg), 0 0 0 8px var(--border-med), 0 18px 50px rgba(0,0,0,0.18);
  transition: box-shadow 0.4s ease;
  animation: medallion-bob 6s ease-in-out infinite;
  z-index: 1;
}
.stele-medallion img { width: 58%; height: 58%; object-fit: contain; }

/* Anillo rotatorio externo — eco del sol del hero */
.medallion-ring {
  position: absolute;
  inset: -12px;
  border: 1px dashed var(--accent);
  border-radius: 50%;
  opacity: 0.35;
  animation: ring-turn 240s linear infinite;
  pointer-events: none;
}
.stele:hover .medallion-ring { opacity: 0.6; }

@keyframes ring-turn { to { transform: rotate(360deg); } }
@keyframes medallion-bob {
  0%, 100% { transform: translateY(0); }
  50%      { transform: translateY(-1.5px); }
}

/* ── Cuerpo ── */
.stele-body { position: relative; z-index: 1; }
.stele-kicker {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-xl); font-weight: 600;
  letter-spacing: 0.34em; text-transform: uppercase;
  color: var(--accent);
}
.stele-myth {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-style: italic;
  font-size: var(--fs-xl);
  color: var(--text-muted);
  margin-top: 0.5rem;
  text-shadow: 0 1px 0 var(--bg);
}

/* Epígrafe latino — inscripción cincelada */
.stele-epigraph {
  display: block;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-xl); font-weight: 600;
  letter-spacing: 0.4em; text-transform: uppercase;
  color: var(--accent);
  opacity: 0.6;
  margin-top: 0.6rem;
}

.stele-title {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: clamp(2rem, 4vw, 2.9rem);
  font-weight: 600;
  line-height: 1.2;
  color: var(--text);
  margin-top: 0.7rem;
}
.stele-desc {
  font-size: var(--fs-xl);
  color: var(--text-dim);
  margin-top: 0.8rem;
  max-width: 72ch;
}
.stele:nth-of-type(even) .stele-desc { margin-left: auto; }
.stele-chips {
  display: flex; flex-wrap: wrap; gap: 0.5rem;
  list-style: none;
  margin-top: 1.1rem;
}
.stele-chips li {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-body);
  color: var(--accent);
  padding: 0.32rem 0.85rem;
  border: 1px solid var(--border-med);
  border-radius: 3px;
  background: var(--accent-dim);
  transition: background 0.3s ease, color 0.3s ease, border-color 0.3s ease;
}
.stele-cta {
  display: inline-flex; align-items: center; gap: 0.5rem;
  margin-top: 1.5rem;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-xl); font-weight: 600;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--accent);
  padding-bottom: 0.3rem;
  border-bottom: 1px solid var(--border-med);
  transition: all var(--transition);
}
.stele-cta:hover { color: var(--accent-bright); border-color: var(--accent); gap: 0.8rem; }

/* ── Hover: estela entera se eleva ── */
.stele.revealed:hover { transform: translateY(-4px); }

/* ── Hover: halo glow del medallón ── */
.stele:hover .stele-medallion {
  box-shadow:
    0 0 0 7px var(--bg),
    0 0 0 8px var(--accent),
    0 0 30px var(--accent-dim),
    0 18px 50px rgba(0,0,0,0.18);
}

/* ── Hover: chips se iluminan ── */
.stele:hover .stele-chips li {
  background: var(--accent);
  color: var(--on-accent);
  border-color: var(--accent);
}

/* ── Divisor entre estelas ── */
.stele-divider {
  max-width: 560px;
  margin: 0 auto;
  opacity: 0.4;
}

/* ═══════════ La senda — cómo se empieza ═══════════ */
/* Pasos, planes y preguntas forman una sola sala, con --surface en vez de
   --bg: antes las tres seguían el fondo de las estelas de arriba, así que la
   página entera desde "Las cinco herramientas" hasta la cinta de tecnologías
   se leía como un único bloque sin costuras. Mismo recurso que ya usa
   .philosophy para separarse de las estelas. */
.path-section {
  margin: 0 auto;
  padding: 4.5rem 3rem 1rem;
  background: var(--surface);
  border-top: 1px solid var(--border);
}
.path-intro { text-align: center; margin-bottom: 3.5rem; }
.path-eyebrow {
  display: block;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-xl); font-weight: 500;
  letter-spacing: 0.42em; text-transform: uppercase;
  color: var(--accent);
}
.path-title {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: clamp(1.6rem, 1.1rem + 2.2vw, 2.6rem);
  font-weight: 600; letter-spacing: 0.12em;
  color: var(--text);
  margin-top: 1rem;
}

/* Los tres pasos, unidos por una línea: el orden es información, y la línea
   lo dice mejor que un número. Es la misma pauta dorada de la filosofía
   (.philo-text::before), puesta en horizontal. */
.path {
  max-width: 1080px;
  position: relative;
  list-style: none;
  margin: 0 auto; padding: 0;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2.5rem;
}
.path::before {
  content: '';
  position: absolute;
  top: 11px; left: 12%; right: 12%;
  height: 1px;
  background: linear-gradient(to right, transparent, var(--accent), transparent);
  opacity: 0.5;
}
.path-step { position: relative; text-align: center; }

/* El hito: el mismo doble anillo del emblema del friso y del medallón de las
   estelas, para que la sección no parezca traída de otra página. */
.path-mark {
  position: relative;
  display: block;
  width: 23px; height: 23px;
  margin: 0 auto 1.4rem;
  border-radius: 50%;
  background: var(--bg);
  border: 1px solid var(--accent);
}
.path-ring {
  position: absolute;
  inset: 4px;
  border-radius: 50%;
  background: var(--accent);
  opacity: 0.65;
}
.path-step-title {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: var(--fs-xl); font-weight: 600;
  color: var(--text);
}
.path-step-desc {
  font-size: var(--fs-md);
  color: var(--text-dim);
  margin-top: 0.5rem;
  max-width: 30ch;
  margin-inline: auto;
}

/* ═══════════ Planes ═══════════ */
.plans-section {
  margin: 0 auto;
  padding: 5rem 5rem 1rem;
  background: var(--surface);
}
.plans-intro { text-align: center; margin-bottom: 3rem; }
.plans-bajada {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-style: italic;
  font-size: var(--fs-xl);
  color: var(--text-muted);
  margin-top: 0.8rem;
  padding-bottom: 2rem;
}
.plans-grid {
  margin: 0 auto;
  max-width: 1200px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 1.1rem;
}
.plan-card {
  position: relative;
  display: flex; flex-direction: column;
  padding: 1.5rem 1.3rem 1.3rem;
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  transition: border-color var(--transition), transform var(--transition);
}
.plan-card:hover { border-color: var(--accent); transform: translateY(-3px); }
/* El gratuito es el que se puede contratar solo, así que es el que se destaca
   — no el más caro, que es lo que haría una tabla de precios al uso. */
.plan-card--default { border-color: var(--accent); }
.plan-tag {
  position: absolute; top: -0.7rem; left: 1.3rem;
  padding: 0.15rem 0.6rem;
  background: var(--accent); color: var(--on-accent);
  border-radius: 999px;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-xs); font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
}
.plan-name {
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-2xl); font-weight: 600;
  letter-spacing: 0.16em; text-transform: uppercase;
  color: var(--text);
}
.plan-tagline {
  font-size: var(--fs-md); color: var(--text-muted);
  margin-top: 0.35rem; min-height: 2.6em;
}
.plan-price { margin-top: 0.9rem; display: flex; align-items: baseline; gap: 0.25rem; }
.plan-amount {
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-2xl); font-weight: 700; color: var(--text);
}
.plan-period { font-size: var(--fs-md); color: var(--text-muted); }
.plan-limits {
  list-style: none; margin: 1.1rem 0 0; padding: 1.1rem 0 0;
  border-top: 1px solid var(--border);
  display: flex; flex-direction: column; gap: 0.5rem;
  flex: 1;
}
.plan-limits li { display: flex; justify-content: space-between; gap: 0.6rem; font-size: var(--fs-md); }
.plan-limit-label { color: var(--text-muted); }
.plan-limit-value { color: var(--text-dim); font-weight: 600; text-align: right; }
.plan-cta {
  display: block; text-align: center;
  margin-top: 1.2rem; padding: 0.55rem 1rem;
  border: 1px solid var(--border-med); border-radius: var(--radius-sm);
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-md); font-weight: 600;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--text-dim);
  transition: all var(--transition);
}
.plan-cta:hover { border-color: var(--accent); color: var(--accent); }
.plan-cta--solid {
  background: var(--accent); border-color: var(--accent); color: var(--on-accent);
}
.plan-cta--solid:hover {
  background: var(--accent-bright); border-color: var(--accent-bright);
  color: var(--on-accent); box-shadow: 0 0 22px var(--sun-glow);
}
.plans-foot { text-align: center; margin-top: 1.8rem; font-size: var(--fs-md); }
.plans-foot a { color: var(--accent); }
.plans-foot a:hover { color: var(--accent-bright); }

/* ═══════════ Preguntas ═══════════ */
.faq-section {
  margin: 0 auto;
  padding: 3rem 3rem 4.5rem;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
.faq-list { display: flex; flex-direction: column; gap: 0.6rem; margin: 0 auto; max-width: 720px; }
.faq-item {
  background: var(--surface-2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.faq-item[open] { border-color: var(--border-med); }
.faq-q {
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  padding: 1rem 1.2rem;
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: var(--fs-lg); font-weight: 600;
  color: var(--text);
  cursor: pointer;
  list-style: none;
}
/* El triángulo por defecto de <summary> no encaja con el resto; se sustituye
   por el mismo chevron del nav. */
.faq-q::-webkit-details-marker { display: none; }
.faq-q:hover { color: var(--accent); transition: 0.2s; }
.faq-q:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
.faq-chevron {
  width: 15px; height: 15px; flex-shrink: 0;
  color: var(--accent);
  transition: transform var(--transition);
}
.faq-item[open] .faq-chevron { transform: rotate(180deg); }
.faq-a {
  padding: 0 1.2rem 1.1rem;
  font-size: var(--fs-md);
  color: var(--text-dim);
  max-width: 62ch;
}

/* ═══════════ Cierre ═══════════ */
/* La pauta que hace de costura con la cinta de tecnologías (ver el div antes
   de esta sección en el template). */
.closing-seam { max-width: 420px; }

.closing {
  margin: 0 auto;
  padding: 4rem 3rem 4.5rem;
  text-align: center;
  /* Antes el resplandor nacía en el borde inferior (at 50% 100%): su punto
     más brillante coincidía exactamente con el border-bottom, así que la
     línea cortaba el brillo por la mitad y la sección entera parecía recortada
     con tijera. Ahora nace arriba, junto al título — como el resplandor de
     .philosophy — y se apaga mucho antes de llegar a ningún borde. Sin bordes
     propios, además: la pauta dorada de arriba y el hueco antes de la placa ya
     separan la sección sin necesidad de una línea recta. */
  background: radial-gradient(ellipse 620px 300px at 50% 0%, var(--sun-glow) 0%, transparent 65%);
}
.closing-title {
  font-family: var(--font-display); font-size-adjust: var(--fsa-display);
  font-size: clamp(1.7rem, 1.2rem + 2.4vw, 2.7rem);
  font-weight: 600; line-height: 1.2;
  color: var(--text);
}
.closing-lede {
  font-size: var(--fs-xl);
  color: var(--text-muted);
  margin-top: 0.9rem;
}
.closing-actions {
  display: flex; align-items: center; justify-content: center; gap: 1rem;
  margin-top: 2.2rem; flex-wrap: wrap;
}

/* ═══════════ Cinta de tecnologías ═══════════ */
.forge {
  margin-top: 0rem;
  padding: 2.4rem 0 0.4rem;
  text-align: center;
}
.forge-eyebrow {
  display: block;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-md); font-weight: 500;
  letter-spacing: 0.4em; text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 1.5rem;
}
.forge-viewport {
  overflow: hidden;
  /* Los nombres aparecen y desaparecen por desvanecimiento en los bordes,
     en vez de cortarse contra el borde de la ventana. */
  mask-image: linear-gradient(to right, transparent, #000 14%, #000 86%, transparent);
  -webkit-mask-image: linear-gradient(to right, transparent, #000 14%, #000 86%, transparent);
}
.forge-track {
  display: flex;
  width: max-content;
  /* De izquierda a derecha: parte de la segunda copia y avanza hasta la
     primera; al llegar a 0 el fotograma es idéntico y el bucle no salta. */
  animation: forge-drift 90s linear infinite;
}
.forge-item {
  flex-shrink: 0;
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-md);
  color: var(--text-dim);
  letter-spacing: 0.08em;
  padding: 0 1.6rem;
}
.forge-item::after {
  content: '◆';
  color: var(--accent);
  opacity: 0.45;
  font-size: 0.5em;
  vertical-align: middle;
  margin-left: 1.6rem;
}
@keyframes forge-drift {
  from { transform: translateX(-50%); }
  to   { transform: translateX(0); }
}

/* Lista equivalente para lectores de pantalla — la cinta va aria-hidden. */
.sr-only {
  position: absolute;
  width: 1px; height: 1px;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}

/* ═══════════ Placa ═══════════ */
.plaque {
  max-width: 1080px;
  margin: 2.6rem auto 0;
  padding: 1.4rem 2rem;
  display: flex; align-items: center; justify-content: center; gap: 1.2rem;
  flex-wrap: wrap;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
  font-family: var(--font-mono); font-size-adjust: var(--fsa-mono);
  font-size: var(--fs-md);
  color: var(--text-dim);
  letter-spacing: 0.05em;
}
.plaque-dot {
  display: inline-block;
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--success);
  box-shadow: 0 0 8px var(--success);
  margin-right: 0.5rem;
  vertical-align: middle;
}
.plaque-sep { color: var(--text-muted); }
.plaque-link:hover { color: var(--accent); }

/* ═══════════ Menú móvil ═══════════ */
/* En escritorio no existe: la navegación de arriba ya está a la vista. */
.menu-toggle { display: none; }
.nav-link--plain { display: inline-flex; align-items: center; background: none; border: none; cursor: pointer; }

.mobile-menu {
  position: absolute;
  top: 100%; left: 1.4rem; right: 1.4rem;
  z-index: 40;
  display: flex; flex-direction: column; gap: 0.15rem;
  max-height: calc(100vh - 5rem);
  overflow-y: auto;
  padding: 0.7rem;
  background: var(--surface);
  border: 1px solid var(--border-solid);
  border-radius: var(--radius);
  box-shadow: 0 24px 56px rgba(0,0,0,0.4);
}
.mobile-heading {
  padding: 0.5rem 0.6rem 0.3rem;
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-xs); font-weight: 600;
  letter-spacing: 0.3em; text-transform: uppercase;
  color: var(--text-muted);
}
.mobile-item {
  display: block;
  padding: 0.6rem;
  border-radius: var(--radius-sm);
  font-size: var(--fs-md); font-weight: 500;
  color: var(--text-dim);
  transition: background var(--transition), color var(--transition);
}
.mobile-item:hover, .mobile-item:focus-visible { background: var(--accent-dim); color: var(--text); }
.mobile-item--tool { display: flex; align-items: center; gap: 0.75rem; }
.mobile-icon { width: 26px; height: 26px; object-fit: contain; flex-shrink: 0; }
.mobile-text { display: flex; flex-direction: column; gap: 0.1rem; min-width: 0; }
.mobile-name { font-size: var(--fs-md); font-weight: 600; color: var(--text); }
.mobile-blurb { font-size: var(--fs-sm); color: var(--text-muted); }
.mobile-cta {
  margin-top: 0.5rem; padding: 0.7rem;
  text-align: center;
  background: var(--accent); color: var(--on-accent);
  border-radius: var(--radius-sm);
  font-family: var(--font-epic); font-size-adjust: var(--fsa-epic);
  font-size: var(--fs-sm); font-weight: 600;
  letter-spacing: 0.16em; text-transform: uppercase;
}
.mobile-cta:hover { background: var(--accent-bright); }

/* Foco visible en la cabecera, que no lo tenía en ningún control. */
.nav-link:focus-visible,
.menu-toggle:focus-visible,
.theme-toggle:focus-visible,
.enter-btn:focus-visible,
.nav-panel-item:focus-visible,
.mobile-item:focus-visible,
.mobile-cta:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

/* ═══════════ Responsive ═══════════ */
@media (max-width: 960px) {
  /* La navegación de arriba se va y el botón del menú toma el relevo. Antes se
     iba sin sustituto: desde un móvil no había forma de llegar a las
     herramientas desde la cabecera. */
  .ely-nav { display: none; }
  .menu-toggle {
    width: 36px; height: 36px; border-radius: 50%;
    display: grid; place-items: center;
    color: var(--accent);
    border: 1px solid var(--border-med);
    background: none; cursor: pointer;
    transition: all var(--transition);
  }
  .menu-toggle:hover { border-color: var(--accent); box-shadow: 0 0 14px var(--accent-dim); }
  .menu-toggle svg { width: 19px; height: 19px; }
  .ely-header { padding: 1.1rem 1.4rem; }
}

@media (max-width: 768px) {
  /* Los tres pasos se apilan: en columna la línea que los une deja de tener
     sentido horizontal, así que se apaga. */
  .path { grid-template-columns: 1fr; gap: 2.2rem; }
  .path::before { display: none; }
  .path-section, .plans-section, .faq-section { width: 100% }
  .closing { padding: 2.8rem 1.5rem; }
}
@media (max-width: 860px) {
  .stele,
  .stele:nth-of-type(even) { grid-template-columns: 1fr; gap: 1.8rem; }
  .stele:nth-of-type(even) .stele-medallion { order: 0; }
  .stele:nth-of-type(even) .stele-body { order: 1; text-align: left; }
  .stele:nth-of-type(even) .stele-chips { justify-content: flex-start; }
  .stele:nth-of-type(even) .stele-desc { margin-left: 0; }
  .stele-medallion { width: 150px; height: 150px; margin: 0; }
  .stelae { gap: 3.5rem; padding: 3.5rem 1.5rem 3rem; }
  .stele::before { font-size: clamp(6rem, 18vw, 10rem); opacity: 0.04; }
  .stele-epigraph { letter-spacing: 0.28em; }
}
@media (max-width: 640px) {
  .wordmark-text { letter-spacing: 0.24em; font-size: var(--fs-xl); }
  .columns { width: 34vw; }
  .hero-actions .cta { padding: 0.8rem 1.5rem; }
  .stelae-title { letter-spacing: 0.1em; }
  .stelae-bajada { font-size: var(--fs-xl); padding-bottom: 1.8rem; }
  .stele-epigraph { letter-spacing: 0.2em; font-size: var(--fs-md); }
  .stele-divider { max-width: 320px; }
  .stelae { padding: 3rem 1.2rem 2.5rem; }
  .greek-banner { height: 28px; }
  .philosophy { padding: 4rem 1.4rem; }
  .philosophy-inner { grid-template-columns: 1fr; gap: 1.6rem; justify-items: center; text-align: center; }
  .philo-figure { max-width: 130px; }
  .philo-text { padding-left: 1.3rem; gap: 1.5rem; text-align: left; }
  .forge-item { padding: 0 1rem; font-size: var(--fs-body); }
  .forge-item::after { margin-left: 1rem; }
}

/* ═══════════ Movimiento reducido ═══════════ */
@media (prefers-reduced-motion: reduce) {
  .scroll-cue span, .hero-copy { animation: none !important; }
  .stele { opacity: 1; transform: none; transition: none; }
  .stele.revealed:hover { transform: none !important; }
  .stele-medallion, .medallion-ring { animation: none !important; }
  .philo-para { opacity: 1; transform: none; transition: none; }
  .philo-text::before { transform: scaleY(1); transition: none; }
  .forge-track { animation: none; }
  .plan-card, .faq-chevron { transition: none; }
  .plan-card:hover { transform: none; }
}
</style>
