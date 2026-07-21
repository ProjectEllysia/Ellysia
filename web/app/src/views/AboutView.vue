<template>
  <InfoPage eyebrow="Ellysia" title="Sobre nosotros">
    <p>
      Ellysia reúne cuatro herramientas de operaciones de seguridad bajo un mismo cielo,
      pensadas para las pequeñas y medianas empresas que necesitan protegerse sin poder
      permitirse un equipo de seguridad completo.
    </p>

    <h2>Las cuatro herramientas</h2>
    <ul>
      <li><strong>Themis</strong> — detección de vulnerabilidades con motor propio (Lybra) y los escáneres clásicos como testigos.</li>
      <li><strong>Aegis</strong> — formación de concienciación generada por IA, enviada y demostrada con campañas.</li>
      <li><strong>Iris</strong> — análisis de cabeceras de correo contra el phishing, con veredicto explicado.</li>
      <li><strong>Acheron</strong> — bóveda cifrada en tu navegador: la llave nunca viaja al servidor.</li>
    </ul>

    <h2>Nuestra idea</h2>
    <p>
      Creemos que la seguridad no debería ser un privilegio de las grandes empresas. Ellysia
      nace para dar a quien lleva la seguridad de una PYME algo entre no hacer nada y contratar
      a un consultor: en su idioma, a un precio razonable y sin la fricción de un despliegue
      empresarial.
    </p>

    <p class="note">
      Ellysia es un proyecto en construcción. Si tienes comentarios o quieres seguir su
      evolución, el código está disponible en
      <a href="https://github.com/ProjectEllysia/Ellysia" target="_blank" rel="noopener noreferrer">GitHub</a>.
    </p>
  </InfoPage>
</template>

<script setup>
import InfoPage from '@/components/shared/InfoPage.vue'
</script>
