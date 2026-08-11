<template>
  <InfoPage eyebrow="Error 404" title="Esta página no existe">
    <p>
      La dirección a la que has llegado no corresponde a ninguna página de Ellysia.
      Puede que el enlace esté mal escrito, o que la página se moviera de sitio.
    </p>
    <p class="note">
      Desde aquí puedes volver a la
      <router-link to="/">portada</router-link>, ver las
      <router-link to="/themis">herramientas</router-link>
      o consultar los <router-link to="/planes">planes</router-link>.
    </p>
  </InfoPage>
</template>

<script setup>
/**
 * Página para direcciones que no existen.
 *
 * Sin ella, el router no tenía ruta comodín y cualquier URL desconocida
 * renderizaba una vista en blanco: ni error, ni salida, ni forma de saber si
 * la aplicación se había roto. Reutiliza el layout `InfoPage` (cabecera + pie
 * compartidos) para que la salida siempre esté a la vista.
 */
import InfoPage from '@/components/shared/InfoPage.vue'
</script>
