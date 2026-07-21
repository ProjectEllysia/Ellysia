<template>
  <InfoPage eyebrow="Documentación" :title="route.meta.docTitle">
    <p>{{ route.meta.docIntro }}</p>
    <p class="note">Esta sección está en construcción — se irá completando junto al resto de la documentación de Ellysia.</p>
  </InfoPage>
</template>

<script setup>
import { useRoute } from 'vue-router'
import InfoPage from '@/components/shared/InfoPage.vue'

const route = useRoute()
</script>
