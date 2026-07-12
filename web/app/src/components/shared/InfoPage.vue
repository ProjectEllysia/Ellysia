<template>
  <div class="info-page">
    <SiteHeader />
    <main class="info-main">
      <span class="info-eyebrow">{{ eyebrow }}</span>
      <h1 class="info-title">{{ title }}</h1>
      <div class="info-body">
        <slot />
      </div>
    </main>
    <SiteFooter />
  </div>
</template>

<script setup>
import SiteHeader from '@/components/shared/SiteHeader.vue'
import SiteFooter from '@/components/shared/SiteFooter.vue'

defineProps({
  eyebrow: { type: String, default: 'Ellysia' },
  title: { type: String, required: true },
})
</script>

<style scoped>
.info-page { min-height: 100vh; background: var(--bg); display: flex; flex-direction: column; }
.info-main {
  flex: 1;
  width: 100%;
  max-width: 760px;
  margin: 0 auto;
  padding: 4rem 2rem 5rem;
}
.info-eyebrow {
  font-family: var(--font-epic);
  font-size: 1.3rem; font-weight: 600;
  letter-spacing: 0.32em; text-transform: uppercase;
  color: var(--accent);
}
.info-title {
  font-family: var(--font-display);
  font-size: clamp(2.2rem, 5vw, 3.2rem);
  font-weight: 600;
  color: var(--text);
  margin-top: 0.6rem;
  line-height: 1.15;
}
.info-body {
  margin-top: 2rem;
  color: var(--text-dim);
  font-size: 1.4rem;
  line-height: 1.75;
}
/* El contenido llega vía slot; estos estilos globales lo maquetan. */
.info-body :deep(h2) {
  font-family: var(--font-epic);
  font-size: 1.57rem; font-weight: 600;
  letter-spacing: 0.16em; text-transform: uppercase;
  color: var(--accent);
  margin: 2.4rem 0 0.8rem;
}
.info-body :deep(p) { margin-bottom: 1.1rem; }
.info-body :deep(ul) { margin: 0 0 1.1rem 1.2rem; display: flex; flex-direction: column; gap: 0.5rem; }
.info-body :deep(strong) { color: var(--text); font-weight: 600; }
.info-body :deep(.note) {
  margin-top: 2.5rem;
  padding: 1.1rem 1.3rem;
  border-left: 2px solid var(--accent);
  background: var(--accent-dim);
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  font-size: 1.25rem;
  color: var(--text-dim);
}
</style>
