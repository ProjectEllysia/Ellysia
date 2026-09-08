<template>
  <div class="collapsible" :class="{ 'collapsible--open': isOpen }">
    <button type="button" class="collapsible-toggle" @click="isOpen = !isOpen">
      <span class="collapsible-toggle-main"><slot name="header" /></span>
      <span class="collapsible-arrow" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6" /></svg>
      </span>
    </button>
    <div v-show="isOpen" class="collapsible-body">
      <slot />
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
const props = defineProps({ defaultOpen: { type: Boolean, default: true } })
const isOpen = ref(props.defaultOpen)
</script>

<style scoped>
.collapsible-toggle { width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; background: none; border: none; padding: 0; cursor: pointer; text-align: left; color: inherit; font: inherit; }
.collapsible-toggle-main { flex: 1; min-width: 0; }
.collapsible-arrow { width: 18px; height: 18px; flex-shrink: 0; display: flex; color: var(--text-muted); transition: transform 0.15s ease; }
.collapsible--open .collapsible-arrow { transform: rotate(180deg); }
.collapsible-body { padding-top: 0.65rem; }
</style>
