<template>
  <div v-if="password" class="strength-meter">
    <div class="strength-track">
      <div
        class="strength-fill"
        :style="{ width: strength.percent + '%', background: strength.color }"
      ></div>
    </div>
    <span class="strength-label" :style="{ color: strength.color }">{{ strength.label }}</span>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { scorePassword } from '@/acheron/passwordStrength.js'

const props = defineProps({
  password: { type: String, default: '' },
})

const strength = computed(() => scorePassword(props.password))
</script>

<style scoped>
.strength-meter {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 0.4rem;
}
.strength-track {
  flex: 1;
  height: 5px;
  border-radius: 3px;
  overflow: hidden;
  background: rgba(255, 255, 255, 0.08);
}
.strength-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.25s ease, background 0.25s ease;
}
.strength-label {
  font-family: var(--font-mono);
  font-size: var(--fs-body);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  white-space: nowrap;
}
</style>
