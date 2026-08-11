<template>
  <div class="user-card" :class="`user-card--${roleClass}`" @click="$emit('details', user.id)">
    <div class="card-avatar">{{ initials }}</div>
    <div class="card-body">
      <div class="card-name">{{ user.first_name || '—' }} {{ user.last_name || '' }}</div>
      <div class="card-username">@{{ user.username }}</div>
      <div class="card-meta">
        <span class="card-email" :title="user.email">{{ user.email }}</span>
        <span class="card-id">#{{ user.id }}</span>
      </div>
      <div class="card-footer">
        <span class="card-role-badge" :class="`role-badge--${roleClass}`">{{ roleLabel }}</span>
        <span v-if="user.created_at" class="card-date">{{ formatDate(user.created_at) }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useUtils } from '@/composables/useUtils'

const { formatDate, getInitials } = useUtils()
const props = defineProps({ user: { type: Object, required: true } })
defineEmits(['details'])

const initials = computed(() => getInitials(props.user.first_name, props.user.last_name))
const roleClass = computed(() => { const r = props.user.role || 'role_user'; if (r === 'role_root') return 'root'; if (r === 'role_admin') return 'admin'; return 'user' })
const roleLabel = computed(() => { const r = props.user.role || 'role_user'; if (r === 'role_root') return 'Root'; if (r === 'role_admin') return 'Admin'; return 'Usuario' })
</script>

<style scoped>
.user-card { display: flex; align-items: center; gap: 0.85rem; padding: 0.85rem; background: var(--surface); border: 1px solid var(--border); border-radius: 9px; cursor: pointer; transition: border-color 0.2s, transform 0.15s; }
.user-card:hover { border-color: var(--border-med); }
.user-card--root  { border-left: 3px solid var(--danger); }
.user-card--admin { border-left: 3px solid var(--warn); }
.user-card--user  { border-left: 3px solid var(--info); }
.card-avatar { width: 42px; height: 42px; border-radius: 50%; flex-shrink: 0; display: flex; align-items: center; justify-content: center; font-size: var(--fs-xl); font-weight: 700; background: var(--accent-dim); color: var(--accent-bright); font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); }
.user-card--root  .card-avatar { background: rgba(217,108,108,0.15); color: var(--danger); }
.user-card--admin .card-avatar { background: rgba(212,160,74,0.15); color: var(--warn); }
.user-card--user  .card-avatar { background: rgba(96,128,224,0.15); color: var(--info); }
.card-body { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 0.15rem; }
.card-name { font-size: var(--fs-xl); font-weight: 700; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.card-username { font-size: var(--fs-lg); color: var(--text-dim); }
.card-meta { display: flex; gap: 0.65rem; font-size: var(--fs-md); color: var(--text-muted); }
.card-email { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 140px; }
.card-id { font-family: var(--font-mono); font-size-adjust: var(--fsa-mono); opacity: 0.6; font-size: var(--fs-md); }
.card-footer { display: flex; align-items: center; gap: 0.4rem; margin-top: 0.15rem; }
.card-role-badge { font-size: var(--fs-body); font-weight: 700; text-transform: uppercase; letter-spacing: 0.02em; padding: 0.1rem 0.4rem; border-radius: 4px; }
.role-badge--root  { background: rgba(217,108,108,0.15);  color: var(--danger); }
.role-badge--admin { background: rgba(212,160,74,0.15); color: var(--warn); }
.role-badge--user  { background: rgba(96,128,224,0.12); color: var(--info); }
.card-date { font-size: var(--fs-body); color: var(--text-muted); margin-left: auto; }
</style>
