# CLAUDE.md — Web SPA

Vue 3 + Vite single-page app (Pinia + Vue Router). See the root [`../../CLAUDE.md`](../../CLAUDE.md) for backend/architecture context. Comments are in **Spanish** — match them.

## Commands (run from this directory)
```bash
npm install
npm run dev            # dev server on :5173; proxies /oauth,/themis,/aegis,/users,/system,/acheron,/iris → Flask :5000 (see vite.config.js)
npm run build
npm run test:acheron   # crypto interop + CRUD tests for the Acheron vault client (node, in test/)
```

## Layout (`src/`)
- `views/` — one component per route (Themis, Iris, Aegis, Acheron, Users, Config, Profile, Queue, Login, Landing).
- `stores/` — Pinia stores, one per domain (`authStore`, `themisStore`, `mfaStore`, ...).
- `components/` — grouped by feature (`themis/`, `aegis/`, `iris/`, `acheron/`, `shared/`, ...).
- `composables/` — `useApi.js` is the authed fetch wrapper: injects the JWT, refreshes on 401 and retries once, redirects to login on failure. **Use `apiFetch` for all API calls**, don't call `fetch` directly.
- `acheron/` — client-side vault crypto (`crypto.js`, `vault.js`, password tools). Encryption is client-side; the server only ever sees ciphertext.
- `@` alias → `src/` (configured in `vite.config.js`).
