# Stage 1: Build the Vue SPA
FROM node:22-slim AS builder
WORKDIR /app
COPY app/package.json app/pnpm-lock.yaml ./
RUN npm install -g pnpm@11.10.0 && pnpm install --frozen-lockfile
COPY app/ .
RUN pnpm build

# Stage 2: Serve with Caddy
#
# E6 ya no aplica: no hay clave privada que se pueda hornear en una capa de
# la imagen. Caddy emite y guarda el certificado él mismo, en el volumen
# `caddy_data` que docker-compose.yml monta en /data.
FROM caddy:2-alpine
COPY --from=builder /app/dist /srv
COPY Caddyfile /etc/caddy/Caddyfile
EXPOSE 80 443
# Sin CMD: la imagen base ya arranca
# `caddy run --config /etc/caddy/Caddyfile --adapter caddyfile`.
