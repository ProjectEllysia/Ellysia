# Stage 1: Build the Vue SPA
FROM node:22-slim AS builder
WORKDIR /app
COPY app/package.json app/pnpm-lock.yaml app/.npmrc ./

# El SPA depende de @projectellysia/acheron-core-web, que vive en GitHub
# Packages y es PRIVADO, asi que la instalacion necesita credencial.
#
# Va como secreto de BuildKit y no como ARG ni ENV a proposito: un ARG queda
# grabado en los metadatos de la imagen y `docker history` lo enseña. Con
# --mount=type=secret el token solo existe durante ese RUN y no deja capa.
RUN --mount=type=secret,id=node_auth_token \
    npm install -g pnpm@11.10.0 \
 && NODE_AUTH_TOKEN="$(cat /run/secrets/node_auth_token)" \
    pnpm install --frozen-lockfile

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
