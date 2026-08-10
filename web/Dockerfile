# Stage 1: Build the Vue SPA
FROM node:22-slim AS builder
WORKDIR /app
COPY app/package.json app/pnpm-lock.yaml ./
RUN npm install -g pnpm@11.10.0 && pnpm install --frozen-lockfile
COPY app/ .
RUN pnpm build

# Stage 2: Serve with Nginx
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
# E6: sin COPY ssl/ — la clave privada no debe quedar horneada en ninguna
# capa de la imagen (ni en un registry si se sube). docker-compose.yml ya
# monta ./web/ssl como volumen read-only en /etc/nginx/ssl; ejecutar esta
# imagen sin ese volumen falla al arrancar (certs ausentes) en vez de
# arrancar con la clave anterior horneada.
COPY proxy-common.conf /etc/nginx/conf.d/proxy-common.conf
# A15: fuera de conf.d/ a propósito — la imagen base incluye conf.d/*.conf
# dentro de http{}, y un `location` en ese contexto impide arrancar.
COPY api-locations.conf /etc/nginx/api-locations.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
