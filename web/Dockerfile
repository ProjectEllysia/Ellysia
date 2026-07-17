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
COPY ssl/ /etc/nginx/ssl/
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]
