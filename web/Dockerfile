# Stage 1: Build the Vue SPA
FROM node:20-alpine AS builder
WORKDIR /app
COPY app/package.json ./
RUN corepack enable && pnpm install
COPY app/ .
RUN pnpm build

# Stage 2: Serve with Nginx
FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY resources/ /usr/share/nginx/html/resources/
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
