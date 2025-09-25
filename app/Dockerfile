# --- Build stage ---
FROM node:20-bullseye AS build
WORKDIR /app
COPY package*.json ./
COPY tsconfig.json ./
COPY vite.config.ts ./
COPY vite.wc.config.ts ./
COPY components.json ./
COPY .eslintrc.cjs ./
COPY eslint.config.js ./
COPY index.html ./
COPY public ./public
COPY src ./src
RUN npm ci && npm run build

# --- Runtime stage (Nginx) ---
FROM nginx:1.27-alpine AS runtime
WORKDIR /usr/share/nginx/html

# Runtime dependencies for templating
RUN apk add --no-cache gettext

# Nginx config template (rendered at container start)
COPY docker/nginx.conf.template /etc/nginx/conf.d/default.conf.template

# Generated SPA assets
COPY --from=build /app/dist/ /usr/share/nginx/html/

# Runtime env injection entrypoint (creates /usr/share/nginx/html/env.js)
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV VITE_API_BASE_URL=""

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1/ >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
