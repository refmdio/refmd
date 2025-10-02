# Build stage: install dependencies and produce TanStack Start output
FROM node:22-bullseye AS build
WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./
COPY vite.config.ts ./
COPY vite.wc.config.ts ./
COPY components.json ./
COPY eslint.config.js ./
COPY public ./public
COPY src ./src

RUN npm ci
RUN npm run build

# Runtime stage: run the prebuilt TanStack Start server
FROM node:22-bullseye-slim AS runtime
ENV NODE_ENV=production
ENV TSS_APP_BASE=/
ENV TSS_SERVER_FN_BASE=/_serverFn
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY --from=build /app/.output ./.output
COPY --from=build /app/dist ./dist

EXPOSE 3000
CMD ["node", ".output/server/index.mjs"]
