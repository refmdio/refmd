# Build stage: install dependencies and produce TanStack Start output
FROM node:22-alpine AS build
WORKDIR /app

# Build tooling required by some npm packages
RUN apk add --no-cache python3 make g++ libc6-compat

COPY package*.json ./
COPY tsconfig.json ./
COPY vite.config.ts ./
COPY vite.wc.config.ts ./
COPY components.json ./
COPY eslint.config.js ./
COPY nitro.config.ts ./
COPY public ./public
COPY src ./src

RUN npm ci
RUN npm run build

# Production deps stage: clean install without dev dependencies
FROM node:22-alpine AS deps
WORKDIR /app

RUN apk add --no-cache python3 make g++ libc6-compat

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Remove build tools and packages not needed at runtime
RUN rm -rf node_modules/vite \
    node_modules/typescript \
    node_modules/prettier \
    node_modules/@esbuild \
    node_modules/esbuild \
    node_modules/lightningcss* \
    node_modules/@babel \
    node_modules/eslint* \
    node_modules/@typescript-eslint \
    node_modules/@vitejs \
    node_modules/wasm-pandoc \
    node_modules/leveldown \
    node_modules/level \
    node_modules/y-leveldb \
    node_modules/rollup \
    node_modules/@rollup \
    node_modules/caniuse-lite \
    node_modules/browserslist

# Runtime stage: run the prebuilt TanStack Start server
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
ENV TSS_APP_BASE=/
ENV TSS_SERVER_FN_BASE=/_serverFn
ENV PORT=80
ENV HOST=0.0.0.0
ENV NITRO_HOST=0.0.0.0
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/package*.json ./
COPY --from=build /app/.output ./.output
COPY --from=build /app/dist ./dist

EXPOSE 80
CMD ["node", ".output/server/index.mjs"]
