import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import { nitroV2Plugin } from '@tanstack/nitro-v2-vite-plugin'
import tailwindcss from '@tailwindcss/vite'
import viteReact from '@vitejs/plugin-react'
import viteTsConfigPaths from 'vite-tsconfig-paths'
import { defineConfig } from 'vite'
import { VitePWA } from 'vite-plugin-pwa'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Plugin } from 'vite'
import type { Plugin as EsbuildPlugin } from 'esbuild'

const __dirname = dirname(fileURLToPath(import.meta.url))

function tanstackStartStorageContextClientStub(): Plugin {
  const stubId = resolve(__dirname, './src/shared/lib/stubs/tanstack-start-storage-context.ts')
  return {
    name: 'refmd:tanstack-start-storage-context-client-stub',
    enforce: 'pre',
    resolveId(source, _importer, options) {
      if (options?.ssr) return null
      if (source === '@tanstack/start-storage-context') {
        return stubId
      }
      return null
    },
  }
}

function tanstackStartStorageContextOptimizeDepsStub(): EsbuildPlugin {
  const stubId = resolve(__dirname, './src/shared/lib/stubs/tanstack-start-storage-context.ts')
  return {
    name: 'refmd:tanstack-start-storage-context-optimize-deps-stub',
    setup(build) {
      build.onResolve({ filter: /^@tanstack\/start-storage-context$/ }, () => ({
        path: stubId,
      }))
    },
  }
}

export default defineConfig(() => {
  const enablePwaDev = process.env.VITE_PWA_DEV === 'true'

  return {
  optimizeDeps: {
    include: ['buffer', 'bip39'],
    exclude: [
      'nitropack',
      'nitropack/runtime',
      '@tanstack/start-client-core',
      '@tanstack/start-storage-context',
      '@resvg/resvg-js',
      '@resvg/resvg-js-linux-x64-gnu',
      '@resvg/resvg-js-linux-x64-musl',
    ],
    esbuildOptions: {
      plugins: [tanstackStartStorageContextOptimizeDepsStub()],
    },
  },
  plugins: [
    wasm(),
    topLevelAwait(),
    tanstackStartStorageContextClientStub(),
    tanstackStart(),
    nitroV2Plugin({
      preset: 'node-server',
    }),
    viteReact(),
    tailwindcss(),
    viteTsConfigPaths({
      projects: ['./tsconfig.json'],
    }),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.ico', 'robots.txt', 'refmd-192.png', 'refmd-512.png'],
      manifest: {
        name: 'RefMD',
        short_name: 'RefMD',
        description: 'RefMD - Real-time Collaborative Markdown Editor',
        theme_color: '#000000',
        background_color: '#ffffff',
        display: 'standalone',
        display_override: ['standalone', 'browser'],
        scope: '/',
        start_url: '/',
        lang: 'en',
        icons: [
          {
            src: 'favicon.ico',
            sizes: '64x64 32x32 24x24 16x16',
            type: 'image/x-icon',
          },
          {
            src: 'refmd-192.png',
            sizes: '192x192',
            type: 'image/png',
          },
          {
            src: 'refmd-512.png',
            sizes: '512x512',
            type: 'image/png',
          },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,webp,woff2}'],
        navigateFallback: '/',
        runtimeCaching: [
          {
            urlPattern: ({ request }) => request.mode === 'navigate',
            handler: 'NetworkFirst',
            options: {
              cacheName: 'refmd-pages',
            },
          },
          {
            urlPattern: ({ request }) => request.destination === 'script' || request.destination === 'style',
            handler: 'StaleWhileRevalidate',
            options: {
              cacheName: 'refmd-assets',
            },
          },
          {
            urlPattern: ({ request }) => request.destination === 'image' || request.destination === 'font',
            handler: 'CacheFirst',
            options: {
              cacheName: 'refmd-static-assets',
              expiration: {
                maxEntries: 200,
                maxAgeSeconds: 60 * 60 * 24 * 30, // 30 days
              },
            },
          },
          {
            urlPattern: ({ url }) => url.pathname.startsWith('/api/'),
            handler: 'NetworkFirst',
            options: {
              cacheName: 'refmd-api',
              networkTimeoutSeconds: 10,
            },
          },
        ],
      },
      devOptions: {
        enabled: enablePwaDev,
        navigateFallback: '/',
        suppressWarnings: true,
      },
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      buffer: 'buffer/',
    },
    dedupe: ['react', 'react-dom'],
  },
  ssr: {
    // Bundle these CommonJS packages for SSR to avoid "require is not defined" errors
    noExternal: ['buffer', 'bip39'],
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('monaco-editor') || id.includes('monaco-markdown') || id.includes('monaco-vim')) {
              return 'monaco'
            }
            if (id.includes('yjs') || id.includes('y-monaco') || id.includes('y-websocket')) {
              return 'yjs'
            }
            if (id.includes('@tanstack/react-router')) {
              return 'router'
            }
            if (id.includes('@tanstack/react-query')) {
              return 'react-query'
            }
          }
          return undefined
        },
      },
    },
  },
  }
})
