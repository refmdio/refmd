import { defineConfig } from 'vite'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import { nitroV2Plugin } from '@tanstack/nitro-v2-vite-plugin'
import tailwindcss from '@tailwindcss/vite'
import viteReact from '@vitejs/plugin-react'
import viteTsConfigPaths from 'vite-tsconfig-paths'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [
    tanstackStart(),
    nitroV2Plugin({ preset: 'node-server' }),
    viteReact(),
    tailwindcss(),
    viteTsConfigPaths({
      projects: ['./tsconfig.json'],
    }),
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
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
})
