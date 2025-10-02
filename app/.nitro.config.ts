import { defineNitroConfig } from '@tanstack/nitro-v2-vite-plugin/config'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

export default defineNitroConfig({
  preset: 'node-server',
  compatibilityDate: '2025-10-02',
  rootDir: __dirname,
  output: {
    dir: {
      public: resolve(__dirname, 'dist/client'),
      server: resolve(__dirname, '.output/server'),
    },
  },
  runtimeConfig: {
    nitro: {
      serveStatic: true,
    },
  },
  serverAssets: {
    inline: false,
  },
})
