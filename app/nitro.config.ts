import { defineNitroConfig } from 'nitropack/config'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

export default defineNitroConfig({
  compatibilityDate: '2026-01-01',
  serverAssets: [
    {
      baseName: 'og-fonts',
      dir: resolve(__dirname, './src/processes/og/assets'),
    },
  ],
})
