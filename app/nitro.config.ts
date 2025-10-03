import { defineNitroConfig } from 'nitropack/config'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

export default defineNitroConfig({
  serverAssets: [
    {
      baseName: 'og-fonts',
      dir: resolve(__dirname, './src/server/og/assets'),
    },
  ],
})
