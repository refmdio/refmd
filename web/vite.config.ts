import { defineConfig } from 'vite'
import { devtools } from '@tanstack/devtools-vite'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import viteReact from '@vitejs/plugin-react'
import viteTsConfigPaths from 'vite-tsconfig-paths'
import { fileURLToPath, URL } from 'url'

import tailwindcss from '@tailwindcss/vite'
import { nitro } from 'nitro/vite'

export default defineConfig(({ mode }) => {
  const isTest = mode === 'test' || Boolean(process.env.VITEST)

  return {
    resolve: {
      alias: {
        '@': fileURLToPath(new URL('./src', import.meta.url)),
      },
    },
    plugins: [
      // Some TanStack Start/Nitro plugins may attempt to bind ports during tests.
      // Skip them so `vitest run` stays hermetic.
      !isTest && devtools(),
      !isTest && nitro(),
      viteTsConfigPaths({
        projects: ['./tsconfig.json'],
      }),
      tailwindcss(),
      !isTest && tanstackStart(),
      viteReact(),
    ].filter(Boolean),
    test: {
      environment: 'jsdom',
      passWithNoTests: true,
    },
  }
})
