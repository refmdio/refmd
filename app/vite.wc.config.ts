import { defineConfig } from 'vite'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Separate build for Web Components library
export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@tanstack/start-client-core': resolve(__dirname, 'src/shared/lib/stubs/tanstack-start-client-core.ts'),
    },
  },
  build: {
    outDir: resolve(__dirname, 'dist'),
    lib: {
      entry: resolve(__dirname, 'src/entities/document/wc/index.ts'),
      name: 'refmd-wc',
      formats: ['es'],
      fileName: () => 'assets/refmd-wc.js',
    },
    rollupOptions: {
      external: [],
      output: {
        // Keep a stable filename for easy inclusion
        assetFileNames: (chunkInfo) => {
          if (chunkInfo.name && /\.css$/.test(chunkInfo.name)) return 'assets/refmd-wc.css'
          return 'assets/[name][extname]'
        },
      },
    },
    sourcemap: false,
    emptyOutDir: false,
  },
})
