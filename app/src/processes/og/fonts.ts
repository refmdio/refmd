import { Buffer } from 'node:buffer'

import { useStorage } from 'nitropack/runtime'
import type { Font } from 'satori'

type FontSpec = {
  key: string
  name: Font['name']
  weight: Font['weight']
}

const FONT_FILES: FontSpec[] = [
  { key: 'og-fonts/NotoSansJP-Regular.ttf', name: 'Noto Sans JP', weight: 400 },
  { key: 'og-fonts/NotoSansJP-Bold.ttf', name: 'Noto Sans JP', weight: 700 },
]

let cache: Promise<Font[]> | null = null

export async function loadOgFonts(): Promise<Font[]> {
  if (!cache) {
    const storage = useStorage('assets')
    cache = Promise.all(
      FONT_FILES.map(async ({ key, name, weight }) => {
        const raw = await storage.getItemRaw(key)
        if (!raw) {
          throw new Error(`Missing OG font asset: ${key}`)
        }
        const view = raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer)
        const normalized = view.byteOffset === 0 && view.byteLength === view.buffer.byteLength ? view : view.slice()
        const data = Buffer.from(normalized)
        return { name, weight, data }
      }),
    )
  }

  return cache!
}
