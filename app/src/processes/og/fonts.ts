import { Buffer } from 'node:buffer'
import { readFile } from 'node:fs/promises'

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
    cache = Promise.all(
      FONT_FILES.map(async ({ key, name, weight }) => {
        const data = await loadFontAsset(key)
        return { name, weight, data }
      }),
    )
  }

  return cache!
}

async function loadFontAsset(key: string): Promise<Buffer> {
  const fromNitro = await tryLoadFromNitroStorage(key)
  if (fromNitro) return fromNitro

  const filename = key.replace(/^og-fonts\//, '')
  const url = new URL(`./assets/${filename}`, import.meta.url)
  return readFile(url)
}

async function tryLoadFromNitroStorage(key: string): Promise<Buffer | null> {
  try {
    const mod = await import('nitropack/runtime')
    const useStorage = (mod as any)?.useStorage as ((base?: string) => any) | undefined
    if (!useStorage) return null
    const storage = useStorage('assets')
    const raw = await storage?.getItemRaw?.(key)
    if (!raw) return null
    const view = raw instanceof Uint8Array ? raw : new Uint8Array(raw as ArrayBuffer)
    const normalized = view.byteOffset === 0 && view.byteLength === view.buffer.byteLength ? view : view.slice()
    return Buffer.from(normalized)
  } catch {
    return null
  }
}
