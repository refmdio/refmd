export function getEnv(name: string, fallback?: string): string {
  const rt = (typeof window !== 'undefined' ? (window as any).__ENV__?.[name] : undefined) as string | undefined
  if (rt !== undefined && rt !== null && String(rt).trim() !== '') return String(rt)
  if (typeof process !== 'undefined' && typeof process.env !== 'undefined') {
    const fromProcess = process.env[name] as string | undefined
    if (fromProcess !== undefined && fromProcess !== null && String(fromProcess).trim() !== '') {
      return String(fromProcess)
    }
  }
  const v = (import.meta as any).env?.[name] as string | undefined
  return v ?? fallback ?? ''
}

// API base URL: prefer runtime (window.__ENV__), otherwise use build-time Vite env
export const API_BASE_URL = getEnv('VITE_API_BASE_URL', '')

// Public site base URL (used for SEO canonical/OG tags)
export const PUBLIC_BASE_URL = getEnv('VITE_PUBLIC_BASE_URL', '')

// Derived Yjs WebSocket server URL (ws(s)://<api-origin>/yjs)
export const YJS_SERVER_URL = (() => {
  if (!API_BASE_URL) return ''
  const u = new URL(API_BASE_URL)
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${u.toString().replace(/\/$/, '')}/api/yjs`
})()
