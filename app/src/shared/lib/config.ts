export function getEnv(name: string, fallback?: string): string {
  const rt = (typeof window !== 'undefined' ? (window as any).__ENV__?.[name] : undefined) as string | undefined
  if (rt !== undefined && rt !== null && String(rt).trim() !== '') return String(rt)
  const v = (import.meta as any).env?.[name] as string | undefined
  return v ?? fallback ?? ''
}

// API base URL: prefer runtime (window.__ENV__), otherwise use build-time Vite env
export const API_BASE_URL = getEnv('VITE_API_BASE_URL', '')

// Derived Yjs WebSocket server URL (ws(s)://<api-origin>/yjs)
export const YJS_SERVER_URL = (() => {
  if (!API_BASE_URL) return ''
  const u = new URL(API_BASE_URL)
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${u.toString().replace(/\/$/, '')}/api/yjs`
})()
