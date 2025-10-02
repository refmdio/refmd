import { PUBLIC_BASE_URL } from '@/shared/lib/config'

export function resolvePublicBaseUrl(): string {
  if (PUBLIC_BASE_URL && PUBLIC_BASE_URL.trim().length > 0) {
    return PUBLIC_BASE_URL.replace(/\/$/, '')
  }
  if (typeof window !== 'undefined' && window.location?.origin) {
    return window.location.origin
  }
  return ''
}

export function buildCanonicalUrl(path: string) {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  const base = resolvePublicBaseUrl()
  const url = base ? `${base}${normalizedPath}` : normalizedPath
  return { base, url }
}

export function buildOgImageUrl(base?: string) {
  const resolvedBase = base ?? resolvePublicBaseUrl()
  const fallback = '/refmd-512.png'
  if (!resolvedBase) return fallback
  return `${resolvedBase}${fallback}`
}
