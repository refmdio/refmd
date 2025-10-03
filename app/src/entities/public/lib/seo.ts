import { PUBLIC_BASE_URL } from '@/shared/lib/config'
import { buildOgImagePath, type OgImageVariant } from '@/shared/lib/og'

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

type OgImageFieldLimit = {
  title: number
  subtitle: number
  description: number
  badge: number
  meta: number
}

const FIELD_LIMITS: OgImageFieldLimit = {
  title: 160,
  subtitle: 120,
  description: 240,
  badge: 64,
  meta: 90,
}

export type OgImageUrlOptions = {
  variant: OgImageVariant
  title: string
  subtitle?: string
  description?: string
  badge?: string
  meta?: string
}

const normalizeField = (value: string | undefined, limit: number) => {
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed) return undefined
  if (trimmed.length <= limit) return trimmed
  return `${trimmed.slice(0, limit - 3)}...`
}

export function buildOgImageUrl(base?: string, options?: OgImageUrlOptions) {
  if (!options) {
    const fallback = '/refmd-512.png'
    const resolvedFallbackBase = base ?? resolvePublicBaseUrl()
    return resolvedFallbackBase ? `${resolvedFallbackBase}${fallback}` : fallback
  }

  const path = buildOgImagePath(options.variant)
  const params = new URLSearchParams()

  const title = normalizeField(options.title, FIELD_LIMITS.title)
  const subtitle = normalizeField(options.subtitle, FIELD_LIMITS.subtitle)
  const description = normalizeField(options.description, FIELD_LIMITS.description)
  const badge = normalizeField(options.badge, FIELD_LIMITS.badge)
  const meta = normalizeField(options.meta, FIELD_LIMITS.meta)

  if (title) params.set('title', title)
  if (subtitle) params.set('subtitle', subtitle)
  if (description) params.set('description', description)
  if (badge) params.set('badge', badge)
  if (meta) params.set('meta', meta)

  const query = params.toString()
  const resolvedBase = base ?? resolvePublicBaseUrl()
  const pathname = query ? `${path}?${query}` : path
  return resolvedBase ? `${resolvedBase}${pathname}` : pathname
}
