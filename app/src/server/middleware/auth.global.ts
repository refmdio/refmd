import { defineEventHandler, getRequestURL, sendRedirect } from 'h3'

import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { validateShareToken } from '@/entities/share'

import { resolveAuthRedirect } from '@/features/auth/lib/guards'
import type { AuthRedirectTarget } from '@/features/auth/lib/guards'

const STATIC_EXTENSIONS = new Set([
  '.apng',
  '.avif',
  '.css',
  '.gif',
  '.ico',
  '.jpg',
  '.jpeg',
  '.js',
  '.json',
  '.map',
  '.mjs',
  '.pdf',
  '.png',
  '.svg',
  '.txt',
  '.webmanifest',
  '.webp',
  '.wasm',
])

const PUBLIC_PATHS = new Set([
  '/favicon.ico',
  '/manifest.json',
  '/robots.txt',
])

const PUBLIC_PREFIXES = ['/_', '/api', '/auth', '/share', '/u/', '/assets']

function hasStaticExtension(pathname: string) {
  const idx = pathname.lastIndexOf('.')
  if (idx === -1) return false
  return STATIC_EXTENSIONS.has(pathname.slice(idx))
}

function shouldBypass(pathname: string) {
  if (PUBLIC_PATHS.has(pathname)) return true
  if (hasStaticExtension(pathname)) return true
  for (const prefix of PUBLIC_PREFIXES) {
    if (pathname.startsWith(prefix)) {
      return true
    }
  }
  return false
}

function isDocumentPath(pathname: string) {
  return pathname.startsWith('/document/')
}

function paramsToObject(params: URLSearchParams) {
  const result: Record<string, string | string[]> = {}
  for (const [key, value] of params.entries()) {
    if (key in result) {
      const existing = result[key]
      if (Array.isArray(existing)) {
        existing.push(value)
      } else {
        result[key] = [existing, value]
      }
    } else {
      result[key] = value
    }
  }
  return result
}

function buildRedirectUrl(origin: string, target: AuthRedirectTarget) {
  const url = new URL(target.to, origin)
  const searchParams = new URLSearchParams()
  for (const [key, value] of Object.entries(target.search)) {
    if (value === undefined || value === null) continue
    if (Array.isArray(value)) {
      value.forEach((item) => searchParams.append(key, String(item)))
    } else {
      searchParams.set(key, String(value))
    }
  }
  const search = searchParams.toString()
  url.search = search.length > 0 ? `?${search}` : ''
  return url.toString()
}

export default defineEventHandler(async (event) => {
  const requestUrl = getRequestURL(event)
  const { pathname, searchParams, origin } = requestUrl

  if (shouldBypass(pathname)) {
    return
  }

  if (isDocumentPath(pathname)) {
    const shareToken = searchParams.get('token')?.trim()
    if (shareToken) {
      try {
        await validateShareToken(shareToken)
        return
      } catch (error) {
        console.warn('[auth-middleware] share token validation failed', error)
      }
    }
  }

  const apiBaseUrl = getEnv('SSR_API_BASE_URL', API_BASE_URL)

  const redirectTarget = await resolveAuthRedirect({
    location: { pathname, search: requestUrl.search },
    search: paramsToObject(searchParams),
    headers: event.node.req.headers,
    origin,
    apiBaseUrl,
    event,
  })

  if (!redirectTarget) {
    return
  }

  const destination = buildRedirectUrl(origin, redirectTarget)

  return sendRedirect(event, destination, 302)
})
