import { createMiddleware } from '@tanstack/react-start'

import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { validateShareToken } from '@/entities/share'

import { resolveAuthRedirect } from '@/features/auth/lib/guards'
import type { AuthRedirectTarget, AuthMiddlewareContext } from '@/features/auth/lib/types'

type AuthServerContext = {
  auth: AuthMiddlewareContext
}

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

const PUBLIC_PREFIXES = ['/_', '/api', '/share', '/u/', '/w/', '/assets']

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
  for (const [key, value] of Object.entries(target.search ?? {})) {
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

function toHeaderRecord(headers: Headers) {
  const record: Record<string, string> = {}
  headers.forEach((value, key) => {
    record[key.toLowerCase()] = value
  })
  return record
}

async function determineAuthState(
  headers: Record<string, string>,
  apiBaseUrl?: string,
  origin?: string,
): Promise<{ authenticated: boolean; user: AuthMiddlewareContext['user'] }> {
  const cookie = headers['cookie'] ?? headers['Cookie']
  if (!cookie) {
    return { authenticated: false, user: null }
  }
  const base = apiBaseUrl ?? getEnv('SSR_API_BASE_URL', API_BASE_URL) ?? origin
  if (!base) {
    return { authenticated: false, user: null }
  }
  try {
    const meUrl = new URL('/api/auth/me', base)
    const res = await fetch(meUrl.toString(), {
      method: 'GET',
      headers: { cookie },
      credentials: 'include',
    })
    if (!res.ok) {
      return { authenticated: false, user: null }
    }
    const user = (await res.json()) as AuthMiddlewareContext['user']
    return { authenticated: true, user }
  } catch (error) {
    console.warn('[auth-middleware] auth state check failed', error)
    return { authenticated: false, user: null }
  }
}

export const authMiddleware = createMiddleware().server<AuthServerContext>(
  async ({ request, next, pathname }) => {
    const requestUrl = new URL(request.url)
    const { pathname: currentPath, searchParams, origin } = requestUrl

    if (shouldBypass(currentPath)) {
      return next()
    }

    const middlewareContext: AuthServerContext = {
      auth: {
        redirectChecked: false,
        redirectTarget: null,
        isAuthenticated: false,
      },
    }

    if (isDocumentPath(currentPath)) {
      const shareToken = searchParams.get('token')?.trim()
      if (shareToken) {
        try {
          await validateShareToken(shareToken)
          middlewareContext.auth.shareToken = shareToken
          middlewareContext.auth.shareTokenValidated = true
        } catch (error) {
          console.warn('[auth-middleware] share token validation failed', error)
        }
      }
    }

    const headers = toHeaderRecord(request.headers)
    middlewareContext.auth.requestHeaders = headers
    const apiBaseUrl = getEnv('SSR_API_BASE_URL', API_BASE_URL)

    const authState = await determineAuthState(headers, apiBaseUrl, origin)
    middlewareContext.auth.redirectChecked = true
    middlewareContext.auth.isAuthenticated = authState.authenticated
    middlewareContext.auth.user = authState.user ?? null

    const authDecision = await resolveAuthRedirect({
      auth: middlewareContext.auth,
      location: { pathname: currentPath, search: requestUrl.search },
      search: paramsToObject(searchParams),
      headers,
      origin,
      apiBaseUrl,
      request: { headers },
      event: { node: { req: { headers } } },
    })

    middlewareContext.auth.redirectTarget = authDecision.redirect
    middlewareContext.auth.isAuthenticated = authDecision.authenticated

    if (!authDecision.redirect) {
      return next({ context: middlewareContext })
    }

    const destination = buildRedirectUrl(origin, authDecision.redirect)

    return {
      request,
      pathname,
      context: middlewareContext,
      response: new Response(null, {
        status: 302,
        headers: {
          Location: destination,
        },
      }),
    }
  },
)
