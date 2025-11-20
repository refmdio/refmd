import { createMiddleware } from '@tanstack/react-start'

import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { validateShareToken } from '@/entities/share'

import { resolveAuthRedirect } from '@/features/auth/lib/guards'
import type { AuthRedirectTarget, AuthMiddlewareContext } from '@/features/auth/lib/types'

type AuthServerContext = {
  auth: AuthMiddlewareContext
}

const REFRESH_COOKIE_NAME = 'refresh_token'

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

function isAuthPath(pathname: string) {
  if (!pathname || pathname === '/') return false
  if (pathname === '/auth') return true
  return pathname.startsWith('/auth/')
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

function hasCookie(raw: string | undefined, name: string) {
  if (!raw) return false
  const target = `${name}=`
  return raw.split(';').some((part) => part.trim().startsWith(target))
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

function extractSetCookieHeaders(response: Response) {
  const headers = (response.headers as unknown as { raw?: () => Record<string, string[]> }).raw?.()
  if (headers && headers['set-cookie'] && headers['set-cookie'].length > 0) {
    return headers['set-cookie']
  }
  const single = response.headers.get('set-cookie')
  return single ? [single] : []
}

function toHeaderRecord(headers: Headers) {
  const record: Record<string, string> = {}
  headers.forEach((value, key) => {
    record[key.toLowerCase()] = value
  })
  return record
}

type DeterminedAuthState = {
  authenticated: boolean
  user: AuthMiddlewareContext['user']
  hasRefreshToken: boolean
  setCookies: string[]
}

type RefreshSessionResult = {
  accessToken?: string
  setCookies: string[]
}

async function tryRefreshSession(
  base: string,
  cookie: string,
): Promise<RefreshSessionResult | null> {
  try {
    const refreshUrl = new URL('/api/auth/refresh', base)
    const res = await fetch(refreshUrl.toString(), {
      method: 'POST',
      headers: { cookie },
      credentials: 'include',
    })
    if (!res.ok) {
      return null
    }
    let accessToken: string | undefined
    try {
      const payload = (await res.json()) as { access_token?: string }
      if (payload && typeof payload.access_token === 'string') {
        accessToken = payload.access_token
      }
    } catch {
      /* no-op */
    }
    return { accessToken, setCookies: extractSetCookieHeaders(res) }
  } catch (error) {
    console.warn('[auth-middleware] refresh request failed', error)
    return null
  }
}

async function determineAuthState(
  headers: Record<string, string>,
  apiBaseUrl?: string,
  origin?: string,
): Promise<DeterminedAuthState> {
  const cookie = headers['cookie'] ?? headers['Cookie']
  const hasRefreshToken = hasCookie(cookie, REFRESH_COOKIE_NAME)
  const base = apiBaseUrl ?? getEnv('SSR_API_BASE_URL', API_BASE_URL) ?? origin
  if (!cookie || !base) {
    return { authenticated: false, user: null, hasRefreshToken, setCookies: [] }
  }

  const meUrl = new URL('/api/auth/me', base)
  const fetchMe = async (authToken?: string) => {
    const requestHeaders: Record<string, string> = { cookie }
    if (authToken) {
      requestHeaders.authorization = `Bearer ${authToken}`
    }
    return fetch(meUrl.toString(), {
      method: 'GET',
      headers: requestHeaders,
      credentials: 'include',
    })
  }

  try {
    const res = await fetchMe()
    if (res.ok) {
      const user = (await res.json()) as AuthMiddlewareContext['user']
      return { authenticated: true, user, hasRefreshToken, setCookies: [] }
    }
    if (res.status !== 401 || !hasRefreshToken) {
      return { authenticated: false, user: null, hasRefreshToken, setCookies: [] }
    }
  } catch (error) {
    console.warn('[auth-middleware] auth state check failed', error)
    return { authenticated: false, user: null, hasRefreshToken, setCookies: [] }
  }

  const refreshResult = await tryRefreshSession(base, cookie)
  if (!refreshResult) {
    return { authenticated: false, user: null, hasRefreshToken, setCookies: [] }
  }

  if (refreshResult.accessToken) {
    try {
      const refreshed = await fetchMe(refreshResult.accessToken)
      if (refreshed.ok) {
        const user = (await refreshed.json()) as AuthMiddlewareContext['user']
        return {
          authenticated: true,
          user,
          hasRefreshToken: true,
          setCookies: refreshResult.setCookies,
        }
      }
    } catch (error) {
      console.warn('[auth-middleware] me after refresh failed', error)
    }
  }

  return {
    authenticated: false,
    user: null,
    hasRefreshToken: true,
    setCookies: refreshResult.setCookies,
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
        hasRefreshToken: false,
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
    const responseCookies: string[] = []
    const cookieHeader = headers['cookie'] ?? headers['Cookie']
    const hasRefreshFromCookie = hasCookie(cookieHeader, REFRESH_COOKIE_NAME)
    const shouldResolveAuth = !isAuthPath(currentPath)

    if (shouldResolveAuth) {
      const authState = await determineAuthState(headers, apiBaseUrl, origin)
      middlewareContext.auth.redirectChecked = true
      middlewareContext.auth.isAuthenticated = authState.authenticated
      middlewareContext.auth.user = authState.user ?? null
      middlewareContext.auth.hasRefreshToken = authState.hasRefreshToken
      if (authState.setCookies.length > 0) {
        responseCookies.push(...authState.setCookies)
      }
    } else {
      middlewareContext.auth.redirectChecked = true
      middlewareContext.auth.isAuthenticated = false
      middlewareContext.auth.user = null
      middlewareContext.auth.hasRefreshToken = hasRefreshFromCookie
    }

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

    const appendCookies = (response: Response) => {
      responseCookies.forEach((cookie) => {
        response.headers.append('set-cookie', cookie)
      })
    }

    if (!authDecision.redirect) {
      const result = await next({ context: middlewareContext })
      appendCookies(result.response)
      return result
    }

    const destination = buildRedirectUrl(origin, authDecision.redirect)
    const response = new Response(null, {
      status: 302,
      headers: {
        Location: destination,
      },
    })
    appendCookies(response)

    return {
      request,
      pathname,
      context: middlewareContext,
      response,
    }
  },
)
