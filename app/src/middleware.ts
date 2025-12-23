import { createMiddleware } from '@tanstack/react-start'

import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { validateShareToken } from '@/entities/share'

import { resolveAuthRedirect } from '@/features/auth/lib/guards'
import type { AuthRedirectTarget, AuthMiddlewareContext } from '@/features/auth/lib/types'

type AuthServerContext = {
  auth: AuthMiddlewareContext
}

const REFRESH_COOKIE_NAME = 'refresh_token'

const IS_DEV = process.env.NODE_ENV !== 'production'

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
  ...(IS_DEV ? ['.ts', '.tsx'] : []),
])

const PUBLIC_PATHS = new Set([
  '/favicon.ico',
  '/manifest.json',
  '/robots.txt',
])

const PUBLIC_PREFIXES = [
  '/_',
  '/api',
  '/u/',
  '/w/',
  '/assets',
  ...(IS_DEV ? ['/@', '/__vite', '/node_modules', '/src'] : []),
]
const AUTH_REQUEST_TIMEOUT_MS = 5000
const AUTH_DEFER_WINDOW_MS = 30_000

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

function scrubRequestHeaders(auth: AuthMiddlewareContext) {
  if ('requestHeaders' in auth) {
    delete auth.requestHeaders
  }
}

type ParsedSetCookie = {
  name: string
  value: string
  remove: boolean
  path?: string | null
  domain?: string | null
}

function parseSetCookie(entry: string): ParsedSetCookie | null {
  const segments = entry.split(';')
  if (segments.length === 0) {
    return null
  }
  const pair = segments[0].trim()
  const eqIdx = pair.indexOf('=')
  if (eqIdx === -1) return null
  const name = pair.slice(0, eqIdx).trim()
  if (!name) return null
  const value = pair.slice(eqIdx + 1).trim()
  let remove = value.length === 0
  let path: string | null | undefined
  let domain: string | null | undefined
  for (let i = 1; i < segments.length; i += 1) {
    const segment = segments[i].trim()
    if (!segment) continue
    const eqIdx = segment.indexOf('=')
    const key = (eqIdx === -1 ? segment : segment.slice(0, eqIdx)).trim().toLowerCase()
    const rawValue = eqIdx === -1 ? '' : segment.slice(eqIdx + 1).trim()
    if (key === 'max-age') {
      const parsed = Number.parseInt(rawValue, 10)
      if (Number.isFinite(parsed) && parsed <= 0) {
        remove = true
      }
      continue
    }
    if (key === 'expires') {
      const expiresAt = new Date(rawValue)
      if (!Number.isNaN(expiresAt.valueOf()) && expiresAt.valueOf() <= Date.now()) {
        remove = true
      }
      continue
    }
    if (key === 'path') {
      path = rawValue.length > 0 ? rawValue : '/'
      continue
    }
    if (key === 'domain') {
      domain = rawValue.length > 0 ? rawValue.toLowerCase() : undefined
      continue
    }
  }
  return { name, value, remove, path, domain }
}

type CookieEntry = {
  name: string
  value: string
  path?: string | null
  domain?: string | null
}

function parseCookieHeader(header?: string) {
  const jar: CookieEntry[] = []
  if (!header) {
    return jar
  }
  header.split(';').forEach((part) => {
    const trimmed = part.trim()
    if (!trimmed) return
    const eqIdx = trimmed.indexOf('=')
    if (eqIdx === -1) return
    const name = trimmed.slice(0, eqIdx).trim()
    if (!name) return
    const value = trimmed.slice(eqIdx + 1).trim()
    jar.push({ name, value })
  })
  return jar
}

function entriesMatch(entry: CookieEntry, target: ParsedSetCookie) {
  if (entry.name !== target.name) return false

  const entryPath = entry.path ?? null
  const targetPath = target.path ?? null
  const pathMatches = entryPath === null || targetPath === null ? true : entryPath === targetPath

  const entryDomain = entry.domain ?? null
  const targetDomain = target.domain ?? null
  const domainMatches = entryDomain === null || targetDomain === null ? true : entryDomain === targetDomain

  return pathMatches && domainMatches
}

function mergeCookieHeader(existing: string | undefined, updates: string[]) {
  if (updates.length === 0) return existing
  const jar = parseCookieHeader(existing)
  let mutated = false

  updates.forEach((setCookie) => {
    const parsed = parseSetCookie(setCookie)
    if (!parsed) return
    if (parsed.remove) {
      let removed = false
      for (let i = jar.length - 1; i >= 0; i -= 1) {
        if (entriesMatch(jar[i], parsed)) {
          jar.splice(i, 1)
          removed = true
        }
      }
      if (!removed && parsed.path == null && parsed.domain == null) {
        // No path/domain info means remove all cookies with the same name
        for (let i = jar.length - 1; i >= 0; i -= 1) {
          if (jar[i].name === parsed.name) {
            jar.splice(i, 1)
            removed = true
          }
        }
      }
      mutated = mutated || removed
    } else {
      const existingIndex = jar.findIndex((entry) => entriesMatch(entry, parsed))
      const newEntry: CookieEntry = {
        name: parsed.name,
        value: parsed.value,
        path: parsed.path ?? null,
        domain: parsed.domain ?? null,
      }
      if (existingIndex >= 0) {
        jar[existingIndex] = newEntry
      } else {
        jar.push(newEntry)
      }
      mutated = true
    }
  })

  if (!mutated) return existing
  if (jar.length === 0) return undefined
  return jar.map((entry) => `${entry.name}=${entry.value}`).join('; ')
}

function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit = {}, timeoutMs = AUTH_REQUEST_TIMEOUT_MS) {
  const controller = new AbortController()
  const finalInit: RequestInit = { ...init }
  if (!finalInit.signal) {
    finalInit.signal = controller.signal
  }
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  return fetch(input, finalInit).finally(() => {
    clearTimeout(timer)
  })
}

type DeterminedAuthState = {
  authenticated: boolean
  user: AuthMiddlewareContext['user']
  hasRefreshToken: boolean
  setCookies: string[]
  resolved: boolean
}

type RefreshSessionResult = {
  accessToken?: string
  setCookies: string[]
  status: 'success' | 'unauthorized' | 'error'
}

async function tryRefreshSession(
  base: string,
  cookie: string,
): Promise<RefreshSessionResult> {
  try {
    const refreshUrl = new URL('/api/auth/refresh', base)
    const res = await fetchWithTimeout(refreshUrl.toString(), {
      method: 'POST',
      headers: { cookie },
      credentials: 'include',
    })
    const setCookies = extractSetCookieHeaders(res)
    if (!res.ok) {
      const status = res.status === 401 ? 'unauthorized' : 'error'
      return { status, setCookies }
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
    return { accessToken, setCookies, status: 'success' }
  } catch (error) {
    console.warn('[auth-middleware] refresh request failed', error)
    return { status: 'error', setCookies: [] }
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
    return { authenticated: false, user: null, hasRefreshToken, setCookies: [], resolved: true }
  }

  const meUrl = new URL('/api/auth/me', base)
  const fetchMe = async (authToken?: string) => {
    const requestHeaders: Record<string, string> = { cookie }
    if (authToken) {
      requestHeaders.authorization = `Bearer ${authToken}`
    }
    return fetchWithTimeout(meUrl.toString(), {
      method: 'GET',
      headers: requestHeaders,
      credentials: 'include',
    })
  }

  try {
    const res = await fetchMe()
    if (res.ok) {
      const user = (await res.json()) as AuthMiddlewareContext['user']
      return { authenticated: true, user, hasRefreshToken, setCookies: [], resolved: true }
    }
    if (res.status !== 401) {
      return {
        authenticated: false,
        user: null,
        hasRefreshToken,
        setCookies: [],
        resolved: hasRefreshToken ? false : true,
      }
    }
    if (!hasRefreshToken) {
      return { authenticated: false, user: null, hasRefreshToken, setCookies: [], resolved: true }
    }
  } catch (error) {
    console.warn('[auth-middleware] auth state check failed', error)
    return { authenticated: false, user: null, hasRefreshToken, setCookies: [], resolved: false }
  }

  const refreshResult = await tryRefreshSession(base, cookie)

  if (refreshResult.status === 'error') {
    return {
      authenticated: false,
      user: null,
      hasRefreshToken,
      setCookies: refreshResult.setCookies,
      resolved: false,
    }
  }

  if (refreshResult.status === 'unauthorized') {
    return {
      authenticated: false,
      user: null,
      hasRefreshToken: false,
      setCookies: refreshResult.setCookies,
      resolved: true,
    }
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
          resolved: true,
        }
      }
      if (refreshed.status === 401) {
        return {
          authenticated: false,
          user: null,
          hasRefreshToken: false,
          setCookies: refreshResult.setCookies,
          resolved: true,
        }
      }
      return {
        authenticated: false,
        user: null,
        hasRefreshToken: true,
        setCookies: refreshResult.setCookies,
        resolved: false,
      }
    } catch (error) {
      console.warn('[auth-middleware] me after refresh failed', error)
      return {
        authenticated: false,
        user: null,
        hasRefreshToken: true,
        setCookies: refreshResult.setCookies,
        resolved: false,
      }
    }
  }

  return {
    authenticated: false,
    user: null,
    hasRefreshToken: true,
    setCookies: refreshResult.setCookies,
    resolved: false,
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
        authResolved: false,
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
    Object.defineProperty(middlewareContext.auth, 'requestHeaders', {
      value: headers,
      writable: true,
      configurable: true,
      enumerable: false,
    })
    const apiBaseUrl = getEnv('SSR_API_BASE_URL', API_BASE_URL)
    const responseCookies: string[] = []
    let cookieHeader: string | undefined = headers['cookie'] ?? headers['Cookie']

    const authState = await determineAuthState(headers, apiBaseUrl, origin)
    middlewareContext.auth.redirectChecked = true
    middlewareContext.auth.authResolved = authState.resolved
    middlewareContext.auth.isAuthenticated = authState.authenticated
    middlewareContext.auth.user = authState.user ?? null
    middlewareContext.auth.hasRefreshToken = authState.hasRefreshToken
    if (!authState.resolved && authState.hasRefreshToken) {
      middlewareContext.auth.deferDurationMs = AUTH_DEFER_WINDOW_MS
      delete middlewareContext.auth.deferUntil
    } else {
      delete middlewareContext.auth.deferUntil
      delete middlewareContext.auth.deferDurationMs
    }

    if (authState.setCookies.length > 0) {
      responseCookies.push(...authState.setCookies)
      const merged = mergeCookieHeader(cookieHeader, authState.setCookies)
      cookieHeader = merged
      if (merged) {
        headers['cookie'] = merged
      } else {
        delete headers['cookie']
      }
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

    const finalize = () => {
      scrubRequestHeaders(middlewareContext.auth)
    }

    try {
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
    } finally {
      finalize()
    }
  },
)
