import { redirect } from '@tanstack/react-router'

import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { validateShareToken } from '@/entities/share'
import { me as fetchCurrentUser } from '@/entities/user'

type MaybeSearch = string | Record<string, unknown> | null | undefined

export type AuthRedirectTarget = {
  to: string
  search: {
    redirect: string
    redirectSearch?: string
  }
}

const SSR_AUTH_ENDPOINT = '/api/auth/me'

function normalizeSearch(value: MaybeSearch): string {
  if (typeof value === 'string') return value
  return ''
}

function extractTokenFromObject(value: MaybeSearch): string | null {
  if (value && typeof value === 'object' && 'token' in value) {
    const token = (value as Record<string, unknown>).token
    if (typeof token === 'string' && token.trim().length > 0) {
      return token
    }
  }
  return null
}

function resolveLocation(ctx: any) {
  const fallbackPath = typeof window !== 'undefined' ? window.location.pathname : '/'
  const fallbackSearch = typeof window !== 'undefined' ? window.location.search : ''
  const pathnameCandidate = ctx?.location?.pathname
  const pathname = typeof pathnameCandidate === 'string' && pathnameCandidate.length > 0 ? pathnameCandidate : fallbackPath

  const tokenFromLocation = extractTokenFromObject(ctx?.location?.search)
  if (tokenFromLocation) {
    return {
      pathname,
      search: `?token=${encodeURIComponent(tokenFromLocation)}`,
      tokenOverride: tokenFromLocation,
    }
  }

  const searchCandidate = normalizeSearch(ctx?.location?.search)
  const search = searchCandidate.length > 0 ? searchCandidate : fallbackSearch
  return { pathname, search, tokenOverride: null as string | null }
}

function extractShareToken(ctx: any, search: string, tokenOverride: string | null) {
  if (tokenOverride) return tokenOverride
  const tokenFromCtx = extractTokenFromObject(ctx?.search)
  if (tokenFromCtx) return tokenFromCtx
  if (!search) return null
  try {
    const sp = new URLSearchParams(search)
    return sp.get('token')
  } catch {
    return null
  }
}

function createAuthRedirect(pathname: string, search: string): AuthRedirectTarget {
  const redirectSearch = search && search !== '?' ? search : ''
  const searchParams: AuthRedirectTarget['search'] = { redirect: pathname }
  if (redirectSearch) {
    searchParams.redirectSearch = redirectSearch
  }
  return {
    to: '/auth/signin',
    search: searchParams,
  }
}

function resolveCookieHeader(ctx: any): string | null {
  const candidates = [ctx?.headers, ctx?.request?.headers, ctx?.event?.node?.req?.headers]

  for (const candidate of candidates) {
    if (!candidate) continue
    if (typeof candidate === 'string' && candidate.trim().length > 0) {
      return candidate
    }
    if (Array.isArray(candidate)) {
      const merged = candidate.filter(Boolean).join('; ')
      if (merged.trim().length > 0) return merged
    }
    if (typeof candidate === 'object') {
      const value = (candidate as Record<string, string | string[] | undefined>).cookie
      if (typeof value === 'string' && value.trim().length > 0) {
        return value
      }
      if (Array.isArray(value)) {
        const merged = value.filter(Boolean).join('; ')
        if (merged.trim().length > 0) return merged
      }
    }
  }

  return null
}

function resolveApiBase(ctx: any): string {
  const fromCtx = typeof ctx?.apiBaseUrl === 'string' ? ctx.apiBaseUrl.trim() : ''
  if (fromCtx.length > 0) return fromCtx

  const envBase = getEnv('SSR_API_BASE_URL', API_BASE_URL)
  if (envBase && envBase.trim().length > 0) {
    return envBase.trim()
  }

  const fromOrigin = typeof ctx?.origin === 'string' ? ctx.origin.trim() : ''
  return fromOrigin
}

async function hasCurrentUserRemote(ctx: any, cookieHeader: string | null) {
  if (!cookieHeader || typeof fetch === 'undefined') return false

  const base = resolveApiBase(ctx)
  if (!base || base.length === 0) return false

  try {
    const endpoint = new URL(SSR_AUTH_ENDPOINT, base)
    const res = await fetch(endpoint.toString(), {
      method: 'GET',
      credentials: 'include',
      headers: {
        cookie: cookieHeader,
      },
    })
    return res.ok
  } catch (error) {
    console.warn('[auth] remote auth check failed', error)
    return false
  }
}

async function hasCurrentUserFallback() {
  try {
    await fetchCurrentUser()
    return true
  } catch {
    return false
  }
}

async function hasCurrentUser(ctx?: any) {
  const isServer = typeof window === 'undefined'
  const cookieHeader = resolveCookieHeader(ctx)
  if (cookieHeader) {
    const authenticated = await hasCurrentUserRemote(ctx, cookieHeader)
    if (authenticated) return true
  }

  if (isServer) {
    if (!ctx?.event) {
      // SSR beforeLoad (no Nitro event) relies on middleware that already handled auth
      return true
    }
    return false
  }

  return hasCurrentUserFallback()
}

export async function resolveAuthRedirect(ctx?: any): Promise<AuthRedirectTarget | null> {
  const { pathname, search } = resolveLocation(ctx)
  const authenticated = await hasCurrentUser(ctx)
  if (!authenticated) {
    return createAuthRedirect(pathname, search)
  }
  return null
}

export async function appBeforeLoadGuard(ctx?: any) {
  const result = await resolveAuthRedirect(ctx)
  if (result) {
    throw redirect(result)
  }
}

export async function documentBeforeLoadGuard(ctx?: any) {
  const { pathname, search, tokenOverride } = resolveLocation(ctx)
  const shareToken = extractShareToken(ctx, search, tokenOverride)
  if (shareToken) {
    try {
      await validateShareToken(shareToken)
      return
    } catch {
      // fall through to auth guard when token validation or access check fails
    }
  }

  const authenticated = await hasCurrentUser(ctx)
  if (!authenticated) {
    throw redirect(createAuthRedirect(pathname, search))
  }
}
