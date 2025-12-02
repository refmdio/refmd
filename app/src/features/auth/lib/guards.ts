import type { QueryClient } from '@tanstack/react-query'
import { redirect } from '@tanstack/react-router'

import type { UserResponse } from '@/shared/api'

import { validateShareToken } from '@/entities/share'
import { me as fetchCurrentUser, userKeys } from '@/entities/user'

import { getRuntimeAuthContext } from './runtime-context'
import type { AuthMiddlewareContext, AuthRedirectTarget, AuthResolution } from './types'

// Re-export so callers can keep importing from this module
export type { AuthRedirectTarget, AuthMiddlewareContext, AuthResolution } from './types'

type MaybeSearch = string | Record<string, unknown> | null | undefined

function getMiddlewareAuthContext(ctx: any): AuthMiddlewareContext | undefined {
  const candidates = [
    ctx?.serverContext?.auth,
    ctx?.context?.auth,
    ctx?.auth,
  ]

  for (const candidate of candidates) {
    if (candidate && typeof candidate === 'object') {
      return candidate as AuthMiddlewareContext
    }
  }
  if (typeof window !== 'undefined') {
    const runtimeContext = getRuntimeAuthContext()
    if (runtimeContext) {
      return runtimeContext
    }
  }
  return undefined
}

function resolveDeferDeadline(auth: AuthMiddlewareContext): number | undefined {
  if (typeof auth.deferUntil === 'number') {
    return auth.deferUntil
  }
  if (typeof auth.deferDurationMs === 'number') {
    const deadline = Date.now() + auth.deferDurationMs
    auth.deferUntil = deadline
    delete auth.deferDurationMs
    return deadline
  }
  return undefined
}

function shouldDeferAuthDecision(ctx: any): boolean {
  const auth = getMiddlewareAuthContext(ctx)
  if (!auth) return false
  if (auth.authResolved === false && auth.hasRefreshToken === true) {
    const deadline = resolveDeferDeadline(auth)
    if (typeof deadline === 'number') {
      const now = Date.now()
      if (now > deadline) {
        auth.authResolved = true
        delete auth.deferUntil
        delete auth.deferDurationMs
        return false
      }
      return true
    }
    return true
  }
  return false
}

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
  const locationSource = ctx?.location ?? ctx?.serverContext?.location ?? null
  const fallbackPath = typeof window !== 'undefined' ? window.location.pathname : '/'
  const fallbackSearch = typeof window !== 'undefined' ? window.location.search : ''
  const pathnameCandidate = locationSource?.pathname ?? ctx?.pathname
  const pathname = typeof pathnameCandidate === 'string' && pathnameCandidate.length > 0 ? pathnameCandidate : fallbackPath

  const tokenFromLocation = extractTokenFromObject(locationSource?.search ?? ctx?.search)
  if (tokenFromLocation) {
    return {
      pathname,
      search: `?token=${encodeURIComponent(tokenFromLocation)}`,
      tokenOverride: tokenFromLocation,
    }
  }

  const searchCandidate = normalizeSearch(locationSource?.search ?? ctx?.search)
  const search = searchCandidate.length > 0 ? searchCandidate : fallbackSearch
  return { pathname, search, tokenOverride: null as string | null }
}

function extractShareToken(ctx: any, search: string, tokenOverride: string | null) {
  if (tokenOverride) return tokenOverride
  const tokenFromCtx = extractTokenFromObject(ctx?.search ?? ctx?.serverContext?.search)
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

function isAuthRoute(pathname: string) {
  if (!pathname || pathname === '/') return false
  if (pathname === '/auth') return true
  return pathname.startsWith('/auth/')
}

function getCachedUser(ctx?: any): UserResponse | null {
  const queryClient = ctx?.context?.queryClient as QueryClient | undefined
  if (!queryClient) return null
  const cached = queryClient.getQueryData(userKeys.me()) as UserResponse | undefined
  return cached ?? null
}

async function hasCurrentUser(ctx?: any) {
  if (shouldDeferAuthDecision(ctx)) {
    return true
  }
  const middlewareAuth = getMiddlewareAuthContext(ctx)
  if (middlewareAuth?.redirectChecked) {
    if (middlewareAuth.user) {
      return true
    }
    if (middlewareAuth.isAuthenticated) {
      return true
    }
    if (middlewareAuth.authResolved === true) {
      return false
    }
    if (middlewareAuth.authResolved === false) {
      return false
    }
    if (middlewareAuth.hasRefreshToken && middlewareAuth.authResolved === undefined) {
      return true
    }
  }

  const cachedUser = getCachedUser(ctx)
  if (cachedUser) {
    return true
  }
  try {
    await fetchCurrentUser()
    return true
  } catch {
    return false
  }
}

export async function resolveAuthRedirect(ctx?: any): Promise<AuthResolution> {
  const { pathname, search, tokenOverride } = resolveLocation(ctx)
  const middlewareAuth = getMiddlewareAuthContext(ctx)
  const shareToken = extractShareToken(ctx, search, tokenOverride)

  let shareTokenValid = false
  if (shareToken) {
    if (middlewareAuth?.shareTokenValidated && middlewareAuth.shareToken === shareToken) {
      shareTokenValid = true
    } else {
      try {
        await validateShareToken(shareToken)
        shareTokenValid = true
      } catch {
        // fall through to auth checks when validation fails
      }
    }
  }

  if (shouldDeferAuthDecision(ctx)) {
    return { redirect: null, authenticated: !!middlewareAuth?.isAuthenticated }
  }

  const authenticated = await hasCurrentUser(ctx)
  if (!authenticated) {
    if (isAuthRoute(pathname)) {
      return { redirect: null, authenticated: false }
    }
    if (shareTokenValid) {
      return { redirect: null, authenticated: false }
    }
    return { redirect: createAuthRedirect(pathname, search), authenticated: false }
  }
  if (isAuthRoute(pathname)) {
    return { redirect: { to: '/dashboard' }, authenticated }
  }
  return { redirect: null, authenticated }
}

export async function appBeforeLoadGuard(ctx?: any) {
  const { redirect: target } = await resolveAuthRedirect(ctx)
  if (target) {
    throw redirect(target)
  }
}

export const requireAuthGuard = appBeforeLoadGuard

export async function authPageGuard(ctx?: any) {
  const { pathname } = resolveLocation(ctx)
  if (!isAuthRoute(pathname)) return
  const { redirect: target, authenticated } = await resolveAuthRedirect(ctx)
  if (target) {
    throw redirect(target)
  }
  if (authenticated) {
    throw redirect({ to: '/dashboard' })
  }
}

export async function documentBeforeLoadGuard(ctx?: any) {
  const { pathname, search, tokenOverride } = resolveLocation(ctx)
  const shareToken = extractShareToken(ctx, search, tokenOverride)
  const middlewareAuth = getMiddlewareAuthContext(ctx)

  if (
    shareToken &&
    middlewareAuth?.shareTokenValidated &&
    middlewareAuth.shareToken === shareToken
  ) {
    return
  }

  if (shareToken) {
    try {
      await validateShareToken(shareToken)
      return
    } catch {
      // fall through to auth guard when token validation or access check fails
    }
  }

  if (shouldDeferAuthDecision(ctx)) {
    return
  }

  const authenticated = await hasCurrentUser(ctx)
  if (!authenticated) {
    throw redirect(createAuthRedirect(pathname, search))
  }
}
