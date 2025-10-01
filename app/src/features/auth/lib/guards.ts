import { redirect } from '@tanstack/react-router'

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

async function hasCurrentUser() {
  try {
    await fetchCurrentUser()
    return true
  } catch {
    return false
  }
}

export async function resolveAuthRedirect(ctx?: any): Promise<AuthRedirectTarget | null> {
  const { pathname, search } = resolveLocation(ctx)
  const authenticated = await hasCurrentUser()
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

  const authenticated = await hasCurrentUser()
  if (!authenticated) {
    throw redirect(createAuthRedirect(pathname, search))
  }
}
