import { redirect } from '@tanstack/react-router'

import { validateShareToken } from '@/entities/share'
import { me as fetchCurrentUser } from '@/entities/user'

type MaybeSearch = string | Record<string, unknown> | null | undefined

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

export async function appBeforeLoadGuard(ctx?: any) {
  const { pathname, search } = resolveLocation(ctx)
  try {
    await fetchCurrentUser()
  } catch {
    const redirectSearch = search && search !== '?' ? search : ''
    throw redirect({
      to: '/auth/signin',
      search: {
        redirect: pathname,
        ...(redirectSearch ? { redirectSearch } : {}),
      },
    })
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

  try {
    await fetchCurrentUser()
  } catch {
    const redirectSearch = search && search !== '?' ? search : ''
    throw redirect({
      to: '/auth/signin',
      search: {
        redirect: pathname,
        ...(redirectSearch ? { redirectSearch } : {}),
      },
    })
  }
}
