import type { UserResponse } from '@/shared/api'

export type AuthRedirectTarget = {
  to: string
  search?: Record<string, string | string[] | undefined>
}

export type AuthMiddlewareContext = {
  redirectChecked: boolean
  redirectTarget: AuthRedirectTarget | null
  isAuthenticated: boolean
  authResolved?: boolean
  deferUntil?: number
  deferDurationMs?: number
  shareToken?: string
  shareTokenValidated?: boolean
  requestHeaders?: Record<string, string>
  hasRefreshToken?: boolean
  user?: UserResponse | null
}

export type AuthResolution = {
  redirect: AuthRedirectTarget | null
  authenticated: boolean
}
