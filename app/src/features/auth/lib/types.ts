import type { UserResponse } from '@/shared/api'

export type AuthRedirectTarget = {
  to: string
  search?: Record<string, unknown>
}

export type AuthMiddlewareContext = {
  redirectChecked: boolean
  redirectTarget: AuthRedirectTarget | null
  isAuthenticated: boolean
  shareToken?: string
  shareTokenValidated?: boolean
  requestHeaders?: Record<string, string>
  user?: UserResponse | null
}

export type AuthResolution = {
  redirect: AuthRedirectTarget | null
  authenticated: boolean
}
