import { getGlobalStartContext } from '@tanstack/start-client-core'

import { API_BASE_URL, getEnv } from '@/shared/lib/config'

import { OpenAPI } from './client'

// Configure generated client at app startup
const resolvedBase = typeof window === 'undefined' ? getEnv('SSR_API_BASE_URL', API_BASE_URL) : API_BASE_URL

OpenAPI.BASE = resolvedBase
OpenAPI.WITH_CREDENTIALS = true
OpenAPI.CREDENTIALS = 'include'
OpenAPI.HEADERS = async () => {
  if (typeof window !== 'undefined') {
    return {}
  }

  try {
    const context = getGlobalStartContext()
    const authContext = (context as { auth?: { requestHeaders?: Record<string, string> } } | undefined)?.auth
    const requestHeaders = authContext?.requestHeaders ?? (context as { requestHeaders?: Record<string, string> } | undefined)?.requestHeaders

    if (!requestHeaders) {
      return {}
    }

    const headers: Record<string, string> = {}
    const cookie = requestHeaders.cookie ?? requestHeaders.Cookie
    if (cookie) {
      headers.cookie = cookie
    }

    const forwardedProto = requestHeaders['x-forwarded-proto']
    if (forwardedProto) {
      headers['x-forwarded-proto'] = forwardedProto
    }

    const forwardedHost = requestHeaders['x-forwarded-host'] ?? requestHeaders.host
    if (forwardedHost) {
      headers['x-forwarded-host'] = forwardedHost
    }

    return headers
  } catch {
    return {}
  }
}
