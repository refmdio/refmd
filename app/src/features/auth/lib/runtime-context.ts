import { getGlobalStartContext } from '@tanstack/start-client-core'

import type { AuthMiddlewareContext } from './types'

let cachedContext: AuthMiddlewareContext | null | undefined

function resolveContext(): AuthMiddlewareContext | null {
  if (typeof window === 'undefined') {
    return null
  }
  if (cachedContext !== undefined) {
    return cachedContext
  }
  try {
    const context = getGlobalStartContext() as { auth?: AuthMiddlewareContext } | undefined
    cachedContext = context?.auth ?? null
  } catch {
    // Swallow transient errors but allow future calls to retry.
    cachedContext = undefined
    return null
  }
  return cachedContext
}

export function getRuntimeAuthContext(): AuthMiddlewareContext | null {
  return resolveContext()
}

export function updateRuntimeAuthContext(
  updater: (ctx: AuthMiddlewareContext) => void,
): void {
  const ctx = resolveContext()
  if (!ctx) return
  updater(ctx)
}

export function resetRuntimeAuthContextCache() {
  cachedContext = undefined
}
