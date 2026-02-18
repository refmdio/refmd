/**
 * DSK Session — sessionStorage UMK for rememberMe=false
 *
 * Stores UMK in sessionStorage (persists until tab close) when the user
 * doesn't want to persist their session across browser restarts.
 *
 * Security note: sessionStorage is isolated per tab and origin.
 * XSS is considered a fatal breach; CSP is the primary defense.
 */

import { base64UrlEncode, base64UrlDecode } from './encoding'

const SESSION_UMK_KEY = 'refmd-session-umk'

interface SessionUmkData {
  umk: string // base64url encoded
  userId: string
}

/**
 * Store UMK in sessionStorage (for rememberMe=false)
 */
export function storeSessionUmk(umk: Uint8Array, userId: string): void {
  const data: SessionUmkData = {
    umk: base64UrlEncode(umk),
    userId,
  }
  sessionStorage.setItem(SESSION_UMK_KEY, JSON.stringify(data))
}

/**
 * Load UMK from sessionStorage
 *
 * @returns UMK and userId if found and valid, null otherwise
 */
export function loadSessionUmk(): { umk: Uint8Array; userId: string } | null {
  const raw = sessionStorage.getItem(SESSION_UMK_KEY)
  if (!raw) {
    return null
  }

  try {
    const data: SessionUmkData = JSON.parse(raw)
    if (!data.umk || !data.userId) {
      return null
    }
    return {
      umk: base64UrlDecode(data.umk),
      userId: data.userId,
    }
  } catch {
    return null
  }
}

/**
 * Clear UMK from sessionStorage
 */
export function clearSessionUmk(): void {
  sessionStorage.removeItem(SESSION_UMK_KEY)
}
