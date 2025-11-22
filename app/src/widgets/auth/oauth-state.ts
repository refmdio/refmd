export type RedirectSearchParams = Record<string, string | string[]>

export type OAuthStatePayload = {
  nonce: string
  redirect?: string
  redirectSearch?: RedirectSearchParams
  rememberMe?: boolean
}

const STORAGE_KEY_PREFIX = 'refmd.oauth.state.'
const LEGACY_GITHUB_STATE_STORAGE_KEY = 'refmd.github.oauth.state'

function storageKey(provider: string) {
  return `${STORAGE_KEY_PREFIX}${provider}`
}

function normalizeRedirectSearchValue(value: unknown): RedirectSearchParams | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined
  const result: RedirectSearchParams = {}
  for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
    if (typeof raw === 'string') {
      result[key] = raw
      continue
    }
    if (Array.isArray(raw)) {
      const filtered = raw.filter((item): item is string => typeof item === 'string')
      if (filtered.length === 1) {
        result[key] = filtered[0]
      } else if (filtered.length > 1) {
        result[key] = filtered
      }
    }
  }
  return Object.keys(result).length > 0 ? result : undefined
}

export function parseRedirectSearch(search?: string) {
  if (!search) return undefined

  try {
    const params = new URLSearchParams(search)
    if (!params.toString()) return undefined

    const result: RedirectSearchParams = {}
    params.forEach((value, key) => {
      if (result[key] === undefined) result[key] = value
      else if (Array.isArray(result[key])) (result[key] as string[]).push(value)
      else result[key] = [result[key] as string, value]
    })

    return result
  } catch {
    return undefined
  }
}

export function buildRedirectSearchString(params?: RedirectSearchParams) {
  if (!params) return undefined
  const searchParams = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (Array.isArray(value)) {
      value.forEach((entry) => {
        searchParams.append(key, entry)
      })
    } else {
      searchParams.append(key, value)
    }
  }
  const serialized = searchParams.toString()
  return serialized ? `?${serialized}` : undefined
}

function readStateFromStorage(key: string): OAuthStatePayload | null {
  if (typeof window === 'undefined') return null
  try {
    const raw = window.sessionStorage.getItem(key)
    if (!raw) return null
    try {
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && typeof parsed.nonce === 'string') {
        return {
          nonce: parsed.nonce,
          redirect: typeof parsed.redirect === 'string' ? parsed.redirect : undefined,
          redirectSearch: normalizeRedirectSearchValue((parsed as { redirectSearch?: unknown }).redirectSearch),
          rememberMe: typeof (parsed as { rememberMe?: unknown }).rememberMe === 'boolean'
            ? ((parsed as { rememberMe?: boolean }).rememberMe as boolean)
            : undefined,
        }
      }
    } catch {
      return { nonce: raw }
    }
    return { nonce: raw }
  } catch {
    return null
  }
}

export function readOauthState(provider: string): OAuthStatePayload | null {
  const fromPrimary = readStateFromStorage(storageKey(provider))
  if (fromPrimary) return fromPrimary
  if (provider === 'github') {
    return readStateFromStorage(LEGACY_GITHUB_STATE_STORAGE_KEY)
  }
  return null
}

export function writeOauthState(provider: string, payload: OAuthStatePayload): boolean {
  if (typeof window === 'undefined') return false
  try {
    const data = JSON.stringify(payload)
    window.sessionStorage.setItem(storageKey(provider), data)
    if (provider === 'github') {
      window.sessionStorage.setItem(LEGACY_GITHUB_STATE_STORAGE_KEY, data)
    }
    return true
  } catch {
    return false
  }
}

export function clearOauthState(provider: string) {
  if (typeof window === 'undefined') return
  try {
    window.sessionStorage.removeItem(storageKey(provider))
    if (provider === 'github') {
      window.sessionStorage.removeItem(LEGACY_GITHUB_STATE_STORAGE_KEY)
    }
  } catch {
    /* noop */
  }
}
