/** Allowed internal redirect path prefixes. */
const ALLOWED_REDIRECT_PREFIXES = ['/workspace', '/invite', '/document']

/**
 * Validates a redirect query parameter against a whitelist of internal paths.
 * Returns the redirect path if valid, undefined otherwise.
 * Prevents open redirect by requiring the path starts with a known prefix
 * followed by end-of-string, '/', '?', or '#'.
 */
export function sanitizeRedirect(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  if (!value.startsWith('/')) return undefined
  return ALLOWED_REDIRECT_PREFIXES.some((prefix) => {
    if (!value.startsWith(prefix)) return false
    // Ensure the prefix is followed by a boundary (exact match, '/', '?', or '#')
    const rest = value.slice(prefix.length)
    return rest.length === 0 || rest[0] === '/' || rest[0] === '?' || rest[0] === '#'
  })
    ? value
    : undefined
}
