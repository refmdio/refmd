/**
 * Plugin Sandbox Configuration
 *
 * Provides CSP (Content Security Policy) settings for plugin iframes
 * to prevent malicious plugins from exfiltrating decrypted data.
 */

/** CSP directives for plugin sandboxes */
export const PLUGIN_SANDBOX_CSP = {
  'default-src': ["'self'"],
  'connect-src': ["'none'"], // Block all network requests
  'script-src': ["'self'"],
  'style-src': ["'self'", "'unsafe-inline'"],
  'img-src': ["'self'", 'data:', 'blob:'],
  'font-src': ["'self'"],
  'object-src': ["'none'"],
  'base-uri': ["'self'"],
  'form-action': ["'none'"],
  'frame-ancestors': ["'none'"],
} as const

/**
 * Build CSP header string from directives.
 */
export function buildCspString(
  directives: Record<string, readonly string[]> = PLUGIN_SANDBOX_CSP
): string {
  return Object.entries(directives)
    .map(([key, values]) => `${key} ${values.join(' ')}`)
    .join('; ')
}

/**
 * Create a sandboxed iframe for plugin execution.
 *
 * The iframe has restricted permissions:
 * - allow-scripts: Allow JavaScript execution
 * - NO allow-same-origin: Prevents access to parent document
 * - NO allow-forms: Prevents form submission
 * - NO allow-popups: Prevents opening new windows
 *
 * @param pluginId - Plugin identifier for debugging
 * @returns Configured iframe element
 */
export function createPluginIframe(pluginId: string): HTMLIFrameElement {
  const iframe = document.createElement('iframe')

  // Set sandbox attribute with minimal permissions
  iframe.sandbox.add('allow-scripts')
  // Intentionally NOT adding:
  // - allow-same-origin (would allow access to parent)
  // - allow-forms (would allow form submission)
  // - allow-popups (would allow opening windows)
  // - allow-top-navigation (would allow navigation)

  // Set CSP via attribute (some browsers support this)
  iframe.setAttribute('csp', buildCspString())

  // Set referrer policy
  iframe.referrerPolicy = 'no-referrer'

  // Add plugin ID for debugging
  iframe.dataset.pluginId = pluginId

  // Style for visibility
  iframe.style.display = 'none'

  return iframe
}

/**
 * Sandbox attributes for plugin iframes.
 *
 * These are the recommended attributes for maximum security
 * while still allowing plugin functionality.
 */
export const SANDBOX_ATTRIBUTES = [
  'allow-scripts', // Required for JavaScript
] as const

/**
 * Forbidden sandbox attributes that should never be added.
 */
export const FORBIDDEN_SANDBOX_ATTRIBUTES = [
  'allow-same-origin', // Would bypass sandbox
  'allow-top-navigation', // Could navigate away
  'allow-top-navigation-by-user-activation',
  'allow-forms', // Could submit data externally
  'allow-popups', // Could open external windows
  'allow-popups-to-escape-sandbox',
  'allow-modals', // Could block user
  'allow-orientation-lock',
  'allow-pointer-lock',
  'allow-presentation',
  'allow-downloads', // Could trigger downloads
] as const
