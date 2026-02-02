/**
 * Security Headers Middleware
 *
 * Sets security headers including CSP based on environment.
 * Development: Relaxed CSP for HMR/DevTools compatibility
 * Production: Strict CSP with nonce
 */

import { defineEventHandler, setHeader, type H3Event } from 'h3'
import { randomBytes } from 'crypto'

const isDev = process.env.NODE_ENV !== 'production'

/**
 * Generate a cryptographically random nonce
 */
function generateNonce(): string {
  return randomBytes(16).toString('base64')
}

/**
 * Build CSP header value
 */
function buildCsp(nonce: string): string {
  if (isDev) {
    // Development: Allow inline scripts/styles for HMR and DevTools
    return [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' blob: data:",
      "media-src 'self' blob:",
      "font-src 'self'",
      "connect-src 'self' ws://localhost:* http://localhost:*",
      "worker-src 'self' blob:",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join('; ')
  }

  // Production: Strict CSP per design doc (web-security.md)
  return [
    "default-src 'self'",
    "script-src 'self'",
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' blob: data:",
    "media-src 'self' blob:",
    "font-src 'self'",
    "connect-src 'self' wss://app.refmd.io https://app.refmd.io",
    "worker-src 'self' blob:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "require-trusted-types-for 'script'",
  ].join('; ')
}

export default defineEventHandler((event: H3Event) => {
  // Skip for API routes (handled by backend)
  const path = event.path || ''
  if (path.startsWith('/api/')) {
    return
  }

  // Generate nonce for this request
  const nonce = generateNonce()

  // Store nonce in event context for use in HTML rendering
  event.context.cspNonce = nonce

  // Set security headers
  setHeader(event, 'X-Content-Type-Options', 'nosniff')
  setHeader(event, 'X-Frame-Options', 'DENY')
  setHeader(event, 'Referrer-Policy', 'strict-origin-when-cross-origin')
  setHeader(event, 'Permissions-Policy', 'geolocation=(), microphone=(), camera=()')

  // HSTS only in production (requires HTTPS)
  if (!isDev) {
    setHeader(event, 'Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
  }

  // CSP
  setHeader(event, 'Content-Security-Policy', buildCsp(nonce))
})
