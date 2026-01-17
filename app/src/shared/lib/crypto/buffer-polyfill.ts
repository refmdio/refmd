/**
 * Buffer polyfill for browser environment
 * This must be imported before any modules that use Buffer (like bip39)
 */

import { Buffer } from 'buffer'

// Make Buffer available globally for libraries that expect it
if (typeof globalThis !== 'undefined' && !globalThis.Buffer) {
  globalThis.Buffer = Buffer
}

export { Buffer }
