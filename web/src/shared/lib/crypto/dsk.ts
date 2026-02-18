/**
 * DSK (Device Storage Key) Module — Barrel re-export
 *
 * DSK is a non-exportable AES-256-GCM key stored in IndexedDB.
 * Used to wrap UMK for local caching (KMSI - Keep Me Signed In).
 *
 * Security properties:
 * - Non-exportable: Key cannot be extracted via API (protects against disk theft)
 * - XSS is considered a fatal breach; CSP is the primary defense
 *
 * Submodules:
 * - dsk-capability: Browser support detection
 * - dsk-store: IndexedDB helpers and DSK CRUD
 * - dsk-umk: UMK wrap/unwrap with DSK
 * - dsk-device-keys: Device key wrap/unwrap and device ID storage
 * - dsk-session: sessionStorage UMK for rememberMe=false
 */

// Capability detection
export { canPersistDsk } from './dsk-capability'

// DSK lifecycle
export { generateDsk, storeDsk, loadDsk, ensureDsk } from './dsk-store'

// UMK wrap/unwrap and session management
export {
  wrapAndStoreUmk,
  loadAndUnwrapUmk,
  clearSessionCache,
  clearDskData,
  hasCachedSession,
} from './dsk-umk'

// Device key wrap/unwrap and device ID
export {
  storeDeviceId,
  loadDeviceId,
  wrapAndStoreDeviceKeys,
  loadAndUnwrapDeviceKeys,
} from './dsk-device-keys'

// Session storage (for rememberMe=false)
export {
  storeSessionUmk,
  loadSessionUmk,
  clearSessionUmk,
} from './dsk-session'
