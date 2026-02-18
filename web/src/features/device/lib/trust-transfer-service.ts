/**
 * Trust Transfer Service — Barrel
 *
 * Re-exports from focused sub-modules for backward compatibility.
 */

export type {
  TrustDeviceInfo,
  TrustStateResponse,
  ImportParams,
  SenderAction,
  FetchedTrustData,
} from './trust-transfer-types'
export { TrustTransferAbortError } from './trust-transfer-types'

export { verifyAllDevicesTofu, verifySenderAndResolve, buildDirectImportAction } from './trust-transfer-verify'
export { safeImportTrustState } from './trust-transfer-import'
export { fetchTrustData, retryRetrieveState } from './trust-transfer-fetch'
