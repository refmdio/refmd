/**
 * TOFU Policy — Centralized decision logic
 *
 * Encapsulates the common TOFU verification → decision pattern
 * used across device approval, registration, KEK rotation, document init, etc.
 *
 * Callers handle UI (error display, warning dialogs) based on the returned decision.
 */

import { verifyTofu, handleTofuResult, type TofuVerifyResult } from './tofu'
import { base64UrlDecode } from './encoding'
import { logger } from '../logger'
import type { KeyChangeWarningItem } from '@/shared/model/key-change-types'

export type TofuDecision =
  | { action: 'proceed'; tofuResult: TofuVerifyResult }
  | { action: 'abort'; reason: string }
  | { action: 'key_changed'; oldFingerprint: string; newFingerprint: string; tofuResult: TofuVerifyResult }

/**
 * Convert a `key_changed` TofuDecision to a key change warning item.
 */
export function toKeyChangeItem(
  decision: TofuDecision & { action: 'key_changed' },
  displayName: string
): KeyChangeWarningItem {
  return {
    displayName,
    oldFingerprint: decision.oldFingerprint,
    newFingerprint: decision.newFingerprint,
    tofuNewEntry: decision.tofuResult.newEntry,
  }
}

/**
 * Map a raw TofuVerifyResult to a TofuDecision.
 * Shared between evaluateTofu and evaluateTofuWithoutPersist.
 */
function tofuResultToDecision(tofuResult: TofuVerifyResult, deviceId: string): TofuDecision {
  if (tofuResult.status === 'ecdh_key_mismatch') {
    return {
      action: 'abort',
      reason: `Device ${deviceId} ECDH key mismatch. This may indicate tampering.`,
    }
  }

  if (tofuResult.status === 'identity_key_changed') {
    return {
      action: 'key_changed',
      oldFingerprint: tofuResult.oldFingerprint!,
      newFingerprint: tofuResult.newFingerprint!,
      tofuResult,
    }
  }

  return { action: 'proceed', tofuResult }
}

/**
 * Evaluate TOFU for a device and return a decision.
 *
 * - `proceed`: Keys are trusted (first_seen auto-saved, known_trusted last-seen updated).
 * - `abort`: ECDH key mismatch detected — caller should block.
 * - `key_changed`: Identity key changed — caller should show a warning dialog.
 */
export async function evaluateTofu(
  userId: string,
  deviceId: string,
  signingPublicKey: Uint8Array,
  ecdhPublicKey: Uint8Array
): Promise<TofuDecision> {
  const tofuResult = await verifyTofu(userId, deviceId, signingPublicKey, ecdhPublicKey)
  const decision = tofuResultToDecision(tofuResult, deviceId)

  if (decision.action === 'proceed') {
    await handleTofuResult(tofuResult)
  }

  return decision
}

/**
 * Assert that a TOFU decision is trusted (proceed).
 * Throws on abort or key_changed — use in service functions where
 * interactive key change dialogs are not available.
 */
export function assertTofuTrustedOrThrow(decision: TofuDecision, context: string): void {
  if (decision.action === 'abort') {
    throw new Error(`${context}: ECDH key mismatch detected. Aborted for security.`)
  }
  if (decision.action === 'key_changed') {
    throw new Error(
      `${context}: Identity key changed unexpectedly. ` +
      'Please verify your devices from a trusted device before continuing.'
    )
  }
}

/**
 * Evaluate TOFU without auto-persisting (no handleTofuResult call).
 *
 * Use this for pending/unapproved devices where TOFU state should NOT be saved
 * until the device is explicitly approved. Per tofu.ts contract:
 * "NEVER call handleTofuResult for unapproved Pending devices."
 */
export async function evaluateTofuWithoutPersist(
  userId: string,
  deviceId: string,
  signingPublicKey: Uint8Array,
  ecdhPublicKey: Uint8Array
): Promise<TofuDecision> {
  const tofuResult = await verifyTofu(userId, deviceId, signingPublicKey, ecdhPublicKey)
  return tofuResultToDecision(tofuResult, deviceId)
}

/**
 * Dispatch a TofuDecision to handler callbacks.
 * Centralizes the abort/key_changed/proceed branching used across hooks
 * to prevent logic drift when new decision types are added.
 *
 * @returns true if the decision requires early return (abort or key_changed)
 */
export function dispatchTofuDecision(
  decision: TofuDecision,
  displayName: string,
  handlers: {
    onAbort: (reason: string) => void
    onKeyChanged: (item: KeyChangeWarningItem) => void
  }
): boolean {
  if (decision.action === 'abort') {
    handlers.onAbort(decision.reason)
    return true
  }
  if (decision.action === 'key_changed') {
    handlers.onKeyChanged(toKeyChangeItem(decision, displayName))
    return true
  }
  return false
}

// --- Convenience helpers for base64-encoded keys ---

export interface DeviceWithKeys {
  id: string
  name: string
  signing_public_key: string
  ecdh_public_key: string
}

/**
 * Evaluate TOFU for a device with base64url-encoded keys.
 * Decodes keys and delegates to `evaluateTofu`.
 */
export async function evaluateDeviceTofu(
  userId: string,
  deviceId: string,
  signingPublicKeyBase64: string,
  ecdhPublicKeyBase64: string
): Promise<TofuDecision> {
  const signingPk = base64UrlDecode(signingPublicKeyBase64)
  const ecdhPk = base64UrlDecode(ecdhPublicKeyBase64)
  return evaluateTofu(userId, deviceId, signingPk, ecdhPk)
}

export interface DeviceListTofuResult {
  keyChangeItems: KeyChangeWarningItem[]
  abortedDevice: DeviceWithKeys | null
  /** Devices that failed TOFU verification due to unexpected errors (e.g., corrupted keys) */
  failedDevices: DeviceWithKeys[]
}

/**
 * Categorized TOFU result for consumers.
 *
 * Shared between useTofuVerification (settings page) and useKekRotation
 * (device revocation flow) — both need to categorize the same result
 * but apply different side effects.
 */
export type CategorizedTofuResult =
  | { outcome: 'aborted'; device: DeviceWithKeys }
  | { outcome: 'ok'; failedDevices: DeviceWithKeys[]; failedIds: Set<string>; keyChangeItems: KeyChangeWarningItem[] }

/**
 * Categorize a DeviceListTofuResult into an abort or ok result.
 * Eliminates the duplicated abort/failed/keyChange branching pattern.
 */
function categorizeTofuResult(result: DeviceListTofuResult): CategorizedTofuResult {
  if (result.abortedDevice) {
    return { outcome: 'aborted', device: result.abortedDevice }
  }
  const failedIds = new Set(result.failedDevices.map(d => d.id))
  return { outcome: 'ok', failedDevices: result.failedDevices, failedIds, keyChangeItems: result.keyChangeItems }
}

export interface TofuCategoryHandlers {
  onAborted: (device: DeviceWithKeys) => void
  onFailed?: (devices: DeviceWithKeys[], ids: Set<string>) => void
  onKeyChange?: (items: KeyChangeWarningItem[]) => void
}

/**
 * Process a CategorizedTofuResult with handler callbacks.
 * Standardizes the abort/failed/keyChange branching pattern
 * shared between useTofuVerification and useKekRotation.
 *
 * @returns true if aborted (caller should return early)
 */
function processCategorizedTofu(
  categorized: CategorizedTofuResult,
  handlers: TofuCategoryHandlers
): boolean {
  if (categorized.outcome === 'aborted') {
    handlers.onAborted(categorized.device)
    return true
  }
  if (categorized.failedDevices.length > 0 && handlers.onFailed) {
    handlers.onFailed(categorized.failedDevices, categorized.failedIds)
  }
  if (categorized.keyChangeItems.length > 0 && handlers.onKeyChange) {
    handlers.onKeyChange(categorized.keyChangeItems)
  }
  return false
}

/**
 * Verify TOFU for a list of devices. Collects key_changed items and stops on abort.
 * Common pattern used in trust transfer, device verification, and KEK rotation.
 */
export async function verifyDeviceListTofu(
  devices: DeviceWithKeys[],
  userId: string
): Promise<DeviceListTofuResult> {
  const keyChangeItems: KeyChangeWarningItem[] = []
  const failedDevices: DeviceWithKeys[] = []

  for (const device of devices) {
    if (!device.signing_public_key || !device.ecdh_public_key) {
      failedDevices.push(device)
      continue
    }

    try {
      const decision = await evaluateDeviceTofu(
        userId, device.id, device.signing_public_key, device.ecdh_public_key
      )

      if (decision.action === 'abort') {
        return { keyChangeItems, abortedDevice: device, failedDevices }
      }

      if (decision.action === 'key_changed') {
        keyChangeItems.push(toKeyChangeItem(decision, device.name))
      }
    } catch (err) {
      logger.error('tofu', `Verification failed for device ${device.id} (${device.name})`, err)
      failedDevices.push(device)
    }
  }

  return { keyChangeItems, abortedDevice: null, failedDevices }
}

/**
 * Convenience wrapper: verify + categorize + process in one call.
 * Combines verifyDeviceListTofu → categorizeTofuResult → processCategorizedTofu.
 *
 * @returns `{ aborted: true }` if the caller should return early,
 *          `{ aborted: false, categorized }` otherwise.
 */
export async function processDeviceListTofu(
  devices: DeviceWithKeys[],
  userId: string,
  handlers: TofuCategoryHandlers
): Promise<{ aborted: true } | { aborted: false; categorized: CategorizedTofuResult & { outcome: 'ok' } }> {
  const categorized = categorizeTofuResult(
    await verifyDeviceListTofu(devices, userId)
  )
  if (processCategorizedTofu(categorized, handlers)) {
    return { aborted: true }
  }
  return { aborted: false, categorized: categorized as CategorizedTofuResult & { outcome: 'ok' } }
}
