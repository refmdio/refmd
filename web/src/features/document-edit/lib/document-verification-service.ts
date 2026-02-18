/**
 * Document Verification Service
 *
 * Handles document state anti-rollback checks, device TOFU verification,
 * and update signature/hash-chain verification with decryption.
 */

import {
  base64UrlDecode,
  decryptContent,
  verifyDocumentUpdate,
  evaluateTofu,
  type TofuDecision,
} from '@/shared/lib/crypto'
import {
  checkDocumentStateRollback,
  getDocumentStatePin,
  isRevocationRolledBack,
} from '@/shared/lib/anti-rollback'
import { deviceApi } from '@/shared/api'
import type { TofuKeyChangeWarning } from './types'
import * as Y from 'yjs'

/**
 * Thrown when an update is authored by an unknown device (not in the current user's device list).
 * Phase 3 (multi-user collaboration) will replace this guard with cross-user device resolution.
 */
export class MultiUserNotSupportedError extends Error {
  constructor(authorDeviceId: string, updateIndex: number) {
    super(
      `Unknown author device ${authorDeviceId} at update index ${updateIndex}. ` +
      `Multi-user collaboration is not yet supported.`
    )
    this.name = 'MultiUserNotSupportedError'
  }
}

/**
 * Evaluate a TOFU decision for document verification contexts.
 * - abort: throws
 * - key_changed: returns the warning payload
 * - proceed: returns 'continue'
 */
function evaluateVerificationTofu(
  decision: TofuDecision,
  deviceId: string,
): 'continue' | TofuKeyChangeWarning {
  if (decision.action === 'abort') {
    throw new Error(`TOFU violation: device ${deviceId} ECDH key mismatch`)
  }
  if (decision.action === 'key_changed') {
    return {
      deviceId,
      oldFingerprint: decision.oldFingerprint,
      newFingerprint: decision.newFingerprint,
      tofuResult: decision.tofuResult,
    }
  }
  return 'continue'
}

// =============================================================================
// Document State Anti-Rollback
// =============================================================================

/**
 * Verify document update state hasn't been rolled back or forked.
 */
export async function verifyDocumentStateAntiRollback(
  documentId: string,
  updates: Array<{ update_hash: string; [key: string]: unknown }>
): Promise<void> {
  if (updates.length === 0) {
    const emptyPin = await getDocumentStatePin(documentId)
    if (emptyPin) {
      throw new Error(
        `Document rollback detected for ${documentId}: ` +
        `server returned 0 updates but seq ${emptyPin.latestSeq} was previously observed`
      )
    }
    return
  }

  const latestUpdate = updates[updates.length - 1]
  const latestSeq = latestUpdate.seq as number | undefined
  if (latestSeq == null) return

  const seqRollback = await checkDocumentStateRollback(documentId, latestSeq)
  if (seqRollback.rolledBack) {
    throw new Error(
      `Document rollback detected for ${documentId}: ` +
      `server returned seq ${latestSeq}, pinned seq ${seqRollback.pinnedSeq}`
    )
  }

  const pin = await getDocumentStatePin(documentId)
  if (pin && latestSeq === pin.latestSeq && latestUpdate.update_hash !== pin.latestUpdateHash) {
    throw new Error(
      `Document fork detected for ${documentId} at seq ${latestSeq}: ` +
      `server hash differs from pinned hash`
    )
  }
}

// =============================================================================
// Device TOFU + Key Cache
// =============================================================================

export type DeviceKeyCacheResult =
  | { status: 'ok'; signingKeys: Map<string, Uint8Array>; ecdhKeys: Map<string, Uint8Array> }
  | { status: 'key_changed'; warning: TofuKeyChangeWarning }

/**
 * Build device key caches and verify TOFU for all devices.
 * Returns a key_changed result if a TOFU key change is detected.
 */
export async function buildDeviceKeyCaches(
  userId: string,
): Promise<DeviceKeyCacheResult> {
  const signingKeys = new Map<string, Uint8Array>()
  const ecdhKeys = new Map<string, Uint8Array>()

  const devicesResponse = await deviceApi.listDevices()
  for (const dev of devicesResponse.devices) {
    const signingPk = base64UrlDecode(dev.signing_public_key)
    const ecdhPk = base64UrlDecode(dev.ecdh_public_key)
    signingKeys.set(dev.id, signingPk)
    ecdhKeys.set(dev.id, ecdhPk)

    const devDecision = await evaluateTofu(userId, dev.id, signingPk, ecdhPk)
    const tofuResult = evaluateVerificationTofu(devDecision, dev.id)
    if (tofuResult !== 'continue') {
      return { status: 'key_changed', warning: tofuResult }
    }
  }

  return { status: 'ok', signingKeys, ecdhKeys }
}

// =============================================================================
// Update Verification & Decryption
// =============================================================================

export type VerifyAndApplyResult =
  | { status: 'ok'; prevUpdateHash: string | null }
  | { status: 'key_changed'; warning: TofuKeyChangeWarning }

/**
 * Verify and decrypt each document update, applying to the Y.Doc.
 * Returns a key_changed result if a TOFU key change is detected.
 */
export async function verifyAndApplyUpdates(
  updates: Array<{
    update_data: string; nonce: string; key_version: number
    update_hash: string; prev_update_hash?: string | null
    signature: string; author_device_id: string; timestamp: number
    [key: string]: unknown
  }>,
  yDoc: Y.Doc,
  dek: Uint8Array,
  documentId: string,
  userId: string,
  signingKeys: Map<string, Uint8Array>,
  ecdhKeys: Map<string, Uint8Array>,
): Promise<VerifyAndApplyResult> {
  let prevUpdateHash: string | null = null

  for (const [index, update] of updates.entries()) {
    const authorDeviceId = update.author_device_id
    const signingPubKey = signingKeys.get(authorDeviceId)
    const ecdhPubKey = ecdhKeys.get(authorDeviceId)

    if (!signingPubKey || !ecdhPubKey) {
      // Phase 3: resolve cross-user devices via workspace membership API
      // and run per-user TOFU verification + revocation checks.
      throw new MultiUserNotSupportedError(authorDeviceId, index)
    }

    // TOFU: verify author device identity key
    const authorDecision = await evaluateTofu(userId, authorDeviceId, signingPubKey, ecdhPubKey)
    const tofuResult = evaluateVerificationTofu(authorDecision, authorDeviceId)
    if (tofuResult !== 'continue') {
      return { status: 'key_changed', warning: tofuResult }
    }

    // Revocation check
    const revoked = await isRevocationRolledBack(userId, authorDeviceId)
    if (revoked) {
      throw new Error(`Revoked device ${authorDeviceId} authored update at seq ${update.seq}`)
    }

    // Signature verification + update_hash recomputation
    verifyDocumentUpdate({
      signingPublicKey: signingPubKey,
      documentId,
      encryptedContent: update.update_data,
      nonce: update.nonce,
      keyVersion: update.key_version,
      updateHash: update.update_hash,
      prevUpdateHash: update.prev_update_hash ?? null,
      signature: update.signature,
      authorDeviceId,
      timestamp: update.timestamp,
    })

    // Verify hash chain continuity
    if (prevUpdateHash !== null && update.prev_update_hash !== prevUpdateHash) {
      throw new Error(
        `Hash chain broken at update index ${index}: ` +
        `expected prev_update_hash=${prevUpdateHash}, got=${update.prev_update_hash}`
      )
    }

    // Decrypt and apply
    const encryptedData = base64UrlDecode(update.update_data)
    const nonce = base64UrlDecode(update.nonce)
    const decryptedUpdate = decryptContent(encryptedData, nonce, dek, documentId, update.key_version)
    Y.applyUpdate(yDoc, decryptedUpdate)

    prevUpdateHash = update.update_hash
  }

  return { status: 'ok', prevUpdateHash }
}
