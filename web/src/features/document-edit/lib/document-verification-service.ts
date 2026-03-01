/**
 * Document Verification Service
 *
 * Handles device TOFU verification, envelope signature verification,
 * snapshot proof chain verification, and snapshot decryption.
 *
 * Clock-based: uses per-device monotonic clocks and snapshot proof chain
 * instead of linear hash chain.
 */

import {
  base64UrlDecode,
  computeParentSnapshotProof,
  evaluateTofu,
  type TofuDecision,
} from '@/shared/lib/crypto'
import { deviceApi } from '@/shared/api'
import type { TofuKeyChangeWarning } from './types'

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
// Device TOFU + Key Cache
// =============================================================================

export type DeviceKeyCacheResult =
  | { status: 'ok'; signingKeys: Map<string, Uint8Array> }
  | { status: 'key_changed'; warning: TofuKeyChangeWarning }

/**
 * Build device key caches and verify TOFU for all devices.
 * Keys are indexed by device signing public key (base64url) for clock-based lookups.
 * Returns a key_changed result if a TOFU key change is detected.
 */
export async function buildDeviceKeyCaches(
  userId: string,
): Promise<DeviceKeyCacheResult> {
  const signingKeys = new Map<string, Uint8Array>()

  const devicesResponse = await deviceApi.listDevices()
  for (const dev of devicesResponse.devices) {
    const signingPk = base64UrlDecode(dev.signing_public_key)
    const ecdhPk = base64UrlDecode(dev.ecdh_public_key)
    signingKeys.set(dev.signing_public_key, signingPk)

    const devDecision = await evaluateTofu(userId, dev.id, signingPk, ecdhPk)
    const tofuResult = evaluateVerificationTofu(devDecision, dev.id)
    if (tofuResult !== 'continue') {
      return { status: 'key_changed', warning: tofuResult }
    }
  }

  return { status: 'ok', signingKeys }
}

// =============================================================================
// Snapshot Proof Chain Verification
// =============================================================================

/**
 * Verify the snapshot proof chain integrity.
 * Each link in the chain must hash correctly to the next entry's parentSnapshotProof.
 * The active snapshot must connect to the end of the chain.
 *
 * @param knownSnapshotProofHash - If provided, verifies that the first chain entry
 *   connects to the known snapshot (prevents server from injecting arbitrary chains).
 * @param knownSnapshotId - Required when knownSnapshotProofHash is provided.
 * @param knownSnapshotCiphertextHash - Ciphertext hash of the known snapshot.
 */
export function verifySnapshotProofChain(
  activeSnapshot: { id: string; ciphertext_hash: string; parent_snapshot_proof: string },
  proofChain: Array<{ snapshot_id: string; ciphertext_hash: string; parent_snapshot_proof: string }>,
  knownSnapshotProofHash?: string,
  knownSnapshotId?: string,
  knownSnapshotCiphertextHash?: string,
): void {
  if (proofChain.length === 0) return // complete mode: no chain

  // Verify first link connects to the known snapshot (if provided).
  // Without this check, the server could return an arbitrary proof chain
  // disconnected from the client's known state.
  // proofChain[0].parent_snapshot_proof must equal
  // BLAKE3(knownProofHash || knownSnapshotId || knownCiphertextHash)
  if (knownSnapshotProofHash !== undefined && knownSnapshotId !== undefined && knownSnapshotCiphertextHash !== undefined) {
    const firstEntry = proofChain[0]
    const expectedFirstProof = computeParentSnapshotProof(
      knownSnapshotProofHash,
      knownSnapshotId,
      knownSnapshotCiphertextHash,
    )
    if (firstEntry.parent_snapshot_proof !== expectedFirstProof) {
      throw new Error(`Proof chain first link does not connect to known snapshot ${knownSnapshotId}`)
    }
  }

  // Verify each link in the chain (oldest → newest)
  for (let i = 1; i < proofChain.length; i++) {
    const prev = proofChain[i - 1]
    const curr = proofChain[i]
    const expected = computeParentSnapshotProof(
      prev.parent_snapshot_proof,
      prev.snapshot_id,
      prev.ciphertext_hash,
    )
    if (curr.parent_snapshot_proof !== expected) {
      throw new Error(`Proof chain broken at snapshot ${curr.snapshot_id}`)
    }
  }

  // Verify active snapshot connects to chain tail.
  const lastEntry = proofChain[proofChain.length - 1]
  if (lastEntry.snapshot_id === activeSnapshot.id) {
    // Chain tail IS the active snapshot: verify the chain entry's fields match
    // the signed active snapshot metadata. Without this check, a malicious server
    // could forge a chain entry with the active snapshot's ID but a fabricated
    // parentSnapshotProof to bridge from the pinned snapshot to a rollbacked one.
    if (lastEntry.parent_snapshot_proof !== activeSnapshot.parent_snapshot_proof) {
      throw new Error(`Proof chain tail parentSnapshotProof mismatch for active snapshot ${activeSnapshot.id}`)
    }
    if (lastEntry.ciphertext_hash !== activeSnapshot.ciphertext_hash) {
      throw new Error(`Proof chain tail ciphertextHash mismatch for active snapshot ${activeSnapshot.id}`)
    }
  } else {
    // Chain tail is a predecessor: verify active snapshot's parentSnapshotProof
    // connects to the chain tail via hash computation.
    const expectedActiveProof = computeParentSnapshotProof(
      lastEntry.parent_snapshot_proof,
      lastEntry.snapshot_id,
      lastEntry.ciphertext_hash,
    )
    if (activeSnapshot.parent_snapshot_proof !== expectedActiveProof) {
      throw new Error(`Proof chain broken at active snapshot ${activeSnapshot.id}`)
    }
  }
}
