/**
 * AAD (Additional Authenticated Data) constants and helpers
 *
 * Per spec: All AEAD operations must include AAD with protocol/version/purpose
 * AAD is always reconstructed, never stored with ciphertext
 *
 * Signature protocol (canonicalization, buildSignatureMessage) is in ./signature.ts
 */

import { SIGNATURE_PROTOCOL } from './signature'
import { canonicalizeBytes } from './signature'

/**
 * AAD purpose constants (per spec)
 */
export const AAD_PURPOSE = {
  // UMK related
  UMK_WRAP: 'umk_wrap',
  DSK_UMK_CACHE: 'dsk_umk_cache',
  PDK_UMK_WRAP: 'pdk_umk_wrap',
  RECOVERY_UMK_WRAP: 'recovery_umk_wrap',
  DEVICE_UMK_WRAP: 'device_umk_wrap',

  // Identity key related
  IDENTITY_ECDH: 'identity_ecdh',
  IDENTITY_SIGNING: 'identity_signing',

  // Device key related
  DSK_DEVICE_ECDH_PRIVATE: 'dsk_device_ecdh_private',
  DSK_DEVICE_SIGNING_PRIVATE: 'dsk_device_signing_private',
  PDK_DEVICE_ECDH_PRIVATE: 'pdk_device_ecdh_private',
  PDK_DEVICE_SIGNING_PRIVATE: 'pdk_device_signing_private',

  // KEK/DEK related
  KEK_WRAP: 'kek_wrap',
  DEVICE_KEK_WRAP: 'device_kek_wrap',
  DEK_WRAP: 'dek_wrap',
  DOCUMENT_CONTENT: 'document_content',
  DOCUMENT_TAG_VALUE: 'document_tag_value',

  // UMK KEK backup
  UMK_KEK_BACKUP: 'umk_kek_backup',

  // Share related
  SHARE_DEK_WRAP: 'share_dek_wrap',
  SHARE_DEK_WRAP_PASSWORD: 'share_dek_wrap_password',

  // Trust state transfer
  TRUST_STATE_TRANSFER: 'trust_state_transfer',

  // Server internal
  SERVER_AUTH_KEY_WRAP: 'server_auth_key_wrap',
} as const

export type AadPurpose = (typeof AAD_PURPOSE)[keyof typeof AAD_PURPOSE]

/**
 * AAD common header interface
 */
export interface AadCommonHeader {
  protocol: 'doclock-v1'
  version: 1
  purpose: AadPurpose
}

/**
 * Build AAD bytes from header object
 * Uses RFC 8785 JSON Canonicalization Scheme (recursively sorted keys, no whitespace)
 *
 * @param header AAD header object
 * @returns Canonical JSON encoded as UTF-8 bytes
 * @throws Error if header contains undefined or non-finite numbers
 */
export function buildAad(header: AadCommonHeader & Record<string, unknown>): Uint8Array {
  // Use canonicalizeBytes for full RFC 8785 JCS compliance (recursive sorting + validation)
  return canonicalizeBytes(header)
}

/**
 * Build AAD for UMK wrap (with PUK)
 */
export function buildUmkWrapAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.UMK_WRAP,
    user_id: userId,
  })
}

/**
 * Build AAD for recovery UMK wrap
 */
export function buildRecoveryUmkWrapAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.RECOVERY_UMK_WRAP,
    user_id: userId,
  })
}

/**
 * Build AAD for identity ECDH private key encryption
 */
export function buildIdentityEcdhAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.IDENTITY_ECDH,
    user_id: userId,
  })
}

/**
 * Build AAD for identity signing private key encryption
 */
export function buildIdentitySigningAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.IDENTITY_SIGNING,
    user_id: userId,
  })
}

/**
 * Build AAD for device UMK distribution (UMK encrypted with ECDH shared secret)
 */
export function buildDeviceUmkDistributionAad(
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DEVICE_UMK_WRAP,
    user_id: userId,
    sender_device_id: senderDeviceId,
    target_device_id: targetDeviceId,
  })
}

/**
 * Build AAD for device KEK distribution (KEK encrypted with ECDH shared secret)
 */
export function buildDeviceKekDistributionAad(
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string
): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DEVICE_KEK_WRAP,
    workspace_id: workspaceId,
    user_id: userId,
    sender_device_id: senderDeviceId,
    target_device_id: targetDeviceId,
  })
}

/**
 * Build AAD for UMK KEK backup (KEK encrypted with UMK)
 * Includes key_version to prevent version downgrade/mixup attacks.
 */
export function buildUmkKekBackupAad(
  workspaceId: string,
  userId: string,
  keyVersion: number
): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.UMK_KEK_BACKUP,
    workspace_id: workspaceId,
    user_id: userId,
    key_version: keyVersion,
  })
}

/**
 * Build AAD for DEK wrap (DEK encrypted with KEK)
 */
export function buildDekWrapAad(documentId: string, workspaceId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DEK_WRAP,
    document_id: documentId,
    workspace_id: workspaceId,
  })
}

/**
 * Build AAD for document content encryption (Yjs updates encrypted with DEK)
 * Includes key_version to prevent cross-version mixup/replay attacks (per spec).
 */
export function buildDocumentContentAad(documentId: string, keyVersion: number): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DOCUMENT_CONTENT,
    document_id: documentId,
    key_version: keyVersion,
  })
}
