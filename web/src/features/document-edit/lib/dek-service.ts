/**
 * DEK Service
 *
 * Manages Document Encryption Key (DEK) lifecycle:
 * get existing or create new DEK with anti-rollback checks.
 */

import { encryptionApi, ApiError } from '@/shared/api'
import {
  base64UrlEncode,
  base64UrlDecode,
  generateDek,
  wrapDek,
  unwrapDek,
} from '@/shared/lib/crypto'
import {
  assertAndPinKeyVersion,
  assertNoRollbackOn404,
} from '@/shared/lib/anti-rollback'

export interface DekResult {
  dek: Uint8Array
  keyVersion: number
}

/**
 * Get or create DEK for a document, with anti-rollback checks.
 */
export async function getOrCreateDek(
  documentId: string,
  workspaceId: string,
  kek: Uint8Array
): Promise<DekResult> {
  try {
    const keyResponse = await encryptionApi.getDocumentKey(documentId)
    const encryptedDek = base64UrlDecode(keyResponse.encrypted_dek)
    const nonce = base64UrlDecode(keyResponse.nonce)
    const keyVersion = keyResponse.key_version

    const dek = unwrapDek(encryptedDek, nonce, kek, documentId, workspaceId)

    await assertAndPinKeyVersion('dek', documentId, keyVersion)

    return { dek, keyVersion }
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 404)) throw err

    // Anti-rollback: if we previously observed a DEK version, 404 means server rollback
    await assertNoRollbackOn404('dek', documentId)

    const dek = generateDek()
    const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, workspaceId)

    const saveResponse = await encryptionApi.saveDocumentKey(documentId, {
      encrypted_dek: base64UrlEncode(encryptedDek),
      nonce: base64UrlEncode(nonce),
      is_active: true,
    })

    const keyVersion = saveResponse.key_version

    await assertAndPinKeyVersion('dek', documentId, keyVersion)

    return { dek, keyVersion }
  }
}
