/**
 * Document Save
 *
 * Handles the full save flow for a document:
 * - Computes Yjs diff from last saved state
 * - Encrypts the update with DEK
 * - Signs and hashes the update
 * - Sends to server
 * - Handles DEK rotation retry when key version is stale
 */

import * as Y from 'yjs'
import { documentApi, encryptionApi, ApiError } from '@/shared/api'
import {
  base64UrlEncode,
  base64UrlDecode,
  unwrapDek,
  encryptContent,
  computeUpdateHash,
  signDocumentUpdate,
} from '@/shared/lib/crypto'
import {
  assertAndPinKeyVersion,
  pinDocumentState,
} from '@/shared/lib/anti-rollback'
import type { AuthState, DeviceState } from '@/shared/model/auth-types'
import type { DocumentResponse } from '@/shared/api'
import type { DocumentState } from './types'
import { documentCache } from './document-cache'

export interface SaveDocumentParams {
  documentId: string
  auth: AuthState
  device: DeviceState
  kek: Uint8Array
  document: DocumentResponse
}

/**
 * Encrypt, hash, sign, and submit a document update to the server.
 * Returns the update hash and server result.
 */
async function encryptSignAndSubmit(
  updateToSave: Uint8Array,
  dek: Uint8Array,
  documentId: string,
  keyVersion: number,
  prevUpdateHash: string | null,
  device: DeviceState
): Promise<{ updateHash: string; result: { seq: number } }> {
  const { encrypted, nonce } = encryptContent(updateToSave, dek, documentId, keyVersion)
  const timestamp = Date.now()
  const encryptedContentB64 = base64UrlEncode(encrypted)
  const nonceB64 = base64UrlEncode(nonce)

  const updateHash = computeUpdateHash({
    documentId,
    encryptedContent: encryptedContentB64,
    nonce: nonceB64,
    keyVersion,
    prevUpdateHash,
    timestamp,
    authorDeviceId: device.deviceId,
  })

  const signature = signDocumentUpdate({
    signingPrivateKey: device.deviceKeys.signingPrivateKey,
    documentId,
    updateHash,
    prevUpdateHash,
    keyVersion,
    timestamp,
  })

  const result = await documentApi.createUpdate(documentId, {
    update_data: encryptedContentB64,
    nonce: nonceB64,
    key_version: keyVersion,
    update_hash: updateHash,
    prev_update_hash: prevUpdateHash,
    signature: base64UrlEncode(signature),
    author_device_id: device.deviceId,
    timestamp,
  })

  return { updateHash, result }
}

/**
 * Pin document state after a successful save.
 */
async function pinAfterSave(
  documentId: string,
  seq: number | undefined,
  updateHash: string,
  state: DocumentState,
  currentState: Uint8Array
): Promise<void> {
  if (seq != null) {
    await pinDocumentState({
      documentId,
      latestSeq: seq,
      latestUpdateHash: updateHash,
      observedAt: Date.now(),
    })
  }
  state.lastSavedState = currentState
  state.prevUpdateHash = updateHash
  state.isDirty = false
}

/**
 * Save the current document state to the server.
 *
 * Computes the Yjs diff, encrypts it, signs it, and sends it.
 * If the server rejects the save due to a stale DEK version,
 * refreshes the DEK and retries once.
 *
 * @returns true if saved successfully, false if nothing to save
 * @throws on encryption, signing, or network errors
 */
export async function saveDocumentToServer(
  params: SaveDocumentParams
): Promise<boolean> {
  const { documentId, device } = params
  const state = documentCache.getValue(documentId)
  if (!state) {
    return false
  }

  // Get current state
  const currentState = Y.encodeStateAsUpdate(state.yDoc)

  // Calculate diff
  const savedState = state.lastSavedState
  let updateToSave: Uint8Array

  if (savedState) {
    const tempDoc = new Y.Doc()
    Y.applyUpdate(tempDoc, savedState)
    const savedVector = Y.encodeStateVector(tempDoc)
    updateToSave = Y.encodeStateAsUpdate(state.yDoc, savedVector)

    if (updateToSave.length === 0) {
      state.isDirty = false
      return false
    }
  } else {
    updateToSave = currentState
  }

  try {
    const { updateHash, result } = await encryptSignAndSubmit(
      updateToSave, state.dek, documentId, state.keyVersion, state.prevUpdateHash, device
    )
    await pinAfterSave(documentId, result?.seq, updateHash, state, currentState)
    return true
  } catch (saveErr) {
    // If key version is too old (DEK was rotated), refresh DEK and retry
    if (saveErr instanceof ApiError && saveErr.status === 400) {
      if (saveErr.body?.error?.includes('key version too old')) {
        await handleDekRefreshRetry(state, updateToSave, currentState, params)
        return true
      }
    }
    throw saveErr
  }
}

/**
 * Handle a stale DEK version by refreshing the DEK from the server and retrying the save.
 */
async function handleDekRefreshRetry(
  state: DocumentState,
  updateToSave: Uint8Array,
  currentState: Uint8Array,
  params: SaveDocumentParams
): Promise<void> {
  const { documentId, device, kek, document } = params

  const keyResponse = await encryptionApi.getDocumentKey(documentId)
  const freshEncryptedDek = base64UrlDecode(keyResponse.encrypted_dek)
  const freshNonce = base64UrlDecode(keyResponse.nonce)
  const freshDek = unwrapDek(freshEncryptedDek, freshNonce, kek, documentId, document.workspace_id)

  // Anti-rollback: check refreshed DEK version and pin atomically
  await assertAndPinKeyVersion('dek', documentId, keyResponse.key_version)

  state.dek = freshDek
  state.keyVersion = keyResponse.key_version

  const { updateHash, result } = await encryptSignAndSubmit(
    updateToSave, freshDek, documentId, state.keyVersion, state.prevUpdateHash, device
  )
  await pinAfterSave(documentId, result?.seq, updateHash, state, currentState)
}
