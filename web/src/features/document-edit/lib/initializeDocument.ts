/**
 * Document Initialization
 *
 * Handles the full document initialization flow:
 * - Get or create DEK for the document
 * - Load and decrypt existing Yjs updates
 * - Verify TOFU, signatures, hash chains, and anti-rollback
 * - Build the shared DocumentState cache entry
 */

import * as Y from 'yjs'
import { documentApi } from '@/shared/api'
import { pinDocumentState } from '@/shared/lib/anti-rollback'
import type { AuthState } from '@/shared/model/auth-types'
import type { DocumentResponse } from '@/shared/api'
import type { TofuKeyChangeWarning, DocumentState } from './types'
import { getOrCreateDek } from './dek-service'
import { verifyDocumentStateAntiRollback, buildDeviceKeyCaches, verifyAndApplyUpdates } from './document-verification-service'
import { documentCache } from './document-cache'

export interface InitializeDocumentParams {
  documentId: string
  document: DocumentResponse
  kek: Uint8Array
  auth: AuthState
}

export type InitResult =
  | { status: 'ok'; state: DocumentState }
  | { status: 'key_changed'; warning: TofuKeyChangeWarning }

/**
 * Core initialization logic for a document.
 * Returns a discriminated union: 'ok' with DocumentState, or 'key_changed' with warning.
 * Throws on any verification or decryption error.
 */
export async function initializeDocumentCore(
  params: InitializeDocumentParams
): Promise<InitResult> {
  const {
    documentId,
    document,
    kek,
    auth,
  } = params

  // 1. Get or create DEK
  const { dek, keyVersion } = await getOrCreateDek(documentId, document.workspace_id, kek)

  // 2. Load updates
  const updatesResponse = await documentApi.listUpdates(documentId)
  const updates = updatesResponse.updates || []

  // 3. Anti-rollback check on document state
  await verifyDocumentStateAntiRollback(documentId, updates)

  // 4. Build device key caches with TOFU verification
  const newYDoc = new Y.Doc()
  let prevUpdateHash: string | null = null

  if (updates.length > 0) {
    const cacheResult = await buildDeviceKeyCaches(auth.userId)
    if (cacheResult.status === 'key_changed') {
      return { status: 'key_changed', warning: cacheResult.warning }
    }

    // 5. Verify and decrypt each update
    const verifyResult = await verifyAndApplyUpdates(
      updates, newYDoc, dek, documentId, auth.userId,
      cacheResult.signingKeys, cacheResult.ecdhKeys,
    )
    if (verifyResult.status === 'key_changed') {
      return { status: 'key_changed', warning: verifyResult.warning }
    }
    prevUpdateHash = verifyResult.prevUpdateHash
  }

  // 6. Pin document state after loading updates
  if (updates.length > 0) {
    const lastUpdate = updates[updates.length - 1]
    const lastSeq = (lastUpdate as Record<string, unknown>).seq as number | undefined
    if (lastSeq != null) {
      await pinDocumentState({
        documentId,
        latestSeq: lastSeq,
        latestUpdateHash: lastUpdate.update_hash,
        observedAt: Date.now(),
      })
    }
  }

  // 7. Save initial state for dirty tracking
  const lastSavedState = Y.encodeStateAsUpdate(newYDoc)

  // 8. Create shared state
  const state: DocumentState = {
    yDoc: newYDoc,
    dek,
    keyVersion,
    lastSavedState,
    prevUpdateHash,
    isDirty: false,
    isSaving: false,
    contentListeners: new Set(),
    refCount: 0,
  }

  // 9. Track changes
  const yText = newYDoc.getText('content')
  newYDoc.on('update', () => {
    const currentState = Y.encodeStateAsUpdate(newYDoc)
    const savedState = state.lastSavedState
    const newContent = yText.toString()

    // Compare states
    if (!savedState || currentState.length !== savedState.length) {
      state.isDirty = true
    } else {
      let same = true
      for (let i = 0; i < currentState.length; i++) {
        if (currentState[i] !== savedState[i]) {
          same = false
          break
        }
      }
      state.isDirty = !same
    }

    // Notify all listeners
    state.contentListeners.forEach((listener) => listener(newContent))
  })

  documentCache.setValue(documentId, state)
  return { status: 'ok', state }
}
