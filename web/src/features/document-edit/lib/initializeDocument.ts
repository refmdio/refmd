/**
 * Document Initialization
 *
 * Handles the document initialization flow:
 * - Get or create DEK for the document
 * - Build device key caches with TOFU verification
 * - Create empty Y.Doc + shared DocumentState cache entry
 *
 * Actual document content (snapshot + updates) is loaded via the WS
 * `onDocument` message, which is the sole initialization path.
 */

import * as Y from 'yjs'
import { Awareness } from 'y-protocols/awareness'
import type { AuthState, DeviceState } from '@/shared/model/auth-types'
import type { DocumentResponse } from '@/shared/api'
import type { TofuKeyChangeWarning, DocumentState } from './types'
import { getOrCreateDek } from './dek-service'
import { buildDeviceKeyCaches } from './document-verification-service'
import { documentCache } from './document-cache'

export interface InitializeDocumentParams {
  documentId: string
  document: DocumentResponse
  kek: Uint8Array
  auth: AuthState
  device: DeviceState
}

export type InitResult =
  | { status: 'ok'; state: DocumentState }
  | { status: 'key_changed'; warning: TofuKeyChangeWarning }

/**
 * Core initialization logic for a document.
 *
 * Prepares DEK, device key caches, and an empty Y.Doc.
 * The WS `onDocument` callback handles snapshot/update loading and verification.
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

  // 2. Build device key caches with TOFU verification
  const cacheResult = await buildDeviceKeyCaches(auth.userId)
  if (cacheResult.status === 'key_changed') {
    return { status: 'key_changed', warning: cacheResult.warning }
  }
  const { signingKeys } = cacheResult

  // 3. Create empty Y.Doc + shared Awareness (content will be loaded via WS onDocument)
  const newYDoc = new Y.Doc()
  const awareness = new Awareness(newYDoc)

  // 4. Create shared state
  const state: DocumentState = {
    yDoc: newYDoc,
    awareness,
    dek,
    keyVersion,
    lastSavedState: null,
    refCount: 0,
    activeSnapshotId: null,
    snapshotProofHash: '',
    snapshotCiphertextHash: '',
    localClock: 0,
    knownClocks: {},
    confirmedClocks: {},
    snapshotUpdatesCount: 0,
    ws: null,
    wsRefCount: 0,
    autoSync: null,
    signingKeys,
    pendingSnapshot: null,
    initialized: false,
  }

  documentCache.setValue(documentId, state)
  return { status: 'ok', state }
}
