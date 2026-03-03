/**
 * Document Initialization
 *
 * Handles the document initialization flow:
 * - Get or create DEK for the document
 * - Create empty Y.Doc + shared DocumentState cache entry
 *
 * Device key caches and TOFU verification are handled on WS connection
 * (onDocument callback) per design spec (collaboration.md).
 * Actual document content (snapshot + updates) is loaded via the WS
 * `onDocument` message, which is the sole initialization path.
 */

import * as Y from 'yjs'
import { Awareness } from 'y-protocols/awareness'
import type { DocumentResponse } from '@/shared/api'
import type { DocumentState } from './types'
import { getOrCreateDek } from './dek-service'
import { documentCache } from './document-cache'

export interface InitializeDocumentParams {
  documentId: string
  document: DocumentResponse
  kek: Uint8Array
}

/**
 * Core initialization logic for a document.
 *
 * Prepares DEK and an empty Y.Doc.
 * The WS `onDocument` callback handles device key caches, TOFU verification,
 * and snapshot/update loading.
 */
export async function initializeDocumentCore(
  params: InitializeDocumentParams
): Promise<DocumentState> {
  const {
    documentId,
    document,
    kek,
  } = params

  // 1. Get or create DEK
  const { dek, keyVersion } = await getOrCreateDek(documentId, document.workspace_id, kek)

  // 2. Create empty Y.Doc + shared Awareness (content will be loaded via WS onDocument)
  const newYDoc = new Y.Doc()
  const awareness = new Awareness(newYDoc)

  // 3. Create shared state (signingKeys populated on WS onDocument per design spec)
  const state: DocumentState = {
    yDoc: newYDoc,
    awareness,
    dek,
    keyVersion,
    lastSavedState: null,
    refCount: 0,
    workspaceId: document.workspace_id,
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
    signingKeys: new Map(),
    signingKeyOwners: new Map(),
    pendingSnapshot: null,
    initialized: false,
    ephemeralSession: null,
    awarenessRelayCleanup: null,
    onTofuKeyChange: null,
  }

  documentCache.setValue(documentId, state)
  return state
}
