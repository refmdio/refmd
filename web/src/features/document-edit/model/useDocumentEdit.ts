/**
 * Document Edit Hook
 *
 * Orchestrates document editing by composing:
 * - Metadata fetching
 * - KEK fetching (useWorkspaceKek)
 * - Y.Doc initialization (useDocumentInit)
 * - WebSocket + auto-sync (useDocumentWs)
 * - TOFU key change flow
 */

import { useState, useCallback, useEffect, useMemo } from 'react'
import type * as Y from 'yjs'
import type { Awareness } from 'y-protocols/awareness'
import { documentApi } from '@/shared/api'
import type { DocumentResponse } from '@/shared/api'
import { useAuthContext } from '@/shared/context'
import { useWorkspaceKek } from '@/entities/workspace'
import { useKeyChangeFlow, useAsyncData, type KeyChangeWarningDialogProps } from '@/shared/hooks'
import type { WsConnectionState } from '../lib/ws'
import type { TofuKeyChangeWarning } from '../lib/types'
import { documentCache, invalidateDocument } from '../lib/document-cache'
import { useDocumentInit } from './useDocumentInit'
import { useDocumentWs } from './useDocumentWs'

export interface UseDocumentEditResult {
  document: DocumentResponse | null
  yDoc: Y.Doc | null
  awareness: Awareness | null
  isLoading: boolean
  error: Error | null
  /** Non-null when an identity key change is detected and user confirmation is needed */
  keyChangeDialogProps: KeyChangeWarningDialogProps | null
  /** Current WebSocket connection state */
  wsState: WsConnectionState
  /** Notify auto-sync of a local CM edit */
  onLocalEdit: () => void
}

/**
 * Hook to manage document editing with E2EE
 * Shares Y.Doc instance across components for the same document
 *
 * @param documentId Document ID to edit
 */
export function useDocumentEdit(documentId: string): UseDocumentEditResult {
  const { auth, device } = useAuthContext()
  const [overrideError, setOverrideError] = useState<Error | null>(null)
  const [retryTrigger, setRetryTrigger] = useState(0)

  // TOFU key change flow
  const { push: pushKeyChange, dialogProps: keyChangeDialogProps } = useKeyChangeFlow({
    afterTrust: async () => {
      setOverrideError(null)
      invalidateDocument(documentId)
      setRetryTrigger((n) => n + 1)
    },
    onBlock: async (item) => {
      setOverrideError(new Error(`Identity key change rejected for device ${item.displayName}`))
    },
    onCancel: async () => {
      setOverrideError(new Error('Key change verification cancelled'))
    },
  })

  // Adapter: convert TofuKeyChangeWarning to KeyChangeWarningItem
  const handleTofuKeyChange = useCallback(
    (warning: TofuKeyChangeWarning | null) => {
      if (warning) {
        pushKeyChange({
          displayName: warning.deviceId,
          oldFingerprint: warning.oldFingerprint,
          newFingerprint: warning.newFingerprint,
          tofuNewEntry: warning.tofuResult.newEntry,
        })
      }
    },
    [pushKeyChange]
  )

  // Load document metadata
  const { data: document, error: docFetchError } = useAsyncData(
    () => documentApi.get(documentId),
    [documentId],
  )

  // Get workspace KEK (depends on document metadata)
  const { kek, isLoading: kekLoading, error: kekError } = useWorkspaceKek(
    document?.workspace_id,
    auth?.userId,
    device?.deviceId,
    device?.deviceKeys,
    auth?.umk
  )

  // Y.Doc initialization (depends on document + kek + auth)
  const {
    yDoc,
    isLoading: initLoading,
    error: initError,
  } = useDocumentInit(documentId, document, kek, retryTrigger)

  const error = overrideError || docFetchError || kekError || initError

  // Shared Awareness instance from documentCache (created in initializeDocumentCore)
  const awareness = useMemo(() => {
    if (!yDoc) return null
    return documentCache.getValue(documentId)?.awareness ?? null
  }, [yDoc, documentId])

  // WebSocket connection + auto-sync (delegated to useDocumentWs)
  const onFatalError = useCallback((err: Error) => setOverrideError(err), [])
  const { wsState, onLocalEdit } = useDocumentWs(
    documentId, yDoc, device,
    auth?.userId ?? '',
    onFatalError,
    handleTofuKeyChange,
  )

  // Y.Doc ref counting: destroy Y.Doc when last subscriber disconnects
  useEffect(() => {
    const state = documentCache.getValue(documentId)
    if (!state) return

    state.refCount++

    return () => {
      state.refCount--
      if (state.refCount <= 0) {
        state.awareness.destroy()
        state.yDoc.destroy()
        documentCache.removeValue(documentId)
      }
    }
  }, [documentId, yDoc])

  return {
    document,
    yDoc,
    awareness,
    isLoading: !error && (initLoading || kekLoading),
    error,
    keyChangeDialogProps,
    wsState,
    onLocalEdit,
  }
}
