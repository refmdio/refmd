/**
 * Document Edit Hook
 *
 * Coordinates document editing:
 * - Metadata fetching
 * - KEK fetching (useWorkspaceKek)
 * - Y.Doc initialization (useDocumentInit)
 * - Content subscription (useDocumentContent)
 * - Save + TOFU key change flow
 */

import { useState, useCallback } from 'react'
import type * as Y from 'yjs'
import { documentApi } from '@/shared/api'
import type { DocumentResponse } from '@/shared/api'
import { useAuthContext } from '@/shared/context'
import { useWorkspaceKek } from '@/entities/workspace'
import { useKeyChangeFlow, useAsyncData, type KeyChangeWarningDialogProps } from '@/shared/hooks'
import type { TofuKeyChangeWarning } from '../lib/types'
import { documentCache, invalidateDocument } from '../lib/document-cache'
import { saveDocumentToServer } from '../lib/saveDocument'
import { useDocumentContent } from './useDocumentContent'
import { useDocumentInit } from './useDocumentInit'

export interface UseDocumentEditResult {
  document: DocumentResponse | null
  yDoc: Y.Doc | null
  content: string
  isLoading: boolean
  error: Error | null
  isDirty: boolean
  isSaving: boolean
  save: () => Promise<void>
  /** Non-null when an identity key change is detected and user confirmation is needed */
  keyChangeDialogProps: KeyChangeWarningDialogProps | null
}

/**
 * Hook to manage document editing with E2EE
 * Shares Y.Doc instance across components for the same document
 *
 * @param documentId Document ID to edit
 */
export function useDocumentEdit(documentId: string): UseDocumentEditResult {
  const { auth, device } = useAuthContext()
  const [isSaving, setIsSaving] = useState(false)
  const [isDirty, setIsDirty] = useState(false)
  const [overrideError, setOverrideError] = useState<Error | null>(null)
  const [retryTrigger, setRetryTrigger] = useState(0)

  // TOFU key change flow
  const { push: pushKeyChange, dialogProps: keyChangeDialogProps } = useKeyChangeFlow({
    afterTrust: async () => {
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
  } = useDocumentInit(documentId, document, kek, auth, retryTrigger, handleTofuKeyChange)

  const error = overrideError || docFetchError || kekError || initError

  // Content subscription + ref counting
  const content = useDocumentContent(documentId, yDoc, setIsDirty)

  // Save function
  const save = useCallback(async () => {
    const state = documentCache.getValue(documentId)
    if (!state || !auth || !device || !kek || !document || state.isSaving) {
      return
    }

    state.isSaving = true
    setIsSaving(true)

    try {
      await saveDocumentToServer({
        documentId,
        auth,
        device,
        kek,
        document,
      })

      setIsDirty(false)
    } catch (err) {
      setOverrideError(err instanceof Error ? err : new Error('Failed to save document'))
    } finally {
      state.isSaving = false
      setIsSaving(false)
    }
  }, [documentId, auth, device, kek, document])

  return {
    document,
    yDoc,
    content,
    isLoading: !error && (initLoading || kekLoading),
    error,
    isDirty,
    isSaving,
    save,
    keyChangeDialogProps,
  }
}
