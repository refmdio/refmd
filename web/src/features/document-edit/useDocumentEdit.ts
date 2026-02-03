/**
 * Document Edit Hook
 *
 * Manages document editing state:
 * - Fetches document metadata
 * - Gets/creates DEK for the document
 * - Loads and decrypts Yjs updates
 * - Saves encrypted updates on manual save
 * - Shares Y.Doc across multiple components for the same document
 */

import { useState, useEffect, useCallback } from 'react'
import * as Y from 'yjs'
import { documentApi, encryptionApi, ApiError } from '@/shared/api'
import {
  base64UrlEncode,
  base64UrlDecode,
  generateDek,
  wrapDek,
  unwrapDek,
  encryptContent,
  decryptContent,
} from '@/shared/lib/crypto'
import { useAuthContext } from '@/shared/context/AuthContext'
import { useWorkspaceKek } from '@/features/workspace-crypto'

export interface DocumentResponse {
  id: string
  workspace_id: string
  parent_id: string | null
  title: string
  encrypted_title?: string
  slug: string
  doc_type: string
  is_encrypted: boolean
  is_archived: boolean
  created_by: string | null
  created_at: string
  updated_at: string
  archived_at: string | null
}

export interface UseDocumentEditResult {
  document: DocumentResponse | null
  yDoc: Y.Doc | null
  content: string
  isLoading: boolean
  error: Error | null
  isDirty: boolean
  isSaving: boolean
  save: () => Promise<void>
}

// Shared document state cache
interface DocumentState {
  yDoc: Y.Doc
  dek: Uint8Array
  keyVersion: number
  lastSavedState: Uint8Array | null
  isDirty: boolean
  isSaving: boolean
  contentListeners: Set<(content: string) => void>
  refCount: number
}

const documentCache = new Map<string, DocumentState>()
const initializingPromises = new Map<string, Promise<DocumentState | null>>()

/**
 * Hook to manage document editing with E2EE
 * Shares Y.Doc instance across components for the same document
 *
 * @param documentId Document ID to edit
 */
export function useDocumentEdit(documentId: string): UseDocumentEditResult {
  const { auth } = useAuthContext()
  const [document, setDocument] = useState<DocumentResponse | null>(null)
  const [content, setContent] = useState('')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const [isSaving, setIsSaving] = useState(false)
  const [isDirty, setIsDirty] = useState(false)
  const [yDoc, setYDoc] = useState<Y.Doc | null>(null)

  // Get workspace KEK
  const { kek, isLoading: kekLoading, error: kekError } = useWorkspaceKek(
    document?.workspace_id,
    auth?.umk,
    auth?.userId
  )

  // Load document metadata
  useEffect(() => {
    async function loadDocument() {
      try {
        const doc = await documentApi.get(documentId)
        setDocument(doc as unknown as DocumentResponse)
      } catch (err) {
        setError(err instanceof Error ? err : new Error('Failed to load document'))
        setIsLoading(false)
      }
    }

    loadDocument()
  }, [documentId])

  // Subscribe to content changes from shared cache
  useEffect(() => {
    const state = documentCache.get(documentId)
    if (!state) return

    const listener = (newContent: string) => {
      setContent(newContent)
      setIsDirty(state.isDirty)
    }

    state.contentListeners.add(listener)
    state.refCount++

    // Get initial content
    const yText = state.yDoc.getText('content')
    setContent(yText.toString())

    return () => {
      state.contentListeners.delete(listener)
      state.refCount--
      if (state.refCount <= 0) {
        state.yDoc.destroy()
        documentCache.delete(documentId)
      }
    }
  }, [documentId, yDoc])

  // Initialize Yjs document with decrypted updates
  useEffect(() => {
    let cancelled = false

    async function initializeYDoc() {
      if (!document || !kek || !auth) {
        return
      }

      // Already cached
      const existingState = documentCache.get(documentId)
      if (existingState) {
        if (!cancelled) {
          setYDoc(existingState.yDoc)
          const yText = existingState.yDoc.getText('content')
          setContent(yText.toString())
          setIsLoading(false)
        }
        return
      }

      // Wait for existing initialization
      const existingPromise = initializingPromises.get(documentId)
      if (existingPromise) {
        const state = await existingPromise
        if (!cancelled && state) {
          setYDoc(state.yDoc)
          const yText = state.yDoc.getText('content')
          setContent(yText.toString())
          setIsLoading(false)
        }
        return
      }

      // Start new initialization
      const initPromise = (async (): Promise<DocumentState | null> => {
        try {
          // 1. Get or create DEK
          let dek: Uint8Array
          let keyVersion = 1
          try {
            const keyResponse = await encryptionApi.getDocumentKey(documentId)
            const encryptedDek = base64UrlDecode(keyResponse.encrypted_dek)
            const nonce = base64UrlDecode(keyResponse.nonce)
            keyVersion = keyResponse.key_version

            // Decrypt DEK with KEK
            dek = unwrapDek(encryptedDek, nonce, kek, documentId, document.workspace_id)
          } catch (err) {
            // If no DEK exists, create one
            if (err instanceof ApiError && err.status === 404) {
              dek = generateDek()

              // Wrap DEK with KEK
              const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, document.workspace_id)

              // Save to server
              const saveResponse = await encryptionApi.saveDocumentKey(documentId, {
                encrypted_dek: base64UrlEncode(encryptedDek),
                nonce: base64UrlEncode(nonce),
                is_active: true,
              })

              keyVersion = saveResponse.key_version
            } else {
              throw err
            }
          }

          // 2. Create Y.Doc
          const newYDoc = new Y.Doc()

          // 3. Load and decrypt existing updates
          const updatesResponse = await documentApi.listUpdates(documentId)
          const updates = updatesResponse.updates || []

          for (const update of updates) {
            const encryptedData = base64UrlDecode(update.update_data)
            const nonce = base64UrlDecode(update.nonce)

            // Decrypt update with DEK
            const decryptedUpdate = decryptContent(encryptedData, nonce, dek, documentId)

            // Apply to Y.Doc
            Y.applyUpdate(newYDoc, decryptedUpdate)
          }

          // 4. Save initial state for dirty tracking
          const lastSavedState = Y.encodeStateAsUpdate(newYDoc)

          // 5. Create shared state
          const state: DocumentState = {
            yDoc: newYDoc,
            dek,
            keyVersion,
            lastSavedState,
            isDirty: false,
            isSaving: false,
            contentListeners: new Set(),
            refCount: 0,
          }

          // 6. Track changes
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

          documentCache.set(documentId, state)
          return state
        } catch (err) {
          if (!cancelled) {
            setError(err instanceof Error ? err : new Error('Failed to initialize document'))
          }
          return null
        } finally {
          initializingPromises.delete(documentId)
        }
      })()

      initializingPromises.set(documentId, initPromise)

      const state = await initPromise
      if (!cancelled && state) {
        setYDoc(state.yDoc)
        const yText = state.yDoc.getText('content')
        setContent(yText.toString())
        setIsLoading(false)
      }
    }

    initializeYDoc()

    return () => {
      cancelled = true
    }
  }, [document, kek, auth, documentId])

  // Save function
  const save = useCallback(async () => {
    const state = documentCache.get(documentId)
    if (!state || !auth || state.isSaving) {
      return
    }

    state.isSaving = true
    setIsSaving(true)

    try {
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
          setIsDirty(false)
          return
        }
      } else {
        updateToSave = currentState
      }

      // Encrypt update with DEK
      const { encrypted, nonce } = encryptContent(updateToSave, state.dek, documentId)

      // Send to server
      await documentApi.createUpdate(documentId, {
        update_data: base64UrlEncode(encrypted),
        nonce: base64UrlEncode(nonce),
        key_version: state.keyVersion,
        timestamp: Date.now(),
      })

      // Update saved state
      state.lastSavedState = currentState
      state.isDirty = false
      setIsDirty(false)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to save document'))
    } finally {
      state.isSaving = false
      setIsSaving(false)
    }
  }, [documentId, auth])

  // Handle KEK loading/error
  useEffect(() => {
    if (kekError) {
      setError(kekError)
      setIsLoading(false)
    }
  }, [kekError])

  return {
    document,
    yDoc,
    content,
    isLoading: isLoading || kekLoading,
    error,
    isDirty,
    isSaving,
    save,
  }
}
