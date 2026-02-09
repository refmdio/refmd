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
import { documentApi, encryptionApi, deviceApi, ApiError } from '@/shared/api'
import {
  base64UrlEncode,
  base64UrlDecode,
  generateDek,
  wrapDek,
  unwrapDek,
  encryptContent,
  decryptContent,
  computeUpdateHash,
  signDocumentUpdate,
  verifyDocumentUpdate,
  verifyTofu,
  handleTofuResult,
  trustDevice,
  type TofuVerifyResult,
} from '@/shared/lib/crypto'
import { useAuthContext } from '@/shared/context/AuthContext'
import { useWorkspaceKek } from '@/features/workspace-crypto'
import {
  checkKeyVersionRollback,
  pinKeyVersion,
  getKeyVersionPin,
  checkDocumentStateRollback,
  getDocumentStatePin,
  pinDocumentState,
  isRevocationRolledBack,
} from '@/shared/lib/anti-rollback'

export interface DocumentResponse {
  id: string
  workspace_id: string
  parent_id: string | null
  title: string
  encrypted_title?: string
  encrypted_title_nonce?: string
  slug: string
  path?: string | null
  doc_type: string
  is_encrypted: boolean
  is_archived: boolean
  needs_dek_rotation: boolean
  created_by: string | null
  created_at: string
  updated_at: string
  archived_at: string | null
}

export interface TofuKeyChangeWarning {
  deviceId: string
  oldFingerprint: string
  newFingerprint: string
  tofuResult: TofuVerifyResult
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
  /** Non-null when an identity key change is detected and user confirmation is needed */
  tofuKeyChangeWarning: TofuKeyChangeWarning | null
  /** Call with true to trust the new key and continue, false to abort */
  confirmTofuKeyChange: (trust: boolean) => void
}

// Shared document state cache
interface DocumentState {
  yDoc: Y.Doc
  dek: Uint8Array
  keyVersion: number
  lastSavedState: Uint8Array | null
  prevUpdateHash: string | null
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
  const { auth, device } = useAuthContext()
  const [document, setDocument] = useState<DocumentResponse | null>(null)
  const [content, setContent] = useState('')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const [isSaving, setIsSaving] = useState(false)
  const [isDirty, setIsDirty] = useState(false)
  const [yDoc, setYDoc] = useState<Y.Doc | null>(null)
  const [tofuKeyChangeWarning, setTofuKeyChangeWarning] = useState<TofuKeyChangeWarning | null>(null)
  const [tofuRetryTrigger, setTofuRetryTrigger] = useState(0)

  // Get workspace KEK (using device ECDH for per-device key wrapping)
  const { kek, isLoading: kekLoading, error: kekError } = useWorkspaceKek(
    document?.workspace_id,
    auth?.userId,
    device?.deviceId,
    device?.deviceKeys,
    auth?.umk
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
            console.log('[DEK Unwrap] documentId:', documentId, 'workspaceId:', document.workspace_id)
            console.log('[DEK Unwrap] encryptedDek length:', encryptedDek.length)
            console.log('[DEK Unwrap] nonce length:', nonce.length)
            console.log('[DEK Unwrap] kek length:', kek.length)
            console.log('[DEK Unwrap] keyVersion:', keyVersion)
            try {
              dek = unwrapDek(encryptedDek, nonce, kek, documentId, document.workspace_id)
            } catch (unwrapErr) {
              console.error('[DEK Unwrap] FAILED', unwrapErr)
              throw unwrapErr
            }

            // Anti-rollback: check DEK version
            const dekRollback = await checkKeyVersionRollback('dek', documentId, keyVersion)
            if (dekRollback.rolledBack) {
              throw new Error(
                `DEK rollback detected for document ${documentId}: ` +
                `server returned v${keyVersion}, pinned v${dekRollback.pinnedVersion}`
              )
            }
            await pinKeyVersion({
              type: 'dek',
              id: documentId,
              highestVersion: keyVersion,
              observedAt: Date.now(),
            })
          } catch (err) {
            // If no DEK exists, create one
            if (err instanceof ApiError && err.status === 404) {
              // Anti-rollback: if we previously observed a DEK version, 404 means server rollback
              const existingDekPin = await getKeyVersionPin('dek', documentId)
              if (existingDekPin) {
                throw new Error(
                  `DEK rollback detected for document ${documentId}: ` +
                  `server returned 404 but v${existingDekPin.highestVersion} was previously observed`
                )
              }

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

              // Anti-rollback: check + pin initial DEK version
              const newDekRollback = await checkKeyVersionRollback('dek', documentId, keyVersion)
              if (newDekRollback.rolledBack) {
                throw new Error(
                  `DEK rollback detected for document ${documentId}: ` +
                  `new DEK v${keyVersion}, pinned v${newDekRollback.pinnedVersion}`
                )
              }
              await pinKeyVersion({
                type: 'dek',
                id: documentId,
                highestVersion: keyVersion,
                observedAt: Date.now(),
              })
            } else {
              throw err
            }
          }

          // 2. Create Y.Doc
          const newYDoc = new Y.Doc()

          // 3. Load and decrypt existing updates
          const updatesResponse = await documentApi.listUpdates(documentId)
          const updates = updatesResponse.updates || []

          // Anti-rollback: check document state before applying updates
          if (updates.length === 0) {
            // If server returns empty updates but we previously observed state, that's a rollback
            const emptyPin = await getDocumentStatePin(documentId)
            if (emptyPin) {
              throw new Error(
                `Document rollback detected for ${documentId}: ` +
                `server returned 0 updates but seq ${emptyPin.latestSeq} was previously observed`
              )
            }
          } else if (updates.length > 0) {
            const latestUpdate = updates[updates.length - 1]
            const latestSeq: number = (latestUpdate as Record<string, unknown>).seq as number
            if (latestSeq != null) {
              const seqRollback = await checkDocumentStateRollback(documentId, latestSeq)
              if (seqRollback.rolledBack) {
                throw new Error(
                  `Document rollback detected for ${documentId}: ` +
                  `server returned seq ${latestSeq}, pinned seq ${seqRollback.pinnedSeq}`
                )
              }
              // Check for fork (same seq, different hash)
              const pin = await getDocumentStatePin(documentId)
              if (pin && latestSeq === pin.latestSeq && latestUpdate.update_hash !== pin.latestUpdateHash) {
                throw new Error(
                  `Document fork detected for ${documentId} at seq ${latestSeq}: ` +
                  `server hash differs from pinned hash`
                )
              }
            }
          }

          // Fetch device signing public keys for verification
          const deviceKeyCache = new Map<string, Uint8Array>()
          const deviceEcdhKeyCache = new Map<string, Uint8Array>()
          if (updates.length > 0) {
            const devicesResponse = await deviceApi.listDevices()
            for (const dev of devicesResponse.devices) {
              const signingPk = base64UrlDecode(dev.signing_public_key)
              const ecdhPk = base64UrlDecode(dev.ecdh_public_key)
              deviceKeyCache.set(dev.id, signingPk)
              deviceEcdhKeyCache.set(dev.id, ecdhPk)

              // Verify TOFU for all devices on list retrieval
              if (auth) {
                const tofuResult = await verifyTofu(auth.userId, dev.id, signingPk, ecdhPk)
                if (tofuResult.status === 'ecdh_key_mismatch') {
                  throw new Error(`TOFU violation: device ${dev.id} ECDH key mismatch`)
                }
                if (tofuResult.status === 'identity_key_changed') {
                  if (!cancelled) {
                    setTofuKeyChangeWarning({
                      deviceId: dev.id,
                      oldFingerprint: tofuResult.oldFingerprint!,
                      newFingerprint: tofuResult.newFingerprint!,
                      tofuResult,
                    })
                    setIsLoading(false)
                  }
                  return null
                }
                await handleTofuResult(tofuResult)
              }
            }
          }

          let prevUpdateHash: string | null = null
          for (const [index, update] of updates.entries()) {
            const encryptedData = base64UrlDecode(update.update_data)
            const nonce = base64UrlDecode(update.nonce)

            // --- Read-time verification pipeline ---
            if (!auth) {
              throw new Error('Cannot verify document updates: not authenticated')
            }

            const authorDeviceId = update.author_device_id
            const signingPubKey = deviceKeyCache.get(authorDeviceId)
            const ecdhPubKey = deviceEcdhKeyCache.get(authorDeviceId)

            // Note: In Phase 3+ (multi-user), we'll need an API to fetch other users' device keys.
            // For now (single-user), all updates are from the current user's devices.
            if (!signingPubKey || !ecdhPubKey) {
              throw new Error(
                `Cannot verify update at index ${index}: unknown author device ${authorDeviceId}. ` +
                `Device may belong to another user (multi-user verification not yet implemented).`
              )
            }

            // 1. TOFU: verify author device identity key
            const tofuResult = await verifyTofu(auth.userId, authorDeviceId, signingPubKey, ecdhPubKey)
            if (tofuResult.status === 'identity_key_changed') {
              // Per spec: show confirmation dialog, allow user to trust and continue
              if (!cancelled) {
                setTofuKeyChangeWarning({
                  deviceId: authorDeviceId,
                  oldFingerprint: tofuResult.oldFingerprint!,
                  newFingerprint: tofuResult.newFingerprint!,
                  tofuResult,
                })
                setIsLoading(false)
              }
              // Abort this init attempt; will retry after user confirms
              return null
            }
            if (tofuResult.status === 'ecdh_key_mismatch') {
              throw new Error(`TOFU violation: device ${authorDeviceId} ECDH key mismatch`)
            }
            // first_seen or known_trusted: auto-handle
            await handleTofuResult(tofuResult)

            // 2. Revocation check
            const revoked = await isRevocationRolledBack(auth.userId, authorDeviceId)
            if (revoked) {
              throw new Error(`Revoked device ${authorDeviceId} authored update at seq ${(update as Record<string, unknown>).seq}`)
            }

            // 3. Signature verification + update_hash recomputation
            verifyDocumentUpdate({
              signingPublicKey: signingPubKey,
              documentId,
              encryptedContent: update.update_data,
              nonce: update.nonce,
              keyVersion: update.key_version,
              updateHash: update.update_hash,
              prevUpdateHash: update.prev_update_hash ?? null,
              signature: update.signature,
              authorDeviceId,
              timestamp: update.timestamp,
            })

            // 4. Verify hash chain continuity
            if (prevUpdateHash !== null && update.prev_update_hash !== prevUpdateHash) {
              throw new Error(
                `Hash chain broken at update index ${index}: ` +
                `expected prev_update_hash=${prevUpdateHash}, got=${update.prev_update_hash}`
              )
            }

            // Decrypt update with DEK
            let decryptedUpdate: Uint8Array
            try {
              decryptedUpdate = decryptContent(encryptedData, nonce, dek, documentId, update.key_version)
            } catch (decryptErr) {
              console.error('[Content Decrypt] FAILED at update index:', index, decryptErr)
              throw decryptErr
            }

            // Apply to Y.Doc
            Y.applyUpdate(newYDoc, decryptedUpdate)

            // Track the latest update hash for chain verification
            prevUpdateHash = update.update_hash
          }

          // Anti-rollback: pin document state after loading updates
          if (updates.length > 0) {
            const lastUpdate = updates[updates.length - 1]
            const lastSeq: number = (lastUpdate as Record<string, unknown>).seq as number
            if (lastSeq != null) {
              await pinDocumentState({
                documentId,
                latestSeq: lastSeq,
                latestUpdateHash: lastUpdate.update_hash,
                observedAt: Date.now(),
              })
            }
          }

          // 4. Save initial state for dirty tracking
          const lastSavedState = Y.encodeStateAsUpdate(newYDoc)

          // 5. Create shared state
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
      if (!cancelled) {
        if (state) {
          setYDoc(state.yDoc)
          const yText = state.yDoc.getText('content')
          setContent(yText.toString())
        }
        setIsLoading(false)
      }
    }

    initializeYDoc()

    return () => {
      cancelled = true
    }
  }, [document, kek, auth, documentId, tofuRetryTrigger])

  // Save function
  const save = useCallback(async () => {
    const state = documentCache.get(documentId)
    if (!state || !auth || !device || state.isSaving) {
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
      const { encrypted, nonce } = encryptContent(updateToSave, state.dek, documentId, state.keyVersion)

      const timestamp = Date.now()
      const encryptedContentB64 = base64UrlEncode(encrypted)
      const nonceB64 = base64UrlEncode(nonce)

      // Compute update hash using JCS-normalized BLAKE3
      const updateHash = computeUpdateHash({
        documentId,
        encryptedContent: encryptedContentB64,
        nonce: nonceB64,
        keyVersion: state.keyVersion,
        prevUpdateHash: state.prevUpdateHash,
        timestamp,
        authorDeviceId: device.deviceId,
      })

      // Sign update metadata with device signing key
      const signature = signDocumentUpdate({
        signingPrivateKey: device.deviceKeys.signingPrivateKey,
        documentId,
        updateHash,
        prevUpdateHash: state.prevUpdateHash,
        keyVersion: state.keyVersion,
        timestamp,
      })

      // Send to server
      let saveResult: { seq: number } | undefined
      try {
        saveResult = await documentApi.createUpdate(documentId, {
          update_data: encryptedContentB64,
          nonce: nonceB64,
          key_version: state.keyVersion,
          update_hash: updateHash,
          prev_update_hash: state.prevUpdateHash,
          signature: base64UrlEncode(signature),
          author_device_id: device.deviceId,
          timestamp,
        })
      } catch (saveErr) {
        // If key version is too old (DEK was rotated), refresh DEK and retry
        if (saveErr instanceof ApiError && saveErr.status === 400 && kek) {
          if (saveErr.body?.error?.includes('key version too old')) {
            console.log('[Save] DEK version outdated, refreshing...')
            const keyResponse = await encryptionApi.getDocumentKey(documentId)
            const freshEncryptedDek = base64UrlDecode(keyResponse.encrypted_dek)
            const freshNonce = base64UrlDecode(keyResponse.nonce)
            const doc = document
            if (!doc) throw saveErr
            const freshDek = unwrapDek(freshEncryptedDek, freshNonce, kek, documentId, doc.workspace_id)

            // Anti-rollback: check refreshed DEK version
            const freshDekRollback = await checkKeyVersionRollback('dek', documentId, keyResponse.key_version)
            if (freshDekRollback.rolledBack) {
              throw new Error(
                `DEK rollback detected for document ${documentId}: ` +
                `refreshed v${keyResponse.key_version}, pinned v${freshDekRollback.pinnedVersion}`
              )
            }
            await pinKeyVersion({
              type: 'dek',
              id: documentId,
              highestVersion: keyResponse.key_version,
              observedAt: Date.now(),
            })

            state.dek = freshDek
            state.keyVersion = keyResponse.key_version

            // Re-encrypt with new DEK
            const { encrypted: reEncrypted, nonce: reNonce } = encryptContent(updateToSave, freshDek, documentId, state.keyVersion)
            const reTimestamp = Date.now()
            const reEncB64 = base64UrlEncode(reEncrypted)
            const reNonceB64 = base64UrlEncode(reNonce)

            const reHash = computeUpdateHash({
              documentId,
              encryptedContent: reEncB64,
              nonce: reNonceB64,
              keyVersion: state.keyVersion,
              prevUpdateHash: state.prevUpdateHash,
              timestamp: reTimestamp,
              authorDeviceId: device.deviceId,
            })

            const reSig = signDocumentUpdate({
              signingPrivateKey: device.deviceKeys.signingPrivateKey,
              documentId,
              updateHash: reHash,
              prevUpdateHash: state.prevUpdateHash,
              keyVersion: state.keyVersion,
              timestamp: reTimestamp,
            })

            const retryResult = await documentApi.createUpdate(documentId, {
              update_data: reEncB64,
              nonce: reNonceB64,
              key_version: state.keyVersion,
              update_hash: reHash,
              prev_update_hash: state.prevUpdateHash,
              signature: base64UrlEncode(reSig),
              author_device_id: device.deviceId,
              timestamp: reTimestamp,
            })

            // Anti-rollback: pin document state after retry save
            if (retryResult?.seq != null) {
              await pinDocumentState({
                documentId,
                latestSeq: retryResult.seq,
                latestUpdateHash: reHash,
                observedAt: Date.now(),
              })
            }

            state.lastSavedState = currentState
            state.prevUpdateHash = reHash
            state.isDirty = false
            setIsDirty(false)
            return
          }
        }
        throw saveErr
      }

      // Anti-rollback: pin document state after successful save
      if (saveResult?.seq != null) {
        await pinDocumentState({
          documentId,
          latestSeq: saveResult.seq,
          latestUpdateHash: updateHash,
          observedAt: Date.now(),
        })
      }

      // Update saved state and chain hash
      state.lastSavedState = currentState
      state.prevUpdateHash = updateHash
      state.isDirty = false
      setIsDirty(false)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to save document'))
    } finally {
      state.isSaving = false
      setIsSaving(false)
    }
  }, [documentId, auth, device, kek, document])

  // Handle KEK loading/error
  useEffect(() => {
    if (kekError) {
      setError(kekError)
      setIsLoading(false)
    }
  }, [kekError])

  // TOFU key change confirmation callback (per spec: identity_key_changed allows user to trust and continue)
  const confirmTofuKeyChange = useCallback(
    (trust: boolean) => {
      if (!tofuKeyChangeWarning) return
      if (trust) {
        // Trust the new key and retry initialization
        trustDevice(tofuKeyChangeWarning.tofuResult.newEntry).then(() => {
          setTofuKeyChangeWarning(null)
          setIsLoading(true)
          // Clear cached state so init re-runs
          documentCache.delete(documentId)
          initializingPromises.delete(documentId)
          setTofuRetryTrigger((n) => n + 1)
        })
      } else {
        // User rejected — set error
        setTofuKeyChangeWarning(null)
        setError(
          new Error(
            `Identity key change rejected for device ${tofuKeyChangeWarning.deviceId}`
          )
        )
      }
    },
    [tofuKeyChangeWarning, documentId]
  )

  return {
    document,
    yDoc,
    content,
    isLoading: isLoading || kekLoading,
    error,
    isDirty,
    isSaving,
    save,
    tofuKeyChangeWarning,
    confirmTofuKeyChange,
  }
}
