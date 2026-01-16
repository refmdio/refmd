/**
 * Effect Handler
 *
 * Processes effects returned by plugin WASM execution.
 * Handles encryption for E2EE documents before sending to server.
 */

import { toast } from 'sonner'

import {
  createDocument as apiCreateDocument,
} from '@/entities/document'
import {
  createPluginRecord as apiCreateRecord,
  updatePluginRecord as apiUpdateRecord,
  deletePluginRecord as apiDeleteRecord,
  putPluginKv as apiPutKv,
} from '@/entities/plugin/api'

import type { Effect } from './wasm-runtime'

/** Context for effect handling */
export interface EffectHandlerContext {
  pluginId: string
  docId: string | null
  workspaceId: string | null
  documentDEK: Uint8Array | null
  token?: string | null
  navigate: (to: string) => void
}

/**
 * Resolve :createdDocId placeholder in a string
 */
function resolveCreatedDocId(value: string, createdDocId: string | null): string {
  if (!createdDocId) return value
  return value.replace(/:createdDocId/g, createdDocId)
}

/**
 * Get the effective docId, resolving :createdDocId if present
 */
function resolveDocId(
  effectDocId: unknown,
  contextDocId: string | null,
  createdDocId: string | null
): string | null {
  if (typeof effectDocId === 'string') {
    const resolved = resolveCreatedDocId(effectDocId, createdDocId)
    if (resolved && resolved !== ':createdDocId') {
      return resolved
    }
  }
  return createdDocId ?? contextDocId
}

/**
 * Handle effects returned by plugin WASM execution.
 *
 * For E2EE documents, data is encrypted before being sent to the server.
 *
 * @param effects - Array of effects to process
 * @param ctx - Effect handler context
 */
export async function handleEffects(
  effects: Effect[],
  ctx: EffectHandlerContext
): Promise<void> {
  // Track document ID created by createDocument effect
  let createdDocId: string | null = null
  // Track DEK for newly created document
  let createdDocDEK: Uint8Array | null = null

  for (const effect of effects) {
    if (!effect || typeof effect !== 'object') continue

    try {
      switch (effect.type) {
        case 'createDocument': {
          const title = typeof effect.title === 'string' ? effect.title : 'Untitled'
          const docType = effect.docType as string | undefined
          const parentId = effect.parentId as string | undefined

          // Create the document
          const response = await apiCreateDocument({
            title,
            parent_id: parentId ?? null,
            type: docType === 'folder' ? 'folder' : 'document',
          })

          // Store the created document ID for subsequent effects
          const newDocId = (response as any)?.id
          if (typeof newDocId === 'string') {
            createdDocId = newDocId

            // Create and fetch DEK for the new document if E2EE is enabled
            if (ctx.workspaceId) {
              try {
                const { createDocumentDekIfNeeded, getDocumentDekForPlugin } = await import('@/features/security/lib/document-keys')
                await createDocumentDekIfNeeded(newDocId, ctx.workspaceId)
                // Fetch the DEK for subsequent effects
                createdDocDEK = await getDocumentDekForPlugin(newDocId, ctx.workspaceId)
              } catch (err) {
                console.warn('[effect-handler] Failed to create/fetch document DEK:', err)
              }
            }
          }
          break
        }

        case 'createRecord': {
          const kind = effect.kind as string
          if (!kind) {
            console.warn('createRecord effect missing kind')
            break
          }

          let data = effect.data
          const docId = resolveDocId(effect.docId, ctx.docId, createdDocId)

          if (!docId) {
            console.warn('createRecord effect: no docId available')
            break
          }

          // E2EE encryption - use createdDocDEK for newly created documents
          const effectDEK = (docId === createdDocId && createdDocDEK) ? createdDocDEK : ctx.documentDEK
          if (data !== undefined) {
            if (!effectDEK) {
              throw new Error(`E2EE: DEK not available for createRecord on document ${docId}`)
            }
            const { encryptRecordData } = await import('@/features/security/lib/plugins')
            data = await encryptRecordData(data, effectDEK, ctx.pluginId)
          }

          await apiCreateRecord(ctx.pluginId, docId, kind, data, ctx.token ?? undefined)
          break
        }

        case 'updateRecord': {
          const recordId = effect.recordId as string
          if (!recordId) {
            console.warn('updateRecord effect missing recordId')
            break
          }

          let patch = effect.patch

          // E2EE encryption (updateRecord doesn't have createdDocId context)
          if (patch !== undefined) {
            if (!ctx.documentDEK) {
              throw new Error(`E2EE: DEK not available for updateRecord ${recordId}`)
            }
            const { encryptRecordData } = await import('@/features/security/lib/plugins')
            patch = await encryptRecordData(patch, ctx.documentDEK, ctx.pluginId)
          }

          await apiUpdateRecord(ctx.pluginId, recordId, patch)
          break
        }

        case 'deleteRecord': {
          const recordId = effect.recordId as string
          if (!recordId) {
            console.warn('deleteRecord effect missing recordId')
            break
          }

          await apiDeleteRecord(ctx.pluginId, recordId)
          break
        }

        case 'putKv': {
          const key = effect.key as string
          if (!key) {
            console.warn('putKv effect missing key')
            break
          }

          let value = effect.value
          const docId = resolveDocId(effect.docId, ctx.docId, createdDocId)

          if (!docId) {
            console.warn('putKv effect: no docId available')
            break
          }

          // E2EE encryption - use createdDocDEK for newly created documents
          const effectDEK = (docId === createdDocId && createdDocDEK) ? createdDocDEK : ctx.documentDEK
          if (value !== null && value !== undefined) {
            if (!effectDEK) {
              throw new Error(`E2EE: DEK not available for putKv on document ${docId}`)
            }
            const { encryptKV } = await import('@/features/security/lib/plugins')
            value = await encryptKV(value, effectDEK, ctx.pluginId)
          }

          await apiPutKv(ctx.pluginId, docId, key, value, ctx.token ?? undefined)
          break
        }

        case 'showToast': {
          const message = effect.message as string
          if (!message) break

          const level = (effect.level as string) ?? 'info'

          switch (level) {
            case 'success':
              toast.success(message)
              break
            case 'warn':
            case 'warning':
              toast.warning?.(message) ?? toast(message)
              break
            case 'error':
              toast.error(message)
              break
            default:
              toast(message)
          }
          break
        }

        case 'navigate': {
          let to = effect.to as string
          if (!to) break

          // Resolve :createdDocId in navigation path
          to = resolveCreatedDocId(to, createdDocId)
          ctx.navigate(to)
          break
        }

        case 'log': {
          const message = effect.message as string ?? ''
          const level = (effect.level as string) ?? 'info'

          switch (level) {
            case 'debug':
              console.debug('[plugin]', message)
              break
            case 'warn':
            case 'warning':
              console.warn('[plugin]', message)
              break
            case 'error':
              console.error('[plugin]', message)
              break
            default:
              console.log('[plugin]', message)
          }
          break
        }

        default:
          console.warn(`Unknown effect type: ${effect.type}`)
      }
    } catch (err) {
      console.error(`Failed to handle effect ${effect.type}:`, err)
    }
  }
}
