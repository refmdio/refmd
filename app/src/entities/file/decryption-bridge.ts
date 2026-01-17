/**
 * Decryption Bridge for Web Components
 *
 * Provides a global interface for Web Components to request file decryption
 * without direct access to React context.
 */

import { API_BASE_URL } from '@/shared/lib/config'

import {
  downloadAttachment,
  extractDocumentIdFromUrl,
  buildFileMap,
  type FileMap,
  type FileMapEntry,
} from './api'

/** Decryption context set by React app */
interface DecryptionContext {
  /** Document encryption key */
  dek: Uint8Array | null
  token?: string
}

const contextRegistry = new Map<string, DecryptionContext>()
let defaultContext: DecryptionContext | null = null

// File map registry: documentId → FileMap
const fileMapRegistry = new Map<string, FileMap>()
const fileMapInitPromises = new Map<string, Promise<FileMap>>()
// Store DEK used for each document's file map (for fallback context)
const fileMapDekRegistry = new Map<string, Uint8Array>()

// Blob URL cache: "documentId:logicalPath" → { blobUrl, filename, mimeType }
// This ensures each unique path gets a consistent blob URL across renders
const blobUrlCache = new Map<string, { blobUrl: string; filename: string; mimeType: string }>()
// In-flight decryption requests to prevent duplicate downloads
const pendingDecryptions = new Map<string, Promise<{ blobUrl: string; filename: string; mimeType: string } | null>>()

/**
 * Set decryption context for a specific document
 */
export function setDecryptionContext(documentId: string, context: DecryptionContext): void {
  contextRegistry.set(documentId, context)
}

/**
 * Remove decryption context for a document
 */
export function clearDecryptionContext(documentId: string): void {
  contextRegistry.delete(documentId)
}

/**
 * Set default decryption context (used when documentId is not in registry)
 */
export function setDefaultDecryptionContext(context: DecryptionContext | null): void {
  defaultContext = context
}

/**
 * Get decryption context for a document
 */
export function getDecryptionContext(documentId: string): DecryptionContext | null {
  return contextRegistry.get(documentId) ?? defaultContext
}

/**
 * Download and decrypt a file, returning a blob URL
 *
 * @param url - File URL
 * @param documentIdHint - Optional documentId hint for URLs that don't include it
 * @returns Object with blob URL, filename, and mimeType, or null if decryption fails
 */
export async function downloadAndDecrypt(
  url: string,
  documentIdHint?: string
): Promise<{ blobUrl: string; filename: string; mimeType: string } | null> {
  // Try to extract documentId from URL, fall back to hint
  let documentId = extractDocumentIdFromUrl(url)
  if (!documentId && documentIdHint) {
    documentId = documentIdHint
  }
  if (!documentId) {
    console.warn('[Decrypt] Could not extract documentId from URL:', url)
    return null
  }

  const context = getDecryptionContext(documentId) ?? defaultContext
  // Fallback to DEK stored during initFileMap if context is not available
  // This handles race conditions during SPA navigation where cleanup runs after new context is set
  const dek = context?.dek ?? fileMapDekRegistry.get(documentId)
  if (!dek) {
    console.warn('[Decrypt] No DEK available for document:', documentId)
    return null
  }

  try {
    const result = await downloadAttachment(documentId, url, {
      dek,
      token: context?.token,
    })

    const blobUrl = URL.createObjectURL(result.blob)
    return {
      blobUrl,
      filename: result.filename,
      mimeType: result.mimeType,
    }
  } catch (error) {
    console.error('[Decrypt] Failed to decrypt file:', error)
    return null
  }
}

/**
 * Resolve a logical path and decrypt the file
 *
 * This is the unified entry point for decrypting files from logical paths.
 * It handles: file map lookup → API URL construction → download & decrypt
 *
 * @param logicalPath - Logical path (e.g., "./attachments/photo.png" or "attachments/photo.png")
 * @param documentId - Document ID
 * @returns Object with blob URL, filename, and mimeType, or null if failed
 */
export async function resolveAndDecrypt(
  logicalPath: string,
  documentId: string
): Promise<{ blobUrl: string; filename: string; mimeType: string } | null> {
  // Normalize path (remove leading ./)
  const normalizedPath = logicalPath.startsWith('./') ? logicalPath.slice(2) : logicalPath
  const cacheKey = `${documentId}:${normalizedPath}`

  // Check cache first
  const cached = blobUrlCache.get(cacheKey)
  if (cached) {
    return cached
  }

  // Check if there's already a pending request for this path
  const pending = pendingDecryptions.get(cacheKey)
  if (pending) {
    return pending
  }

  // Create the decryption promise
  const decryptionPromise = (async (): Promise<{ blobUrl: string; filename: string; mimeType: string } | null> => {
    try {
      // Wait for file map to be ready
      let fileMap = await waitForFileMap(documentId)

      // If file map not initialized yet, try to initialize with default context
      // This handles SPA navigation where the context is set but initFileMap hasn't been called yet
      if (!fileMap) {
        const context = getDecryptionContext(documentId) ?? defaultContext
        if (context?.dek) {
          fileMap = await initFileMap(documentId, context.dek)
        }
      }

      if (!fileMap) {
        console.warn('[resolveAndDecrypt] No file map available for document:', documentId)
        return null
      }

      // Look up file entry directly from the returned map (not from registry again)
      // This avoids race conditions where the registry might have changed
      const fileEntry = fileMap.get(normalizedPath)
      if (!fileEntry) {
        return null
      }

      // Build API URL and decrypt
      const apiUrl = `${API_BASE_URL}/api/files/${fileEntry.fileId}`
      const result = await downloadAndDecrypt(apiUrl, documentId)

      // Cache successful results
      if (result) {
        blobUrlCache.set(cacheKey, result)
      }

      return result
    } finally {
      pendingDecryptions.delete(cacheKey)
    }
  })()

  pendingDecryptions.set(cacheKey, decryptionPromise)
  return decryptionPromise
}

/**
 * Revoke a blob URL to free memory
 */
export function revokeBlobUrl(blobUrl: string): void {
  try {
    URL.revokeObjectURL(blobUrl)
  } catch {
    // Ignore errors
  }
}

/**
 * Initialize file map for a document
 *
 * This fetches the file list and decrypts metadata to build a
 * logicalPath → fileId mapping.
 *
 * @param documentId - Document ID
 * @param dek - Document encryption key
 * @param token - Optional share token for authentication
 */
export async function initFileMap(documentId: string, dek: Uint8Array, token?: string): Promise<FileMap> {
  // Check if initialization is in progress
  const inProgress = fileMapInitPromises.get(documentId)
  if (inProgress) {
    return inProgress
  }

  // Check if already initialized (and no pending uploads)
  const existing = fileMapRegistry.get(documentId)
  if (existing && existing.size > 0) {
    return existing
  }

  // Store DEK for fallback context
  fileMapDekRegistry.set(documentId, dek)

  // Start initialization
  const initPromise = (async () => {
    try {
      const fileMap = await buildFileMap(documentId, dek, token)

      // Merge with any entries added while we were fetching
      // (e.g., from concurrent uploads via addFileToMap)
      const currentMap = fileMapRegistry.get(documentId)
      if (currentMap) {
        for (const [key, value] of currentMap) {
          // Only add if not already in server response
          if (!fileMap.has(key)) {
            fileMap.set(key, value)
          }
        }
      }

      fileMapRegistry.set(documentId, fileMap)
      return fileMap
    } finally {
      fileMapInitPromises.delete(documentId)
    }
  })()

  fileMapInitPromises.set(documentId, initPromise)
  return initPromise
}

/**
 * Get file map for a document (must be initialized first)
 */
export function getFileMap(documentId: string): FileMap | undefined {
  return fileMapRegistry.get(documentId)
}

/**
 * Wait for file map initialization to complete
 * Returns the file map if initialized, or waits for pending initialization
 */
export async function waitForFileMap(documentId: string): Promise<FileMap | undefined> {
  const existing = fileMapRegistry.get(documentId)
  if (existing) {
    return existing
  }

  const pending = fileMapInitPromises.get(documentId)
  if (pending) {
    return pending
  }

  return undefined
}

/**
 * Clear file map for a document
 */
export function clearFileMap(documentId: string): void {
  fileMapRegistry.delete(documentId)
  fileMapInitPromises.delete(documentId)
  fileMapDekRegistry.delete(documentId)

  // Also clear blob URL cache for this document
  const prefix = `${documentId}:`
  for (const [key, value] of blobUrlCache) {
    if (key.startsWith(prefix)) {
      try {
        URL.revokeObjectURL(value.blobUrl)
      } catch {
        // Ignore errors
      }
      blobUrlCache.delete(key)
    }
  }

  // Clear any pending decryptions
  for (const key of pendingDecryptions.keys()) {
    if (key.startsWith(prefix)) {
      pendingDecryptions.delete(key)
    }
  }
}

/**
 * Resolve a logical path to a file ID
 *
 * @param documentId - Document ID
 * @param logicalPath - Logical path (e.g., "attachments/photo.png")
 * @returns FileMapEntry if found
 */
export function resolveFileByPath(
  documentId: string,
  logicalPath: string
): FileMapEntry | undefined {
  const fileMap = fileMapRegistry.get(documentId)
  if (!fileMap) {
    return undefined
  }
  return fileMap.get(logicalPath)
}

/**
 * Add a file to the map (used after upload)
 */
export function addFileToMap(documentId: string, entry: FileMapEntry): void {
  let fileMap = fileMapRegistry.get(documentId)
  if (!fileMap) {
    fileMap = new Map()
    fileMapRegistry.set(documentId, fileMap)
  }
  fileMap.set(entry.logicalPath, entry)
}

/**
 * Get existing logical paths for collision detection
 * Waits for file map initialization if pending
 */
export async function getExistingPaths(documentId: string): Promise<Set<string>> {
  const fileMap = await waitForFileMap(documentId)
  if (!fileMap) {
    return new Set()
  }
  return new Set(fileMap.keys())
}

// Expose to global for Web Components
if (typeof window !== 'undefined') {
  ;(window as any).__refmd_file_decryption__ = {
    downloadAndDecrypt,
    resolveAndDecrypt,
    revokeBlobUrl,
    setDecryptionContext,
    clearDecryptionContext,
    setDefaultDecryptionContext,
    getDecryptionContext,
    // File map functions
    initFileMap,
    getFileMap,
    waitForFileMap,
    clearFileMap,
    resolveFileByPath,
    addFileToMap,
    getExistingPaths,
  }
}
