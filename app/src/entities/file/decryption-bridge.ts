/**
 * Decryption Bridge for Web Components
 *
 * Provides a global interface for Web Components to request file decryption
 * without direct access to React context.
 */

import {
  downloadAttachment,
  extractDocumentIdFromUrl,
  buildFileMap,
  type FileMap,
  type FileMapEntry,
} from './api'

/** Decryption context set by React app */
interface DecryptionContext {
  workspaceId: string | null
  token?: string
}

const contextRegistry = new Map<string, DecryptionContext>()
let defaultContext: DecryptionContext | null = null

// File map registry: documentId → FileMap
const fileMapRegistry = new Map<string, FileMap>()
const fileMapInitPromises = new Map<string, Promise<FileMap>>()

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
  if (!context?.workspaceId) {
    console.warn('[Decrypt] No context available for document:', documentId)
    return null
  }

  try {
    const result = await downloadAttachment(documentId, url, {
      workspaceId: context.workspaceId,
      token: context.token,
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
 */
export async function initFileMap(documentId: string, workspaceId: string): Promise<FileMap> {
  // Check if already initialized
  const existing = fileMapRegistry.get(documentId)
  if (existing) {
    return existing
  }

  // Check if initialization is in progress
  const inProgress = fileMapInitPromises.get(documentId)
  if (inProgress) {
    return inProgress
  }

  // Start initialization
  const initPromise = (async () => {
    try {
      const fileMap = await buildFileMap(documentId, workspaceId)
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
 * Clear file map for a document
 */
export function clearFileMap(documentId: string): void {
  fileMapRegistry.delete(documentId)
  fileMapInitPromises.delete(documentId)
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
 */
export function getExistingPaths(documentId: string): Set<string> {
  const fileMap = fileMapRegistry.get(documentId)
  if (!fileMap) {
    return new Set()
  }
  return new Set(fileMap.keys())
}

// Expose to global for Web Components
if (typeof window !== 'undefined') {
  ;(window as any).__refmd_file_decryption__ = {
    downloadAndDecrypt,
    revokeBlobUrl,
    setDecryptionContext,
    clearDecryptionContext,
    setDefaultDecryptionContext,
    getDecryptionContext,
    // File map functions
    initFileMap,
    getFileMap,
    clearFileMap,
    resolveFileByPath,
    addFileToMap,
    getExistingPaths,
  }
}
