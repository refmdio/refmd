import {
  uploadFile as apiUploadFile,
  listFiles,
  type ListFileResponse,
} from '@/shared/api'

import { fetchDocumentKeys } from '@/features/security'
import { encryptFile, decryptFile, isRmeFile, decryptMetadata } from '@/features/security/lib/files'

export const fileKeys = {
  all: ['files'] as const,
}

export interface UploadAttachmentOptions {
  /** Workspace ID (required for E2EE) */
  workspaceId: string
  /** Existing logical paths for collision detection */
  existingPaths?: Set<string>
}

/**
 * Upload an attachment with E2EE encryption
 *
 * @param documentId - Document ID
 * @param file - File to upload
 * @param options - Upload options
 */
export async function uploadAttachment(
  documentId: string,
  file: File,
  options: UploadAttachmentOptions
) {
  // 1. Read file content
  const content = new Uint8Array(await file.arrayBuffer())

  // 2. Get encryption keys
  const { dek } = await fetchDocumentKeys(documentId, options.workspaceId)

  // 3. Resolve logical path with collision detection
  const logicalPath = options.existingPaths
    ? resolveLogicalPath(file.name, options.existingPaths)
    : `attachments/${file.name}`

  // 4. Encrypt file
  const result = await encryptFile(content, dek, {
    filename: file.name,
    mimeType: file.type || 'application/octet-stream',
    logicalPath,
  })

  // 5. Create .rme file blob
  const rmeBlob = new Blob([result.rmeBytes as BlobPart], {
    type: 'application/octet-stream',
  })
  const rmeFile = new File([rmeBlob], `${file.name}.rme`, {
    type: 'application/octet-stream',
  })

  // 6. Build metadata JSON for API
  const metadata = JSON.stringify({
    encryptedMetadata: result.encryptedMetadata,
    encryptedMetadataNonce: result.metadataNonce,
    encryptedHash: result.encryptedHash,
  })

  // 7. Upload encrypted file
  const uploadResult = await apiUploadFile({
    docId: documentId,
    formData: {
      file: rmeFile,
      metadata,
    },
  })

  // Return with logicalPath for caller to use
  return {
    ...uploadResult,
    logicalPath,
    originalFilename: file.name,
    mimeType: file.type || 'application/octet-stream',
  }
}

export interface DownloadAttachmentOptions {
  /** Workspace ID (required for E2EE) */
  workspaceId: string
  /** Share token for authentication */
  token?: string
}

export interface DownloadAttachmentResult {
  /** Decrypted file content as Blob */
  blob: Blob
  /** Original filename (from encrypted metadata) */
  filename: string
  /** MIME type (from encrypted metadata) */
  mimeType: string
}

/**
 * Download and decrypt an attachment
 *
 * @param documentId - Document ID
 * @param url - Full URL to the attachment
 * @param options - Download options
 * @returns Decrypted file content and metadata
 */
export async function downloadAttachment(
  documentId: string,
  url: string,
  options: DownloadAttachmentOptions
): Promise<DownloadAttachmentResult> {
  // 1. Fetch the file
  const fetchUrl = options.token
    ? url.includes('?')
      ? `${url}&token=${encodeURIComponent(options.token)}`
      : `${url}?token=${encodeURIComponent(options.token)}`
    : url

  const response = await fetch(fetchUrl, {
    credentials: 'include',
  })
  if (!response.ok) {
    throw new Error(`Failed to download file: ${response.status}`)
  }

  const bytes = new Uint8Array(await response.arrayBuffer())

  // 2. Check if file is encrypted
  if (!isRmeFile(bytes)) {
    // Not encrypted, return as-is
    const contentType =
      response.headers.get('content-type') || 'application/octet-stream'
    const filename = extractFilenameFromUrl(url)
    return {
      blob: new Blob([bytes], { type: contentType }),
      filename,
      mimeType: contentType,
    }
  }

  // 3. Get encryption keys and decrypt
  const { dek } = await fetchDocumentKeys(documentId, options.workspaceId)
  const decrypted = await decryptFile(bytes, dek)

  // 4. Return decrypted content
  return {
    blob: new Blob([decrypted.content as BlobPart], { type: decrypted.metadata.mimeType }),
    filename: decrypted.metadata.filename,
    mimeType: decrypted.metadata.mimeType,
  }
}

/**
 * Extract document ID from attachment URL
 * @param url - URL like /api/uploads/{docId}/attachments/xxx
 */
export function extractDocumentIdFromUrl(url: string): string | null {
  const match = url.match(/\/api\/uploads\/([^/]+)\//)
  return match?.[1] ?? null
}

/**
 * Extract filename from URL
 */
function extractFilenameFromUrl(url: string): string {
  try {
    const path = url.split('?')[0]
    const segments = path.split('/')
    const filename = segments[segments.length - 1] || 'download'
    return decodeURIComponent(filename)
  } catch {
    return 'download'
  }
}

// Re-export for use in file map
export type { ListFileResponse }

/** File map entry with decrypted metadata */
export interface FileMapEntry {
  fileId: string
  logicalPath: string
  filename: string
  mimeType: string
}

/** File map: logicalPath → FileMapEntry */
export type FileMap = Map<string, FileMapEntry>

/**
 * List files for a document (API call only)
 */
export async function listDocumentFiles(documentId: string): Promise<ListFileResponse[]> {
  const response = await listFiles({ docId: documentId })
  return response
}

/**
 * Build a file map for a document by fetching and decrypting file metadata.
 *
 * @param documentId - Document ID
 * @param workspaceId - Workspace ID for key access
 * @returns FileMap with logicalPath → FileMapEntry mapping
 */
export async function buildFileMap(
  documentId: string,
  workspaceId: string
): Promise<FileMap> {
  // 1. Fetch file list
  const files = await listDocumentFiles(documentId)

  // 2. Get encryption keys
  const { dek } = await fetchDocumentKeys(documentId, workspaceId)

  // 3. Build map by decrypting each file's metadata
  const map: FileMap = new Map()

  for (const file of files) {
    if (!file.encryptedMetadata || !file.encryptedMetadataNonce) {
      // Legacy file without E2EE metadata - skip
      continue
    }

    try {
      // Decode base64
      const metadataBytes = Uint8Array.from(atob(file.encryptedMetadata), (c) =>
        c.charCodeAt(0)
      )
      const nonceBytes = Uint8Array.from(atob(file.encryptedMetadataNonce), (c) =>
        c.charCodeAt(0)
      )

      // Decrypt metadata
      const metadata = await decryptMetadata(metadataBytes, nonceBytes, dek)

      map.set(metadata.logicalPath, {
        fileId: file.id,
        logicalPath: metadata.logicalPath,
        filename: metadata.filename,
        mimeType: metadata.mimeType,
      })
    } catch (error) {
      console.warn('[FileMap] Failed to decrypt metadata for file:', file.id, error)
    }
  }

  return map
}

/**
 * Resolve a logical path with collision detection.
 * If a file with the same name already exists, appends a suffix.
 *
 * @param filename - Original filename
 * @param existingPaths - Set of existing logical paths
 * @returns Unique logical path
 */
export function resolveLogicalPath(
  filename: string,
  existingPaths: Set<string>
): string {
  const base = `attachments/${filename}`
  if (!existingPaths.has(base)) {
    return base
  }

  const ext = filename.includes('.') ? filename.slice(filename.lastIndexOf('.')) : ''
  const name = filename.includes('.')
    ? filename.slice(0, filename.lastIndexOf('.'))
    : filename

  let counter = 2
  while (existingPaths.has(`attachments/${name}-${counter}${ext}`)) {
    counter++
  }

  return `attachments/${name}-${counter}${ext}`
}
