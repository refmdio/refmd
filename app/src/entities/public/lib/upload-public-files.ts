import { getFile } from '@/shared/api'
import { decryptFile, isRmeFile } from '@/shared/lib/files'

import { buildFileMap } from '@/entities/file'

import { uploadPublicFile } from '../api'

export interface UploadPublicFilesOptions {
  documentId: string
  /** Document encryption key */
  dek: Uint8Array
}

/**
 * Upload decrypted attachments for a published E2EE document.
 * Downloads each file, decrypts it, and uploads to the public files API.
 *
 * @param options - Options including document ID and DEK
 */
export async function uploadPublicFilesForDocument(
  options: UploadPublicFilesOptions
): Promise<{ uploaded: number; failed: number }> {
  const { documentId, dek } = options

  // Build file map to get decrypted metadata
  const fileMap = await buildFileMap(documentId, dek)
  if (fileMap.size === 0) {
    return { uploaded: 0, failed: 0 }
  }

  let uploaded = 0
  let failed = 0

  await Promise.all(
    Array.from(fileMap.values()).map(async (fileEntry) => {
      try {
        // Download file using API client
        const fileBlob = await getFile({ id: fileEntry.fileId })
        const encryptedBytes = new Uint8Array(await fileBlob.arrayBuffer())

        // Decrypt file if encrypted
        let decryptedContent: Uint8Array
        let filename = fileEntry.filename
        let mimeType = fileEntry.mimeType

        if (isRmeFile(encryptedBytes)) {
          const decrypted = await decryptFile(encryptedBytes, dek)
          decryptedContent = decrypted.content
          filename = decrypted.metadata.filename
          mimeType = decrypted.metadata.mimeType
        } else {
          decryptedContent = encryptedBytes
        }

        // Convert to base64
        let binary = ''
        for (let i = 0; i < decryptedContent.length; i++) {
          binary += String.fromCharCode(decryptedContent[i])
        }
        const base64Content = btoa(binary)

        // Extract logical filename from logicalPath for matching in markdown
        // logicalPath is like "attachments/filename.png"
        const logicalFilename = fileEntry.logicalPath.split('/').pop() || filename

        // Upload to public files API
        await uploadPublicFile(documentId, fileEntry.fileId, {
          originalFilename: filename,
          mimeType,
          content: base64Content,
          logicalFilename,
        })
        uploaded++
      } catch (err) {
        console.error('[uploadPublicFiles] Failed:', fileEntry.fileId, err)
        failed++
      }
    })
  )

  return { uploaded, failed }
}
