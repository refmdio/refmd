import { buildFileMap } from '@/entities/file'
import { getFile, getDocumentKey, getMyWorkspaceKey } from '@/shared/api'
import { decryptFile, isRmeFile } from '@/features/security/lib/files'
import { getKeyManager } from '@/features/security'
import { uploadPublicFile } from '../api'

export interface UploadPublicFilesOptions {
  documentId: string
  workspaceId: string
}

/**
 * Upload decrypted attachments for a published E2EE document.
 * Downloads each file, decrypts it, and uploads to the public files API.
 */
export async function uploadPublicFilesForDocument(
  options: UploadPublicFilesOptions
): Promise<{ uploaded: number; failed: number }> {
  const { documentId, workspaceId } = options
  const keyManager = getKeyManager()

  if (!keyManager.isUnlocked) {
    console.warn('[uploadPublicFiles] KeyManager not unlocked, skipping')
    return { uploaded: 0, failed: 0 }
  }

  // Build file map to get decrypted metadata
  const fileMap = await buildFileMap(documentId, workspaceId)
  if (fileMap.size === 0) {
    return { uploaded: 0, failed: 0 }
  }

  // Get workspace KEK and document DEK for decryption
  const kekResponse = await getMyWorkspaceKey({ id: workspaceId })
  const kek = await keyManager.getWorkspaceKek(workspaceId, async () => kekResponse.encryptedKek)
  const dekResponse = await getDocumentKey({ id: documentId })
  const dek = await keyManager.getDocumentDek(documentId, kek, async () => ({
    encryptedDek: dekResponse.encryptedDek,
    nonce: dekResponse.nonce,
  }))

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
