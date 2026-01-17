/**
 * useExport Hook
 *
 * Provides E2EE-compliant document export functionality.
 * All conversion happens client-side after decryption.
 */

import { useCallback, useState } from 'react'
import * as Y from 'yjs'

import {
  getDocumentContent,
  type EncryptedUpdateEntry,
} from '@/shared/api/client'


import {
  resolveAndDecrypt,
  initFileMap,
} from '@/entities/file/decryption-bridge'

import {
  decrypt,
  fetchDocumentKeys,
  getSodium,
} from '@/features/security'

import { createDocumentArchive } from '../lib/archive'
import {
  type ExportFormat,
  getExtension,
  getPandocFormat,
  getFormatMetadata,
  sanitizeFilename,
} from '../lib/formats'
import { exportWithPandoc, preloadPandoc } from '../lib/pandoc'
import { exportToPdf, type PdfExportOptions } from '../lib/pdf'

export interface UseExportOptions {
  documentId: string
  workspaceId: string
  title: string
}

export interface ExportState {
  isExporting: boolean
  progress: string | null
  error: string | null
}

export interface UseExportResult {
  exportDocument: (format: ExportFormat) => Promise<void>
  state: ExportState
}

/**
 * Fetch and decrypt document content
 */
async function fetchDecryptedMarkdown(
  documentId: string,
  workspaceId: string
): Promise<string> {
  // Fetch content from API
  const contentRes = await getDocumentContent({ id: documentId })

  const hasSnapshot = contentRes.content && contentRes.content.length > 0
  const hasUpdates = contentRes.updates && contentRes.updates.length > 0

  if (!hasSnapshot && !hasUpdates) {
    return ''
  }

  const sodium = await getSodium()
  const doc = new Y.Doc()

  try {
    // Get encryption keys
    const { dek } = await fetchDocumentKeys(documentId, workspaceId)

    // Apply snapshot if present
    if (hasSnapshot) {
      const encryptedContent = sodium.from_base64(contentRes.content, sodium.base64_variants.ORIGINAL)
      const nonce = sodium.from_base64(contentRes.nonce!, sodium.base64_variants.ORIGINAL)
      const yjsState = await decrypt(dek, encryptedContent, nonce)
      Y.applyUpdateV2(doc, yjsState)
    }

    // Apply pending updates
    if (hasUpdates) {
      for (const update of contentRes.updates as EncryptedUpdateEntry[]) {
        const encryptedData = sodium.from_base64(update.data, sodium.base64_variants.ORIGINAL)
        const nonce = sodium.from_base64(update.nonce!, sodium.base64_variants.ORIGINAL)
        const yjsUpdate = await decrypt(dek, encryptedData, nonce)
        Y.applyUpdateV2(doc, yjsUpdate)
      }
    }

    return doc.getText('content').toString()
  } finally {
    doc.destroy()
  }
}

/**
 * Create attachment resolver that returns Blob
 * Used for pandoc exports (DOCX, EPUB, etc.)
 */
function createBlobAttachmentResolver(
  documentId: string
): (path: string) => Promise<Blob | null> {
  return async (path: string): Promise<Blob | null> => {
    try {
      const result = await resolveAndDecrypt(path, documentId)
      if (!result) {
        return null
      }

      // Fetch the blob from the blob URL
      const response = await fetch(result.blobUrl)
      return await response.blob()
    } catch (error) {
      console.warn('[Export] Failed to resolve attachment:', path, error)
      return null
    }
  }
}

/**
 * Create attachment resolver for PDF export
 * Converts blob URLs to base64 data URIs
 */
function createDataUriAttachmentResolver(
  documentId: string
): (path: string) => Promise<string | null> {
  return async (path: string): Promise<string | null> => {
    try {
      const result = await resolveAndDecrypt(path, documentId)
      if (!result) {
        return null
      }

      // Fetch the blob and convert to data URI
      const response = await fetch(result.blobUrl)
      const blob = await response.blob()

      return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onloadend = () => resolve(reader.result as string)
        reader.onerror = reject
        reader.readAsDataURL(blob)
      })
    } catch (error) {
      console.warn('[Export] Failed to resolve attachment:', path, error)
      return null
    }
  }
}

/**
 * Convert markdown to the requested format
 */
async function convertToFormat(
  markdown: string,
  format: ExportFormat,
  title: string,
  documentId?: string,
  workspaceId?: string
): Promise<Blob> {
  const meta = getFormatMetadata(format)

  // Special handling: Archive (ZIP)
  if (meta.isArchive) {
    return createDocumentArchive(markdown, sanitizeFilename(title))
  }

  // Initialize file map if documentId is provided (needed for all formats with attachments)
  if (documentId && workspaceId) {
    await initFileMap(documentId, workspaceId)
  }

  // Special handling: PDF (pandoc → HTML → browser print)
  if (meta.useHtml2Pdf) {
    const options: PdfExportOptions = {}

    if (documentId) {
      options.documentId = documentId
      options.resolveAttachment = createDataUriAttachmentResolver(documentId)
    }

    return exportToPdf(markdown, title, options)
  }

  // Plain markdown - no conversion needed
  if (format === 'markdown') {
    return new Blob([markdown], { type: meta.mimeType })
  }

  // All other formats: use pandoc-wasm
  const pandocFormat = getPandocFormat(format)
  if (!pandocFormat) {
    throw new Error(`Unsupported format: ${format}`)
  }

  return exportWithPandoc(markdown, pandocFormat, meta.mimeType, {
    standalone: true,
    title,
    resolveAttachment: documentId ? createBlobAttachmentResolver(documentId) : undefined,
  })
}

/**
 * Trigger file download
 */
function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    link.style.display = 'none'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  } finally {
    URL.revokeObjectURL(url)
  }
}

/**
 * Hook for exporting documents with E2EE support
 */
export function useExport(options: UseExportOptions): UseExportResult {
  const { documentId, workspaceId, title } = options
  const [state, setState] = useState<ExportState>({
    isExporting: false,
    progress: null,
    error: null,
  })

  const exportDocument = useCallback(
    async (format: ExportFormat) => {
      setState({ isExporting: true, progress: 'Decrypting document...', error: null })

      try {
        // 1. Fetch and decrypt content
        const markdown = await fetchDecryptedMarkdown(documentId, workspaceId)
        const sanitizedTitle = sanitizeFilename(title)

        // 2. Convert to requested format
        setState(prev => ({ ...prev, progress: `Converting to ${format}...` }))

        const blob = await convertToFormat(markdown, format, title, documentId, workspaceId)
        const filename = `${sanitizedTitle}.${getExtension(format)}`

        // 3. Download
        setState(prev => ({ ...prev, progress: 'Downloading...' }))
        downloadBlob(blob, filename)

        setState({ isExporting: false, progress: null, error: null })
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Export failed'
        setState({ isExporting: false, progress: null, error: message })
        throw error
      }
    },
    [documentId, workspaceId, title]
  )

  return { exportDocument, state }
}

/**
 * Standalone export function for use outside of React components
 */
export async function exportDocumentFile(
  documentId: string,
  workspaceId: string,
  title: string,
  format: ExportFormat
): Promise<string> {
  // Fetch and decrypt content
  const markdown = await fetchDecryptedMarkdown(documentId, workspaceId)
  const sanitizedTitle = sanitizeFilename(title)

  // Convert to requested format
  const blob = await convertToFormat(markdown, format, title, documentId, workspaceId)
  const filename = `${sanitizedTitle}.${getExtension(format)}`

  // Download
  downloadBlob(blob, filename)

  return filename
}

/**
 * Preload pandoc-wasm in background (call when export dialog opens)
 */
export { preloadPandoc }
