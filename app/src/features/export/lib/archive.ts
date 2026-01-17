/**
 * Archive Export
 *
 * Creates ZIP archives containing markdown and attachments.
 * All processing happens client-side for E2EE compliance.
 */

import JSZip from 'jszip'

export interface ArchiveFile {
  /** Relative path within the archive (e.g., "document.md" or "attachments/image.png") */
  path: string
  /** File content as Blob, string, or Uint8Array */
  content: Blob | string | Uint8Array
}

/**
 * Create a ZIP archive from files
 */
export async function createArchive(files: ArchiveFile[]): Promise<Blob> {
  const zip = new JSZip()

  for (const file of files) {
    if (file.content instanceof Blob) {
      zip.file(file.path, file.content)
    } else if (typeof file.content === 'string') {
      zip.file(file.path, file.content)
    } else {
      zip.file(file.path, file.content)
    }
  }

  return await zip.generateAsync({
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 },
  })
}

/**
 * Create a document archive with markdown and optional attachments
 */
export async function createDocumentArchive(
  markdown: string,
  filename: string,
  attachments?: { name: string; data: Blob | Uint8Array }[]
): Promise<Blob> {
  const files: ArchiveFile[] = [
    {
      path: `${filename}.md`,
      content: markdown,
    },
  ]

  if (attachments && attachments.length > 0) {
    for (const attachment of attachments) {
      files.push({
        path: `attachments/${attachment.name}`,
        content: attachment.data,
      })
    }
  }

  return await createArchive(files)
}

/**
 * Create a workspace archive with multiple documents
 */
export async function createWorkspaceArchive(
  documents: { path: string; content: string; attachments?: { name: string; data: Blob | Uint8Array }[] }[]
): Promise<Blob> {
  const files: ArchiveFile[] = []

  for (const doc of documents) {
    // Add the markdown file
    files.push({
      path: doc.path.endsWith('.md') ? doc.path : `${doc.path}.md`,
      content: doc.content,
    })

    // Add attachments if any
    if (doc.attachments && doc.attachments.length > 0) {
      const docDir = doc.path.replace(/\.md$/, '').replace(/[^/]+$/, '')
      for (const attachment of doc.attachments) {
        files.push({
          path: `${docDir}attachments/${attachment.name}`,
          content: attachment.data,
        })
      }
    }
  }

  return await createArchive(files)
}
