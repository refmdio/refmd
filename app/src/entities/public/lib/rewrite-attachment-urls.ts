import { API_BASE_URL } from '@/shared/lib/config'

/**
 * Rewrites attachment URLs in markdown content for public pages.
 * Transforms relative paths like `./attachments/filename.ext` or `attachments/filename.ext`
 * to the public files API endpoint: `/api/public/workspaces/{slug}/{id}/files/{filename}`
 */
export function rewritePublicAttachmentUrls(
  content: string,
  slug: string,
  documentId: string
): string {
  // Match patterns like:
  // - ./attachments/filename.ext
  // - attachments/filename.ext
  // Captures the full filename including extension
  const attachmentPattern = /(?:\.\/)?attachments\/([^)\s"']+)/gi

  const apiBase = API_BASE_URL || ''

  return content.replace(attachmentPattern, (_match, filename: string) => {
    // Build the public files API URL with the full filename
    return `${apiBase}/api/public/workspaces/${encodeURIComponent(slug)}/${encodeURIComponent(documentId)}/files/${encodeURIComponent(filename)}`
  })
}
