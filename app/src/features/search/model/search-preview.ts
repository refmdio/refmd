import type { DocumentCommentThread } from '@/entities/document'

import { stripCommentMarkers } from '@/features/document-comments'

export function sanitizeSearchPreviewContent(
  content: string,
  threads: readonly DocumentCommentThread[],
) {
  return stripCommentMarkers(
    content,
    threads.map((thread) => thread.marker),
  )
}
