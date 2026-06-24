import type { DocumentCommentThread } from '@/entities/document'

import type { DocumentEditorApi, DocumentEditorRange } from '@/features/plugins'

export function findCommentMarkerRange(
  thread: DocumentCommentThread,
  content: string,
  editor: DocumentEditorApi,
): DocumentEditorRange | null {
  const markerIndex = content.indexOf(thread.marker)
  if (markerIndex < 0) return null
  return editor.getRangeFromOffset(markerIndex, thread.marker.length)
}

export function findCommentThreadRange(
  thread: DocumentCommentThread,
  content: string,
  editor: DocumentEditorApi,
): DocumentEditorRange | null {
  const markerIndex = content.indexOf(thread.marker)
  if (markerIndex >= 0 && thread.quote) {
    const quoteStart = Math.max(0, markerIndex - thread.quote.length)
    if (content.slice(quoteStart, markerIndex) === thread.quote) {
      return editor.getRangeFromOffset(quoteStart, thread.quote.length)
    }
  }

  if (markerIndex >= 0) {
    return editor.getRangeFromOffset(markerIndex, thread.marker.length)
  }

  if (
    typeof thread.startOffset === 'number' &&
    typeof thread.endOffset === 'number' &&
    thread.endOffset > thread.startOffset
  ) {
    const length = thread.endOffset - thread.startOffset
    return editor.getRangeFromOffset(thread.startOffset, length)
  }

  if (thread.startLineNumber && thread.startColumn) {
    return {
      startLineNumber: thread.startLineNumber,
      startColumn: thread.startColumn,
      endLineNumber: thread.endLineNumber ?? thread.startLineNumber,
      endColumn: thread.endColumn ?? thread.startColumn,
    }
  }

  return null
}

export function getCommentThreadLine(
  thread: DocumentCommentThread,
  content: string,
) {
  const markerIndex = content.indexOf(thread.marker)
  if (markerIndex >= 0) {
    return content.slice(0, markerIndex).split('\n').length
  }

  if (thread.startLineNumber && Number.isFinite(thread.startLineNumber)) {
    return Math.max(1, Math.floor(thread.startLineNumber))
  }

  return null
}
