import type { DocumentCommentThread } from '@/entities/document'

import type { DocumentEditorApi, DocumentEditorRange } from '@/features/plugins'

import { COMMENT_MARKER_WRAP_BREAK } from '../model/comments-store'

const LONE_MARKER_LINE = /^\u200B?<!--comment:[A-Za-z0-9_-]+-->$/

function markerAnchorStart(content: string, markerIndex: number) {
  if (
    markerIndex > 0 &&
    content[markerIndex - 1] === COMMENT_MARKER_WRAP_BREAK
  ) {
    return markerIndex - 1
  }
  return markerIndex
}

/** True when the marker is the only content on its line (optional leading ZWSP). */
export function isCommentMarkerAloneOnLine(
  content: string,
  marker: string,
  markerIndex = content.indexOf(marker),
) {
  if (markerIndex < 0) return false
  const lineStart = content.lastIndexOf('\n', markerIndex - 1) + 1
  const nextNl = content.indexOf('\n', markerIndex)
  const lineEnd = nextNl < 0 ? content.length : nextNl
  return LONE_MARKER_LINE.test(content.slice(lineStart, lineEnd))
}

export function findCommentMarkerRange(
  thread: DocumentCommentThread,
  content: string,
  editor: DocumentEditorApi,
): DocumentEditorRange | null {
  const markerIndex = content.indexOf(thread.marker)
  if (markerIndex < 0) return null
  const start = markerAnchorStart(content, markerIndex)
  return editor.getRangeFromOffset(
    start,
    markerIndex + thread.marker.length - start,
  )
}

export function findCommentThreadRange(
  thread: DocumentCommentThread,
  content: string,
  editor: DocumentEditorApi,
): DocumentEditorRange | null {
  const markerIndex = content.indexOf(thread.marker)
  if (markerIndex >= 0 && thread.quote) {
    const quoteEnd = markerAnchorStart(content, markerIndex)
    const quoteStart = Math.max(0, quoteEnd - thread.quote.length)
    if (content.slice(quoteStart, quoteEnd) === thread.quote) {
      return editor.getRangeFromOffset(quoteStart, thread.quote.length)
    }

    // Markers live on their own hidden line after the content line. Find the
    // quote on the previous line so highlights stay on the real text.
    if (isCommentMarkerAloneOnLine(content, thread.marker, markerIndex)) {
      const markerLineStart = content.lastIndexOf('\n', markerIndex - 1) + 1
      const prevLineEnd = Math.max(0, markerLineStart - 1)
      const prevLineStart =
        prevLineEnd > 0 ? content.lastIndexOf('\n', prevLineEnd - 1) + 1 : 0
      const prevLine = content.slice(prevLineStart, prevLineEnd)
      const quotePos = prevLine.lastIndexOf(thread.quote)
      if (quotePos >= 0) {
        return editor.getRangeFromOffset(
          prevLineStart + quotePos,
          thread.quote.length,
        )
      }
    }
  }

  if (markerIndex >= 0) {
    // Prefer stored offsets over highlighting the hidden marker itself.
    if (
      typeof thread.startOffset === 'number' &&
      typeof thread.endOffset === 'number' &&
      thread.endOffset > thread.startOffset
    ) {
      const length = thread.endOffset - thread.startOffset
      return editor.getRangeFromOffset(thread.startOffset, length)
    }
    return findCommentMarkerRange(thread, content, editor)
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
    const markerLine = content.slice(0, markerIndex).split('\n').length
    if (isCommentMarkerAloneOnLine(content, thread.marker, markerIndex)) {
      return Math.max(1, markerLine - 1)
    }
    return markerLine
  }

  if (thread.startLineNumber && Number.isFinite(thread.startLineNumber)) {
    return Math.max(1, Math.floor(thread.startLineNumber))
  }

  return null
}

/** 1-based line number → offset of that line's trailing newline, or content.length at EOF. */
export function getLineEndOffset(content: string, lineNumber: number) {
  const target = Math.max(1, Math.floor(lineNumber))
  let line = 1
  let index = 0
  while (line < target && index < content.length) {
    const nl = content.indexOf('\n', index)
    if (nl < 0) return content.length
    index = nl + 1
    line += 1
  }
  if (index >= content.length) return content.length
  const nl = content.indexOf('\n', index)
  return nl < 0 ? content.length : nl
}
