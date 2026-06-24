import { describe, expect, it } from 'vitest'

import type { DocumentCommentThread } from '@/entities/document'

import { sanitizeSearchPreviewContent } from './search-preview'

const baseThread = {
  id: 'thread-1',
  documentId: 'doc-1',
  marker: '<!--comment:owned-->',
  quote: '',
  startLineNumber: null,
  startColumn: null,
  endLineNumber: null,
  endColumn: null,
  startOffset: null,
  endOffset: null,
  anchored: true,
  tags: [],
  createdBy: null,
  createdByName: null,
  createdAt: '2026-06-24T00:00:00.000Z',
  updatedAt: '2026-06-24T00:00:00.000Z',
  resolvedAt: null,
  resolvedBy: null,
  replies: [],
} satisfies DocumentCommentThread

describe('sanitizeSearchPreviewContent', () => {
  it('strips persisted comment markers from search previews', () => {
    const content =
      'alpha<!--comment:owned--> beta `<!--comment:manual-->`'

    expect(sanitizeSearchPreviewContent(content, [baseThread])).toBe(
      'alpha beta `<!--comment:manual-->`',
    )
  })
})
