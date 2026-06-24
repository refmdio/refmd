import { describe, expect, it } from 'vitest'

import type { DocumentCommentThread } from '@/entities/document'

import type { DocumentEditorApi } from '@/features/plugins'

import { findCommentThreadRange, getCommentThreadLine } from './thread-range'

function commentThread(
  overrides: Partial<DocumentCommentThread> = {},
): DocumentCommentThread {
  return {
    id: 'thread-1',
    documentId: 'doc-1',
    marker: '<!--comment:thread-1-->',
    quote: 'target',
    startLineNumber: 1,
    startColumn: 1,
    endLineNumber: 1,
    endColumn: 7,
    startOffset: 0,
    endOffset: 6,
    anchored: true,
    tags: [],
    createdBy: null,
    createdByName: null,
    createdAt: '2026-06-24T00:00:00.000Z',
    updatedAt: '2026-06-24T00:00:00.000Z',
    resolvedAt: null,
    resolvedBy: null,
    replies: [],
    ...overrides,
  }
}

const rangeEditor = {
  getRangeFromOffset: (offset: number, length = 0) => ({
    startLineNumber: offset,
    startColumn: length,
    endLineNumber: offset,
    endColumn: offset + length,
  }),
} as DocumentEditorApi

describe('comment thread range lookup', () => {
  it('uses the live marker before stale offsets when quote matching fails', () => {
    const content = 'changed text<!--comment:thread-1-->'
    const markerIndex = content.indexOf('<!--comment:thread-1-->')

    expect(
      findCommentThreadRange(
        commentThread({
          quote: 'original text',
          startOffset: 0,
          endOffset: 8,
        }),
        content,
        rangeEditor,
      ),
    ).toEqual({
      startLineNumber: markerIndex,
      startColumn: '<!--comment:thread-1-->'.length,
      endLineNumber: markerIndex,
      endColumn: markerIndex + '<!--comment:thread-1-->'.length,
    })
  })
})

describe('comment thread line lookup', () => {
  it('prefers the live marker over stale stored line metadata', () => {
    const content = [
      'inserted line',
      'another inserted line',
      'target<!--comment:thread-1-->',
    ].join('\n')

    expect(getCommentThreadLine(commentThread({ startLineNumber: 1 }), content))
      .toBe(3)
  })

  it('falls back to stored line metadata when the marker is missing', () => {
    expect(
      getCommentThreadLine(commentThread({ startLineNumber: 4 }), 'target'),
    ).toBe(4)
  })
})
