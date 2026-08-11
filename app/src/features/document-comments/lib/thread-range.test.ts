import { describe, expect, it } from 'vitest'

import type { DocumentCommentThread } from '@/entities/document'

import type { DocumentEditorApi } from '@/features/plugins'

import {
  findCommentThreadRange,
  getCommentThreadLine,
  getLineEndOffset,
  isCommentMarkerAloneOnLine,
} from './thread-range'

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
  it('uses stored offsets when adjacent quote matching fails', () => {
    expect(
      findCommentThreadRange(
        commentThread({
          quote: 'original text',
          startOffset: 0,
          endOffset: 8,
        }),
        'changed text<!--comment:thread-1-->',
        rangeEditor,
      ),
    ).toEqual({
      startLineNumber: 0,
      startColumn: 8,
      endLineNumber: 0,
      endColumn: 8,
    })
  })

  it('finds the quote on the previous line when the marker is alone on a line', () => {
    const content = 'alpha target beta\n<!--comment:thread-1-->'

    expect(
      findCommentThreadRange(
        commentThread({ quote: 'target' }),
        content,
        rangeEditor,
      ),
    ).toEqual({
      startLineNumber: 6,
      startColumn: 'target'.length,
      endLineNumber: 6,
      endColumn: 6 + 'target'.length,
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

  it('points at the content line when the marker is alone on the next line', () => {
    const content = 'target text\n<!--comment:thread-1-->'

    expect(getCommentThreadLine(commentThread(), content)).toBe(1)
  })
})

describe('marker line helpers', () => {
  it('detects markers alone on a line', () => {
    expect(
      isCommentMarkerAloneOnLine(
        'hello\n<!--comment:thread-1-->\nworld',
        '<!--comment:thread-1-->',
      ),
    ).toBe(true)
    expect(
      isCommentMarkerAloneOnLine(
        'hello<!--comment:thread-1-->',
        '<!--comment:thread-1-->',
      ),
    ).toBe(false)
  })

  it('computes line end offsets', () => {
    expect(getLineEndOffset('a\nbb\nc', 1)).toBe(1)
    expect(getLineEndOffset('a\nbb\nc', 2)).toBe(4)
    expect(getLineEndOffset('a\nbb\nc', 3)).toBe(6)
  })
})
