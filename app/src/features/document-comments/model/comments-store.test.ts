import { describe, expect, it } from 'vitest'

import {
  buildCommentMarker,
  createCommentId,
  getCommentSubmitAction,
  parseCommentMarkerId,
  parseCommentTags,
} from './comments-store'

describe('comment markers', () => {
  it('round-trips marker ids used in markdown', () => {
    const id = 'abc_DEF-123'

    expect(buildCommentMarker(id)).toBe('<!--comment:abc_DEF-123-->')
    expect(parseCommentMarkerId(buildCommentMarker(id))).toBe(id)
  })

  it('rejects malformed marker syntax', () => {
    expect(parseCommentMarkerId('<!--comment:-->')).toBeNull()
    expect(parseCommentMarkerId('<!-- comment:abc -->')).toBeNull()
    expect(parseCommentMarkerId('<!--comment:abc def-->')).toBeNull()
    expect(parseCommentMarkerId('comment:abc')).toBeNull()
  })

  it('creates ids that are valid marker ids', () => {
    const id = createCommentId()

    expect(id).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(parseCommentMarkerId(buildCommentMarker(id))).toBe(id)
  })
})

describe('comment submit action', () => {
  it('opens the editor when comments are shown in preview-only mode', () => {
    expect(
      getCommentSubmitAction({
        hasEditor: false,
        hasSelection: false,
        hasDraft: false,
        readOnly: false,
        creating: false,
      }),
    ).toEqual({
      label: 'Open editor',
      title: 'Open editor',
      disabled: false,
    })
  })

  it('keeps preview-only comment creation disabled in read-only mode', () => {
    expect(
      getCommentSubmitAction({
        hasEditor: false,
        hasSelection: false,
        hasDraft: true,
        readOnly: true,
        creating: false,
      }).disabled,
    ).toBe(true)
  })

  it('requires an editor position and a draft before creating a thread', () => {
    expect(
      getCommentSubmitAction({
        hasEditor: true,
        hasSelection: true,
        hasDraft: false,
        readOnly: false,
        creating: false,
      }).disabled,
    ).toBe(true)

    expect(
      getCommentSubmitAction({
        hasEditor: true,
        hasSelection: true,
        hasDraft: true,
        readOnly: false,
        creating: false,
      }).disabled,
    ).toBe(false)

    expect(
      getCommentSubmitAction({
        hasEditor: true,
        hasSelection: false,
        hasDraft: true,
        readOnly: false,
        creating: false,
      }).disabled,
    ).toBe(true)
  })
})

describe('comment tags', () => {
  it('normalizes comma-separated tags', () => {
    expect(parseCommentTags(' review, author ,review,,docs ')).toEqual([
      'review',
      'author',
      'docs',
    ])
  })
})
