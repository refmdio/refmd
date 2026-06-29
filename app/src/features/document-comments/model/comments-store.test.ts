import { describe, expect, it } from 'vitest'

import {
  buildCommentMarker,
  createCommentId,
  createCommentMarkerId,
  findCommentMarkers,
  findUnknownCommentMarkers,
  getCommentSubmitAction,
  parseCommentMarkerId,
  parseCommentTags,
  sanitizeCommentQuote,
  sanitizeStoredCommentQuote,
  stripCommentMarkers,
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
    const id = createCommentMarkerId()

    expect(id).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(parseCommentMarkerId(buildCommentMarker(id))).toBe(id)
  })

  it('uses compact marker ids separately from thread ids', () => {
    const threadId = createCommentId()
    const markerId = createCommentMarkerId()

    expect(threadId).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(markerId).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(markerId.length).toBeLessThan(threadId.length)
  })

  it('strips only persisted markers from rendered/exported content', () => {
    const owned = buildCommentMarker('owned')
    const manual = '<!--comment:manual-->'
    const content = `\`\`\`\ncode ${owned}\n${manual}\n\`\`\``

    expect(stripCommentMarkers(content, [owned])).toBe(
      `\`\`\`\ncode \n${manual}\n\`\`\``,
    )
  })

  it('finds valid comment markers in content once', () => {
    const marker = buildCommentMarker('owned')
    const content = `${marker} text ${marker} <!--comment:bad marker-->`

    expect(findCommentMarkers(content)).toEqual([marker])
  })

  it('returns markers absent from loaded comment threads', () => {
    const known = buildCommentMarker('known')
    const unknown = buildCommentMarker('unknown')

    expect(findUnknownCommentMarkers(`${known}\n${unknown}`, [known])).toEqual([
      unknown,
    ])
  })

  it('sanitizes quote text with known markers while preserving unowned marker text', () => {
    const known = buildCommentMarker('known')
    const unowned = buildCommentMarker('unowned')

    expect(
      sanitizeCommentQuote(`alpha ${known}\n beta ${unowned}`, [known]),
    ).toBe(`alpha beta ${unowned}`)
  })

  it('sanitizes stored quote markers without normalizing whitespace', () => {
    const known = buildCommentMarker('known')

    expect(sanitizeStoredCommentQuote(`alpha\n${known}beta`, [known])).toBe(
      'alpha\nbeta',
    )
  })
})

describe('comment submit action', () => {
  it('opens the editor when comments are shown in preview-only mode', () => {
    expect(
      getCommentSubmitAction({
        hasEditor: false,
        hasTarget: false,
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
        hasTarget: false,
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
        hasTarget: true,
        hasDraft: false,
        readOnly: false,
        creating: false,
      }).disabled,
    ).toBe(true)

    expect(
      getCommentSubmitAction({
        hasEditor: true,
        hasTarget: true,
        hasDraft: true,
        readOnly: false,
        creating: false,
      }).disabled,
    ).toBe(false)

    expect(
      getCommentSubmitAction({
        hasEditor: true,
        hasTarget: false,
        hasDraft: true,
        readOnly: false,
        creating: false,
      }).disabled,
    ).toBe(true)
  })

  it('requires an explicit target before creating a thread', () => {
    expect(
      getCommentSubmitAction({
        hasEditor: true,
        hasTarget: false,
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
