import { describe, expect, it } from 'vitest'

import { shouldRenderEditorPane } from './editor-layout-state'

describe('editor layout pane rendering', () => {
  it('keeps the editor pane mounted for hidden mobile comment workflows', () => {
    expect(shouldRenderEditorPane('0%', true)).toBe(true)
  })

  it('does not render the editor pane when hidden without keep-mounted mode', () => {
    expect(shouldRenderEditorPane('0%', false)).toBe(false)
  })
})
