import { Extension, RangeSetBuilder } from '@codemirror/state'
import { Decoration, DecorationSet, EditorView, WidgetType, ViewPlugin, ViewUpdate } from '@codemirror/view'
import type { Awareness } from 'y-protocols/awareness'

interface AwarenessUser {
  name?: string
  color?: string
  colorLight?: string
}

interface AwarenessState {
  cursor?: { anchor: number; head: number }
  user?: AwarenessUser
}

const DEFAULT_COLORS = [
  { color: '#30bced', light: '#30bced33' },
  { color: '#6eeb83', light: '#6eeb8333' },
  { color: '#ffbc42', light: '#ffbc4233' },
  { color: '#e2525b', light: '#e2525b33' },
  { color: '#8b5cf6', light: '#8b5cf633' },
  { color: '#ec4899', light: '#ec489933' },
  { color: '#14b8a6', light: '#14b8a633' },
  { color: '#f97316', light: '#f9731633' },
]

function getColorForClient(clientId: number): { color: string; light: string } {
  return DEFAULT_COLORS[clientId % DEFAULT_COLORS.length]
}

class CursorWidget extends WidgetType {
  constructor(
    private user: AwarenessUser,
    private clientId: number
  ) {
    super()
  }

  eq(other: CursorWidget): boolean {
    return this.clientId === other.clientId && this.user.name === other.user.name
  }

  toDOM(): HTMLElement {
    const { color } = getColorForClient(this.clientId)
    const userColor = this.user.color || color

    const wrapper = document.createElement('span')
    wrapper.className = 'cm-yjs-cursor'
    wrapper.style.cssText = `
      position: relative;
      border-left: 2px solid ${userColor};
      margin-left: -1px;
      margin-right: -1px;
      pointer-events: none;
    `

    if (this.user.name) {
      const label = document.createElement('span')
      label.className = 'cm-yjs-cursor-label'
      label.textContent = this.user.name
      label.style.cssText = `
        position: absolute;
        top: -1.4em;
        left: -1px;
        font-size: 10px;
        font-weight: 500;
        background: ${userColor};
        color: white;
        padding: 1px 4px;
        border-radius: 3px;
        white-space: nowrap;
        pointer-events: none;
        z-index: 10;
      `
      wrapper.appendChild(label)
    }

    return wrapper
  }

  ignoreEvent(): boolean {
    return true
  }
}

function createCursorDecorations(
  awareness: Awareness,
  localClientId: number
): DecorationSet {
  const builder = new RangeSetBuilder<Decoration>()
  const decorations: Array<{ from: number; to: number; decoration: Decoration }> = []

  awareness.getStates().forEach((state: AwarenessState, clientId: number) => {
    if (clientId === localClientId) return
    if (!state.cursor) return

    const { anchor, head } = state.cursor
    const { light } = getColorForClient(clientId)
    const userLight = state.user?.colorLight || light

    // Selection decoration
    const from = Math.min(anchor, head)
    const to = Math.max(anchor, head)

    if (from !== to) {
      decorations.push({
        from,
        to,
        decoration: Decoration.mark({
          class: 'cm-yjs-selection',
          attributes: {
            style: `background-color: ${userLight};`,
          },
        }),
      })
    }

    // Cursor widget at head position
    decorations.push({
      from: head,
      to: head,
      decoration: Decoration.widget({
        widget: new CursorWidget(state.user || {}, clientId),
        side: 1,
      }),
    })
  })

  // Sort by position for RangeSetBuilder
  decorations.sort((a, b) => a.from - b.from || a.to - b.to)

  for (const { from, to, decoration } of decorations) {
    builder.add(from, to, decoration)
  }

  return builder.finish()
}

export function awarenessExtension(awareness: Awareness): Extension {
  const localClientId = awareness.clientID

  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet

      constructor(_view: EditorView) {
        this.decorations = createCursorDecorations(awareness, localClientId)
      }

      update(_update: ViewUpdate) {
        this.decorations = createCursorDecorations(awareness, localClientId)
      }
    },
    {
      decorations: (v) => v.decorations,
    }
  )
}

export function awarenessStyles(): Extension {
  return EditorView.baseTheme({
    '.cm-yjs-cursor': {
      position: 'relative',
    },
    '.cm-yjs-cursor-label': {
      fontFamily: 'system-ui, -apple-system, sans-serif',
    },
    '.cm-yjs-selection': {
      mixBlendMode: 'multiply',
    },
    '.dark .cm-yjs-selection': {
      mixBlendMode: 'screen',
    },
  })
}
