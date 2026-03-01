/**
 * Floating Toolbar Component
 *
 * React component that renders a formatting toolbar on text selection.
 * Uses omni-ui Button and @floating-ui/dom for positioning.
 */

import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import type { EditorView } from 'prosemirror-view'
import type { Schema, MarkType } from 'prosemirror-model'
import { toggleMark } from 'prosemirror-commands'
import { computePosition, offset, flip, shift } from '@floating-ui/dom'
import { Button } from '@/shared/ui/button'

interface ToolbarButtonDef {
  mark: string
  label: string
  icon: React.ReactNode
}

const BUTTONS: ToolbarButtonDef[] = [
  {
    mark: 'strong',
    label: 'Bold',
    icon: <span className="font-bold text-xs">B</span>,
  },
  {
    mark: 'em',
    label: 'Italic',
    icon: <span className="italic text-xs">I</span>,
  },
  {
    mark: 'strikethrough',
    label: 'Strikethrough',
    icon: <span className="line-through text-xs">S</span>,
  },
  {
    mark: 'code',
    label: 'Code',
    icon: <span className="font-mono text-[10px]">&lt;&gt;</span>,
  },
]

function isMarkActive(
  state: EditorView['state'],
  markType: MarkType
): boolean {
  const { from, $from, to, empty } = state.selection
  if (empty) {
    return !!markType.isInSet(state.storedMarks || $from.marks())
  }
  return state.doc.rangeHasMark(from, to, markType)
}

interface FloatingToolbarProps {
  view: EditorView
  schema: Schema
}

export function FloatingToolbar({ view, schema }: FloatingToolbarProps) {
  const toolbarRef = useRef<HTMLDivElement>(null)
  const { from, to, empty } = view.state.selection

  // Position the toolbar above the selection
  useEffect(() => {
    const toolbar = toolbarRef.current
    if (!toolbar || empty) return

    const virtualEl = {
      getBoundingClientRect: () => {
        const start = view.coordsAtPos(from)
        const end = view.coordsAtPos(to)
        return new DOMRect(
          start.left,
          start.top,
          end.right - start.left,
          end.bottom - start.top
        )
      },
    }

    computePosition(virtualEl, toolbar, {
      placement: 'top',
      middleware: [offset(8), flip(), shift({ padding: 8 })],
    }).then(({ x, y }) => {
      toolbar.style.left = `${x}px`
      toolbar.style.top = `${y}px`
    })
  }, [view, from, to, empty])

  if (empty) return null

  const availableButtons = BUTTONS.filter((b) => schema.marks[b.mark])

  return createPortal(
    <div
      ref={toolbarRef}
      className="fixed z-40 flex items-center gap-0.5 border border-border/60 bg-muted/60 p-1 shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]"
    >
      {availableButtons.map((btn) => {
        const markType = schema.marks[btn.mark]
        const active = isMarkActive(view.state, markType)

        return (
          <Button
            key={btn.mark}
            variant="ghost"
            size="icon-sm"
            className={`size-7 ${active ? 'bg-foreground text-background hover:bg-foreground/90 hover:text-background' : ''}`}
            title={btn.label}
            onMouseDown={(e) => {
              e.preventDefault()
              const cmd = toggleMark(markType)
              cmd(view.state, view.dispatch)
              view.focus()
            }}
          >
            {btn.icon}
          </Button>
        )
      })}
    </div>,
    document.body
  )
}
