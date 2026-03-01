/**
 * ProseMirror Editor Component
 *
 * Renders a ProseMirror instance with Yjs collab plugins via @pm-cm/yjs.
 * WYSIWYG editor with headless PM plugins + React UI overlays.
 *
 * All PM plugin state is read via Plugin.getState() (same closure),
 * never via imported PluginKey — avoids HMR key identity mismatches.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { EditorView } from 'prosemirror-view'
import { EditorState, type Plugin } from 'prosemirror-state'
import type * as Y from 'yjs'
import type { Awareness } from 'y-protocols/awareness'
import { markdownSchema } from '../../lib/prosemirror/schema'
import { setupCollabPlugins } from '../../lib/prosemirror/collab-plugins'
import { buildCollabPlugins } from '../../lib/prosemirror/plugins'
import { slashCommandsPlugin, INACTIVE } from '../../lib/prosemirror/slash-commands'
import type { SlashMenuState, SlashCommand } from '../../lib/prosemirror/slash-commands'
import { placeholderPlugin } from '../../lib/prosemirror/placeholder-plugin'
import { blockHandlePlugin } from '../../lib/prosemirror/block-handle-plugin'
import { SlashMenu } from './SlashMenu'
import { FloatingToolbar } from './FloatingToolbar'

import './prosemirror-editor.css'

export interface ProseMirrorEditorProps {
  yDoc: Y.Doc
  awareness: Awareness
  className?: string
  readOnly?: boolean
}

export function ProseMirrorEditor({
  yDoc,
  awareness,
  className,
  readOnly = false,
}: ProseMirrorEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const viewRef = useRef<EditorView | null>(null)
  const slashPluginRef = useRef<Plugin | null>(null)

  const [slashState, setSlashState] = useState<SlashMenuState>(INACTIVE)
  const [hasSelection, setHasSelection] = useState(false)

  useEffect(() => {
    if (!containerRef.current || !yDoc) return

    let destroyed = false

    const collab = setupCollabPlugins({
      yDoc,
      schema: markdownSchema,
      awareness,
    })

    const slashPlugin = slashCommandsPlugin(markdownSchema)
    slashPluginRef.current = slashPlugin

    const state = EditorState.create({
      doc: collab.doc,
      plugins: [
        ...collab.plugins,
        placeholderPlugin(),
        slashPlugin,
        blockHandlePlugin(),
        ...buildCollabPlugins(markdownSchema),
      ],
    })

    const view = new EditorView(containerRef.current, {
      state,
      editable: () => !readOnly,
      dispatchTransaction(this: EditorView, tr) {
        if (destroyed) return
        const newState = this.state.apply(tr)
        this.updateState(newState)

        const ss = slashPlugin.getState(newState) as SlashMenuState | undefined
        setSlashState(ss ?? INACTIVE)
        setHasSelection(!newState.selection.empty)
      },
    })

    viewRef.current = view

    return () => {
      destroyed = true
      collab.destroy()
      view.destroy()
      viewRef.current = null
      slashPluginRef.current = null
    }
  }, [yDoc, awareness])

  // Update editable state when readOnly changes
  useEffect(() => {
    const view = viewRef.current
    if (view) {
      view.setProps({ editable: () => !readOnly })
    }
  }, [readOnly])

  // Execute a slash command — uses plugin.spec.key from same closure
  const handleSlashSelect = useCallback((cmd: SlashCommand) => {
    const view = viewRef.current
    const plugin = slashPluginRef.current
    if (!view || !plugin) return

    const ss = plugin.getState(view.state) as SlashMenuState | undefined
    if (!ss?.active) return

    const key = plugin.spec.key!
    const from = ss.pos
    const to = view.state.selection.from

    if (to > from) {
      view.dispatch(view.state.tr.delete(from, to).setMeta(key, INACTIVE))
    } else {
      view.dispatch(view.state.tr.setMeta(key, INACTIVE))
    }
    // Defer command execution so the deletion dispatch is fully
    // processed (including ySyncPlugin) before applying the block change
    queueMicrotask(() => {
      cmd.execute(view)
      view.focus()
    })
  }, [])

  const view = viewRef.current

  return (
    <>
      <div
        ref={containerRef}
        className={`h-full overflow-auto relative ${className ?? ''}`}
      />
      {view && slashState.active && (
        <SlashMenu
          view={view}
          slashState={slashState}
          onSelect={handleSlashSelect}
        />
      )}
      {view && hasSelection && (
        <FloatingToolbar view={view} schema={markdownSchema} />
      )}
    </>
  )
}
