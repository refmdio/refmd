/**
 * ProseMirror Slash Commands Plugin
 *
 * Provides a `/` command menu for quick block insertion
 * (heading, list, code block, etc.).
 * Commands are grouped by category for Notion-style display.
 */

import { Plugin, PluginKey } from 'prosemirror-state'
import type { EditorView } from 'prosemirror-view'
import type { Schema } from 'prosemirror-model'
import { setBlockType } from 'prosemirror-commands'
import { wrapInList } from 'prosemirror-schema-list'

export type SlashCommandCategory = 'text' | 'list' | 'other'

export const CATEGORY_LABELS: Record<SlashCommandCategory, string> = {
  text: 'Text',
  list: 'List',
  other: 'Other',
}

export const CATEGORY_ORDER: SlashCommandCategory[] = ['text', 'list', 'other']

export interface SlashCommand {
  label: string
  description: string
  shortcut: string
  category: SlashCommandCategory
  icon: string
  execute: (view: EditorView) => boolean
}

function buildCommands(schema: Schema): SlashCommand[] {
  const commands: SlashCommand[] = []

  if (schema.nodes.paragraph) {
    commands.push({
      label: 'Text',
      description: 'Plain text block',
      shortcut: 'p',
      category: 'text',
      icon: 'type',
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.paragraph)
        return cmd(view.state, view.dispatch)
      },
    })
  }

  if (schema.nodes.heading) {
    commands.push({
      label: 'Heading 1',
      description: 'Large section heading',
      shortcut: 'h1',
      category: 'text',
      icon: 'heading-1',
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.heading, { level: 1 })
        return cmd(view.state, view.dispatch)
      },
    })
    commands.push({
      label: 'Heading 2',
      description: 'Medium section heading',
      shortcut: 'h2',
      category: 'text',
      icon: 'heading-2',
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.heading, { level: 2 })
        return cmd(view.state, view.dispatch)
      },
    })
    commands.push({
      label: 'Heading 3',
      description: 'Small section heading',
      shortcut: 'h3',
      category: 'text',
      icon: 'heading-3',
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.heading, { level: 3 })
        return cmd(view.state, view.dispatch)
      },
    })
  }

  if (schema.nodes.bullet_list) {
    commands.push({
      label: 'Bullet List',
      description: 'Unordered list with bullets',
      shortcut: 'ul',
      category: 'list',
      icon: 'list',
      execute: (view) => {
        const cmd = wrapInList(schema.nodes.bullet_list)
        return cmd(view.state, view.dispatch)
      },
    })
  }

  if (schema.nodes.ordered_list) {
    commands.push({
      label: 'Numbered List',
      description: 'Ordered list with numbers',
      shortcut: 'ol',
      category: 'list',
      icon: 'list-ordered',
      execute: (view) => {
        const cmd = wrapInList(schema.nodes.ordered_list)
        return cmd(view.state, view.dispatch)
      },
    })
  }

  if (schema.nodes.blockquote) {
    commands.push({
      label: 'Quote',
      description: 'Block quotation',
      shortcut: 'quote',
      category: 'text',
      icon: 'quote',
      execute: (view) => {
        const { $from, $to } = view.state.selection
        const range = $from.blockRange($to)
        if (!range) return false
        const tr = view.state.tr.wrap(range, [{ type: schema.nodes.blockquote }])
        view.dispatch(tr)
        return true
      },
    })
  }

  if (schema.nodes.code_block) {
    commands.push({
      label: 'Code',
      description: 'Fenced code block',
      shortcut: 'code',
      category: 'other',
      icon: 'code',
      execute: (view) => {
        const cmd = setBlockType(schema.nodes.code_block)
        return cmd(view.state, view.dispatch)
      },
    })
  }

  if (schema.nodes.horizontal_rule) {
    commands.push({
      label: 'Divider',
      description: 'Horizontal separator',
      shortcut: 'hr',
      category: 'other',
      icon: 'minus',
      execute: (view) => {
        const { $from } = view.state.selection
        const tr = view.state.tr.replaceRangeWith(
          $from.before(),
          $from.after(),
          schema.nodes.horizontal_rule.create()
        )
        view.dispatch(tr)
        return true
      },
    })
  }

  // Sort by category order so flat index matches grouped display order
  commands.sort((a, b) => CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category))

  return commands
}

export const slashCommandsKey = new PluginKey('slashCommands')

export interface SlashMenuState {
  active: boolean
  query: string
  commands: SlashCommand[]
  selectedIndex: number
  pos: number
}

export const INACTIVE: SlashMenuState = {
  active: false,
  query: '',
  commands: [],
  selectedIndex: 0,
  pos: 0,
}

export function slashCommandsPlugin(schema: Schema): Plugin {
  const allCommands = buildCommands(schema)

  function filterCommands(query: string): SlashCommand[] {
    if (!query) return allCommands
    const q = query.toLowerCase()
    return allCommands.filter(
      (c) =>
        c.label.toLowerCase().includes(q) ||
        c.shortcut.toLowerCase().includes(q)
    )
  }

  return new Plugin({
    key: slashCommandsKey,

    state: {
      init: () => INACTIVE,
      apply(tr, prev) {
        const meta = tr.getMeta(slashCommandsKey)
        if (meta !== undefined) return meta as SlashMenuState
        // Keep state as-is if no meta (doc changes are handled by handleKeyDown)
        return prev
      },
    },

    props: {
      handleKeyDown(view, event) {
        const state = slashCommandsKey.getState(view.state) as SlashMenuState | undefined

        if (!state?.active) {
          if (event.key === '/') {
            const { $from } = view.state.selection
            // Only trigger at the start of an empty textblock
            if (
              $from.parent.isTextblock &&
              $from.parent.content.size === 0 &&
              $from.parentOffset === 0
            ) {
              // Insert '/' and activate menu in the same transaction
              const pos = $from.pos
              const tr = view.state.tr
                .insertText('/', pos, pos)
                .setMeta(slashCommandsKey, {
                  active: true,
                  query: '',
                  commands: allCommands,
                  selectedIndex: 0,
                  pos,
                } satisfies SlashMenuState)
              view.dispatch(tr)
              return true // Prevent default '/' insertion
            }
          }
          return false
        }

        // --- Menu is active ---

        if (event.key === 'Escape') {
          view.dispatch(view.state.tr.setMeta(slashCommandsKey, INACTIVE))
          return true
        }

        if (event.key === 'ArrowDown') {
          const next = {
            ...state,
            selectedIndex: (state.selectedIndex + 1) % state.commands.length,
          }
          view.dispatch(view.state.tr.setMeta(slashCommandsKey, next))
          return true
        }

        if (event.key === 'ArrowUp') {
          const next = {
            ...state,
            selectedIndex:
              (state.selectedIndex - 1 + state.commands.length) % state.commands.length,
          }
          view.dispatch(view.state.tr.setMeta(slashCommandsKey, next))
          return true
        }

        if (event.key === 'Enter') {
          const cmd = state.commands[state.selectedIndex]
          if (cmd) {
            // Delete the `/` + query text, then close menu
            const from = state.pos
            const to = view.state.selection.from
            if (to > from) {
              view.dispatch(view.state.tr.delete(from, to).setMeta(slashCommandsKey, INACTIVE))
            } else {
              view.dispatch(view.state.tr.setMeta(slashCommandsKey, INACTIVE))
            }
            // Defer command execution so the deletion dispatch is fully
            // processed (including ySyncPlugin) before applying the block change
            queueMicrotask(() => cmd.execute(view))
          }
          return true
        }

        if (event.key === 'Backspace') {
          if (state.query.length === 0) {
            // Close menu, let PM handle the backspace to delete '/'
            view.dispatch(view.state.tr.setMeta(slashCommandsKey, INACTIVE))
            return false
          }
          // Delete last query char from doc + update menu state in one transaction
          const newQuery = state.query.slice(0, -1)
          const filtered = filterCommands(newQuery)
          const cursorPos = view.state.selection.from
          const tr = view.state.tr
            .delete(cursorPos - 1, cursorPos)
            .setMeta(slashCommandsKey, {
              ...state,
              query: newQuery,
              commands: filtered,
              selectedIndex: 0,
            } satisfies SlashMenuState)
          view.dispatch(tr)
          return true
        }

        if (event.key.length === 1 && !event.ctrlKey && !event.metaKey) {
          const newQuery = state.query + event.key
          const filtered = filterCommands(newQuery)
          if (filtered.length === 0) {
            // No matches — close menu, let PM handle the char insertion
            view.dispatch(view.state.tr.setMeta(slashCommandsKey, INACTIVE))
            return false
          }
          // Insert char into doc + update menu state in one transaction
          const cursorPos = view.state.selection.from
          const tr = view.state.tr
            .insertText(event.key, cursorPos, cursorPos)
            .setMeta(slashCommandsKey, {
              ...state,
              query: newQuery,
              commands: filtered,
              selectedIndex: 0,
            } satisfies SlashMenuState)
          view.dispatch(tr)
          return true // Prevent default char insertion
        }

        return false
      },
    },
  })
}
