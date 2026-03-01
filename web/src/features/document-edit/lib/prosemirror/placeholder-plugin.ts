/**
 * ProseMirror Placeholder Plugin
 *
 * Shows placeholder text in empty blocks using Decoration.node.
 */

import { Plugin } from 'prosemirror-state'
import { Decoration, DecorationSet } from 'prosemirror-view'

export function placeholderPlugin(): Plugin {
  return new Plugin({
    props: {
      decorations(state) {
        const { doc, selection } = state
        const decorations: Decoration[] = []

        // Entire document is empty (single empty paragraph)
        if (doc.childCount === 1 && doc.firstChild!.content.size === 0) {
          decorations.push(
            Decoration.node(0, doc.firstChild!.nodeSize, {
              'data-placeholder': "Type '/' for commands",
              class: 'is-empty is-doc-empty',
            })
          )
          return DecorationSet.create(doc, decorations)
        }

        // Cursor is in an empty textblock
        const $pos = selection.$anchor
        if (
          $pos.parent.content.size === 0 &&
          $pos.parent.isTextblock &&
          !$pos.parent.type.spec.code
        ) {
          const before = $pos.before()
          const placeholder =
            $pos.parent.type.name === 'heading'
              ? `Heading ${$pos.parent.attrs.level}`
              : "Type '/' for commands"

          decorations.push(
            Decoration.node(before, before + $pos.parent.nodeSize, {
              'data-placeholder': placeholder,
              class: 'is-empty',
            })
          )
        }

        return DecorationSet.create(doc, decorations)
      },
    },
  })
}
