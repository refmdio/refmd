/**
 * Sourcepos plugin for remark
 * Adds data-sourcepos attributes to elements for editor<->preview sync
 *
 * Comrak compatibility:
 * - Adds data-sourcepos="startLine:startCol-endLine:endCol" to all elements
 */

import { visit } from 'unist-util-visit'
import type { Plugin } from 'unified'
import type { Root } from 'mdast'

export const remarkSourcepos: Plugin<[], Root> = () => {
  return (tree) => {
    visit(tree, (node) => {
      if (!node.position) {
        return
      }

      const { start, end } = node.position
      const sourcepos = `${start.line}:${start.column}-${end.line}:${end.column}`

      // Create data object if it doesn't exist
      const nodeWithData = node as typeof node & {
        data?: {
          hProperties?: Record<string, unknown>
        }
      }

      nodeWithData.data = nodeWithData.data || {}
      nodeWithData.data.hProperties = nodeWithData.data.hProperties || {}
      nodeWithData.data.hProperties['data-sourcepos'] = sourcepos
    })
  }
}

export default remarkSourcepos
