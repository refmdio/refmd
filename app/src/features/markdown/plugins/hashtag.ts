/**
 * Hashtag plugin for rehype
 * Transforms #tag syntax to <a class="hashtag"> elements
 *
 * Comrak compatibility:
 * - #tag -> <a href="#tag-tag" class="hashtag">#tag</a>
 * - Pattern: #[A-Za-z0-9_]{1,50}
 * - Skip if preceded by alphanumeric or /:@.-_+~=?&%
 */

import type { Root, Element, Text } from 'hast'
import type { Plugin } from 'unified'
import { visit } from 'unist-util-visit'

// Characters that prevent hashtag recognition when immediately preceding #
const SKIP_PREV_CHARS = /[A-Za-z0-9\/:@.\-_+~=?&%]$/

// Hashtag pattern: # followed by 1-50 alphanumeric or underscore characters
const TAG_PATTERN = /#([A-Za-z0-9_]{1,50})(?![A-Za-z0-9_])/g

function createHashtagElement(tag: string): Element {
  const href = `#tag-${tag}`
  const text = `#${tag}`

  return {
    type: 'element',
    tagName: 'a',
    properties: {
      href: href,
      class: 'hashtag',
    },
    children: [{ type: 'text', value: text }],
  }
}

interface ProcessedNode {
  type: 'text' | 'element'
  node: Text | Element
}

function processText(text: string): ProcessedNode[] {
  const result: ProcessedNode[] = []
  let lastIndex = 0

  // Reset regex state
  TAG_PATTERN.lastIndex = 0

  let match: RegExpExecArray | null
  while ((match = TAG_PATTERN.exec(text)) !== null) {
    const matchIndex = match.index
    const tag = match[1]

    // Check if preceded by a character that should prevent matching
    if (matchIndex > 0) {
      const prevChar = text[matchIndex - 1]
      if (SKIP_PREV_CHARS.test(prevChar)) {
        // Skip this match, continue searching
        continue
      }
    }

    // Add text before match
    if (matchIndex > lastIndex) {
      result.push({
        type: 'text',
        node: { type: 'text', value: text.slice(lastIndex, matchIndex) }
      })
    }

    // Add hashtag element
    result.push({
      type: 'element',
      node: createHashtagElement(tag),
    })

    lastIndex = matchIndex + match[0].length
  }

  // Add remaining text
  if (lastIndex < text.length) {
    result.push({
      type: 'text',
      node: { type: 'text', value: text.slice(lastIndex) }
    })
  }

  return result
}

export const rehypeHashtag: Plugin<[], Root> = () => {
  return (tree) => {
    visit(tree, 'text', (node: Text, index: number | undefined, parent) => {
      if (index === undefined || !parent || parent.type !== 'element') return

      const text = node.value
      if (!text.includes('#')) {
        return
      }

      // Skip if inside a link
      const parentElement = parent as Element
      if (parentElement.tagName === 'a') {
        return
      }

      const processed = processText(text)

      if (processed.length === 0) {
        return
      }

      if (processed.length === 1 && processed[0].type === 'text' && (processed[0].node as Text).value === text) {
        // No changes needed
        return
      }

      // Replace the text node with the processed nodes
      const newNodes = processed.map((p) => p.node)
      parentElement.children.splice(index, 1, ...newNodes)
    })
  }
}

export default rehypeHashtag
