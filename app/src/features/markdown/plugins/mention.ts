/**
 * Mention plugin for rehype
 * Transforms #mention:target syntax to <a class="mention"> elements
 *
 * Comrak compatibility:
 * - #mention:user -> <a href="#mention:user" class="mention" data-mention-target="user">#mention:user</a>
 * - Pattern: #mention:[A-Za-z0-9-_:@.]+
 */

import { visit } from 'unist-util-visit'
import type { Plugin } from 'unified'
import type { Root, Element, Text } from 'hast'

// Characters that prevent mention recognition when immediately preceding #
const SKIP_PREV_CHARS = /[A-Za-z0-9\/:@.\-_+~=?&%]$/

// Mention pattern: #mention: followed by valid characters
const MENTION_PATTERN = /#mention:([A-Za-z0-9\-_:@.]+)/g

function createMentionElement(target: string): Element {
  const href = `#mention:${target}`
  const text = `#mention:${target}`

  return {
    type: 'element',
    tagName: 'a',
    properties: {
      href: href,
      class: 'mention',
      'data-mention-target': target,
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
  MENTION_PATTERN.lastIndex = 0

  let match: RegExpExecArray | null
  while ((match = MENTION_PATTERN.exec(text)) !== null) {
    const matchIndex = match.index
    const target = match[1]

    // Check if preceded by a character that should prevent matching
    if (matchIndex > 0) {
      const prevChar = text[matchIndex - 1]
      if (SKIP_PREV_CHARS.test(prevChar)) {
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

    // Add mention element
    result.push({
      type: 'element',
      node: createMentionElement(target),
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

export const rehypeMention: Plugin<[], Root> = () => {
  return (tree) => {
    visit(tree, 'text', (node: Text, index: number | undefined, parent) => {
      if (index === undefined || !parent || parent.type !== 'element') return

      const text = node.value
      if (!text.includes('#mention:')) {
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
        return
      }

      const newNodes = processed.map((p) => p.node)
      parentElement.children.splice(index, 1, ...newNodes)
    })
  }
}

export default rehypeMention
