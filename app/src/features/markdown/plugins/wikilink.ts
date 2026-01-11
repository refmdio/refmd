/**
 * Wikilink plugin for rehype
 * Transforms [[target]] and #wiki:target syntax to <refmd-wikilink> elements
 *
 * Comrak compatibility:
 * - [[target]] -> <refmd-wikilink target="target" href="#wiki:target" variant="embed">target</refmd-wikilink>
 * - [[target|alias]] -> uses alias as display text
 * - [[target|alias|inline]] -> variant="inline"
 * - #wiki:target -> same transformation
 */

import { visit } from 'unist-util-visit'
import type { Plugin } from 'unified'
import type { Root, Element, Text } from 'hast'

function normalizeWikilinkLabel(raw: string): { label: string; inline: boolean } {
  let label = raw.trim()
  if (!label) {
    return { label: '', inline: false }
  }

  let inline = false
  const lower = label.toLowerCase()

  // Check for |inline suffix
  const pipeInlinePos = lower.lastIndexOf('|inline')
  if (pipeInlinePos !== -1 && lower.slice(pipeInlinePos).trim() === '|inline') {
    label = label.slice(0, pipeInlinePos).trimEnd()
    inline = true
  }

  // Remove leading # if present
  if (label.startsWith('#')) {
    label = label.slice(1)
  }

  // Remove wiki: prefix if present
  if (label.toLowerCase().startsWith('wiki:')) {
    label = label.slice(5).trim()
  }

  return { label: label.trim(), inline }
}

function createWikilinkElement(target: string, displayLabel: string, inline: boolean): Element {
  const variant = inline ? 'inline' : 'embed'
  const href = `#wiki:${target}`

  return {
    type: 'element',
    tagName: 'refmd-wikilink',
    properties: {
      class: 'wikilink',
      target: target,
      href: href,
      variant: variant,
    },
    children: [{ type: 'text', value: displayLabel }],
  }
}

interface ProcessedNode {
  type: 'text' | 'element'
  node: Text | Element
}

function processText(text: string): ProcessedNode[] {
  const result: ProcessedNode[] = []
  let lastIndex = 0

  // Combine both patterns and process in order
  const combined = /(\[\[[^\]]+\]\])|(#wiki:[A-Za-z0-9:\-\/_]+)/g

  let match: RegExpExecArray | null
  while ((match = combined.exec(text)) !== null) {
    // Add text before match
    if (match.index > lastIndex) {
      const textBefore = text.slice(lastIndex, match.index)
      result.push({
        type: 'text',
        node: { type: 'text', value: textBefore }
      })
    }

    if (match[1]) {
      // Bracket wikilink [[target]] or [[target|alias]]
      const inside = match[1].slice(2, -2) // Remove [[ and ]]
      const parts = inside.split('|')
      const target = parts[0].trim()

      if (target) {
        // Get alias (everything after first |) or use target
        const aliasRaw = parts.length > 1 ? parts.slice(1).join('|') : target
        const { label, inline } = normalizeWikilinkLabel(aliasRaw)
        const displayLabel = label || target

        result.push({
          type: 'element',
          node: createWikilinkElement(target, displayLabel, inline),
        })
      } else {
        // Empty target, keep as literal
        result.push({
          type: 'text',
          node: { type: 'text', value: match[0] }
        })
      }
    } else if (match[2]) {
      // Hash wiki #wiki:target
      const full = match[2]
      const target = full.slice(6) // Remove #wiki:

      // Check previous character to avoid matching in URLs
      if (match.index > 0) {
        const prevChar = text[match.index - 1]
        if (/[A-Za-z0-9\/:@.\-_+~=?&%]/.test(prevChar)) {
          result.push({
            type: 'text',
            node: { type: 'text', value: full }
          })
          lastIndex = match.index + full.length
          continue
        }
      }

      const { label, inline } = normalizeWikilinkLabel(full)
      result.push({
        type: 'element',
        node: createWikilinkElement(target, label || target, inline),
      })
    }

    lastIndex = match.index + match[0].length
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

export const rehypeWikilink: Plugin<[], Root> = () => {
  return (tree) => {
    visit(tree, 'text', (node: Text, index: number | undefined, parent) => {
      if (index === undefined || !parent || parent.type !== 'element') return

      const text = node.value
      if (!text.includes('[[') && !text.includes('#wiki:')) {
        return
      }

      const processed = processText(text)

      if (processed.length === 0) {
        return
      }

      if (processed.length === 1 && processed[0].type === 'text') {
        // No changes needed
        return
      }

      // Replace the text node with the processed nodes
      const newNodes = processed.map((p) => p.node)
      ;(parent as Element).children.splice(index, 1, ...newNodes)
    })
  }
}

export default rehypeWikilink
