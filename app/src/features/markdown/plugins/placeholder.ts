/**
 * Placeholder plugin for rehype
 * Transforms specific code blocks into placeholder divs for plugin rendering
 *
 * Comrak compatibility:
 * - Code blocks with specific languages become:
 *   <div data-refmd-placeholder="true" data-placeholder-id="p1" data-placeholder-kind="mermaid"></div>
 */

import type { Root, Element } from 'hast'
import type { Plugin } from 'unified'
import { visit } from 'unist-util-visit'

import type { PlaceholderItem } from '../types'

export interface PlaceholderOptions {
  /** Set of code block languages to convert to placeholders */
  kinds: Set<string>
  /** Callback to collect placeholder items */
  onPlaceholder?: (item: PlaceholderItem) => void
}

let placeholderCounter = 0

export const rehypePlaceholder: Plugin<[PlaceholderOptions?], Root> = (options) => {
  const kinds = options?.kinds || new Set<string>()
  const onPlaceholder = options?.onPlaceholder

  return (tree) => {
    if (kinds.size === 0) {
      return
    }

    visit(tree, 'element', (node: Element, index: number | undefined, parent) => {
      if (index === undefined || !parent) return

      // Look for <pre><code class="language-xxx">...</code></pre>
      if (node.tagName !== 'pre') return

      const codeChild = node.children.find(
        (child): child is Element => child.type === 'element' && child.tagName === 'code'
      )

      if (!codeChild) return

      // Get language from class
      const className = codeChild.properties?.className
      if (!className || !Array.isArray(className)) return

      const langClass = className.find(
        (c): c is string => typeof c === 'string' && c.startsWith('language-')
      )

      if (!langClass) return

      const lang = langClass.slice('language-'.length).toLowerCase()

      if (!kinds.has(lang)) return

      // Extract code content
      const codeContent = codeChild.children
        .map((child) => {
          if (child.type === 'text') return child.value
          return ''
        })
        .join('')

      // Generate unique ID
      placeholderCounter++
      const id = `p${placeholderCounter}`

      // Report placeholder
      if (onPlaceholder) {
        onPlaceholder({
          kind: lang,
          id,
          code: codeContent,
        })
      }

      // Replace with placeholder div
      const placeholderDiv: Element = {
        type: 'element',
        tagName: 'div',
        properties: {
          'data-refmd-placeholder': 'true',
          'data-placeholder-id': id,
          'data-placeholder-kind': lang,
        },
        children: [],
      }

      // Replace the pre element with the placeholder div
      ;(parent as Element).children[index] = placeholderDiv
    })
  }
}

/**
 * Reset placeholder counter (useful for testing)
 */
export function resetPlaceholderCounter(): void {
  placeholderCounter = 0
}

export default rehypePlaceholder
