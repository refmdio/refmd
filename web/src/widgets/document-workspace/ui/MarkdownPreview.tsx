/**
 * Markdown Preview Component
 *
 * Renders markdown content as HTML using unified/remark/rehype.
 */

import { useMemo } from 'react'
import { unified } from 'unified'
import remarkParse from 'remark-parse'
import remarkGfm from 'remark-gfm'
import remarkRehype from 'remark-rehype'
import rehypeSanitize, { defaultSchema } from 'rehype-sanitize'
import rehypeStringify from 'rehype-stringify'
import type { Root, Element } from 'hast'

/**
 * Custom sanitization schema:
 * - URLs: https: and mailto: only (no http:)
 * - Image src: https:, blob:, data: (MIME-restricted below)
 * - External links: target="_blank" + rel="noopener noreferrer"
 */
const sanitizeSchema: typeof defaultSchema = {
  ...defaultSchema,
  protocols: {
    ...defaultSchema.protocols,
    href: ['https', 'mailto'],
    src: ['https', 'blob', 'data'],
  },
  attributes: {
    ...defaultSchema.attributes,
    a: [
      ...(defaultSchema.attributes?.a ?? []),
      ['target', '_blank'],
      ['rel', 'noopener noreferrer'],
    ],
  },
}

/**
 * Allowed MIME types for data: URIs.
 * SVG is excluded to prevent XSS via embedded scripts.
 */
const ALLOWED_DATA_MIMES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp']

/**
 * Post-sanitize plugin: strips data: URIs with disallowed MIME types from img[src].
 */
function rehypeFilterDataUris() {
  return (tree: Root) => {
    function visit(node: Root | Element) {
      if ('children' in node) {
        for (const child of node.children) {
          if (child.type === 'element') visit(child)
        }
      }
      if (node.type === 'element' && node.tagName === 'img' && node.properties?.src) {
        const src = String(node.properties.src)
        if (src.startsWith('data:')) {
          const allowed = ALLOWED_DATA_MIMES.some(mime => src.startsWith(`data:${mime}`))
          if (!allowed) {
            delete node.properties.src
          }
        }
      }
    }
    visit(tree)
  }
}

export interface MarkdownPreviewProps {
  content: string
  className?: string
}

export function MarkdownPreview({ content, className = '' }: MarkdownPreviewProps) {
  const html = useMemo(() => {
    try {
      const result = unified()
        .use(remarkParse)
        .use(remarkGfm)
        .use(remarkRehype)
        .use(rehypeSanitize, sanitizeSchema)
        .use(rehypeFilterDataUris)
        .use(rehypeStringify)
        .processSync(content)

      return String(result)
    } catch {
      return '<p>Error rendering markdown</p>'
    }
  }, [content])

  return (
    <div
      className={`prose prose-sm dark:prose-invert max-w-none p-4 overflow-auto ${className}`}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}
