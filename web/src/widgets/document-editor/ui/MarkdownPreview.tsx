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
import rehypeSanitize from 'rehype-sanitize'
import rehypeStringify from 'rehype-stringify'

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
        .use(rehypeSanitize)
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
