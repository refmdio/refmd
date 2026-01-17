/**
 * Client-side Markdown renderer using unified/remark/rehype
 * Replaces server-side Comrak rendering for E2EE support
 */

import rehypeKatex from 'rehype-katex'
import rehypeSanitize from 'rehype-sanitize'
import rehypeStringify from 'rehype-stringify'
import remarkBreaks from 'remark-breaks'
import remarkGfm from 'remark-gfm'
import remarkMath from 'remark-math'
import remarkParse from 'remark-parse'
import remarkRehype from 'remark-rehype'
import { unified } from 'unified'

import {
  remarkSourcepos,
  rehypeWikilink,
  rehypeHashtag,
  rehypeMention,
  rehypePlaceholder,
  rehypeHighlight,
  rehypeAttachments,
  refmdSanitizeSchema,
  resetPlaceholderCounter,
} from './plugins'
import type { RenderOptions, RenderResponse, PlaceholderItem } from './types'

/**
 * Compute SHA-256 hash for cache key
 */
async function computeHash(text: string, options: RenderOptions): Promise<string> {
  const optionsStr = JSON.stringify(options)
  const canonical = `${text}\n${optionsStr}`

  const encoder = new TextEncoder()
  const data = encoder.encode(canonical)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Check if a feature is enabled
 */
function wantsFeature(options: RenderOptions, name: string): boolean {
  if (options.features) {
    return options.features.some((f) => f.toLowerCase() === name.toLowerCase())
  }

  // Default behavior matching Comrak
  switch (name.toLowerCase()) {
    case 'gfm':
      // GFM enabled by default unless flavor is 'commonmark'
      return options.flavor?.toLowerCase() !== 'commonmark'
    case 'highlight':
      return false
    default:
      return false
  }
}

/**
 * Render Markdown to HTML
 *
 * @param markdown - Source Markdown text
 * @param options - Rendering options
 * @returns Rendered HTML, placeholders, and hash
 */
export async function renderMarkdown(
  markdown: string,
  options: RenderOptions = {}
): Promise<RenderResponse> {
  // Reset placeholder counter for consistent IDs
  resetPlaceholderCounter()

  const placeholders: PlaceholderItem[] = []

  // Determine which features to enable
  const enableGfm = wantsFeature(options, 'gfm')
  const enableHighlight = wantsFeature(options, 'highlight')
  const enableSanitize = options.sanitize ?? true

  // Build placeholder kinds set
  const placeholderKinds = new Set(options.placeholderKinds || [])

  // Create unified processor pipeline
  const processor = unified().use(remarkParse)

  // Add GFM support if enabled
  if (enableGfm) {
    processor.use(remarkGfm)
  }

  // Add line break support (soft breaks become <br>)
  processor.use(remarkBreaks)

  // Add math support
  processor.use(remarkMath)

  // Add sourcepos (remark level, before conversion to hast)
  processor.use(remarkSourcepos)

  // Convert to rehype (HTML AST)
  processor.use(remarkRehype, {
    allowDangerousHtml: true,
  })

  // Apply rehype plugins for custom transformations
  // Order: mention before hashtag to catch #mention: first
  // These must run BEFORE sanitization
  processor.use(rehypeWikilink)
  processor.use(rehypeMention)
  processor.use(rehypeHashtag)

  // Add rehype plugins
  // Placeholder must come before highlight to prevent highlighting placeholder code
  if (placeholderKinds.size > 0) {
    processor.use(rehypePlaceholder, {
      kinds: placeholderKinds,
      onPlaceholder: (item) => placeholders.push(item),
    })
  }

  // Add syntax highlighting if enabled
  if (enableHighlight) {
    processor.use(rehypeHighlight, {
      theme: options.theme || 'one-dark-pro',
      skipLanguages: placeholderKinds,
    })
  }

  // Add KaTeX for math rendering
  processor.use(rehypeKatex)

  // Rewrite attachment URLs
  processor.use(rehypeAttachments, {
    docId: options.docId,
    token: options.token,
    baseOrigin: options.baseOrigin,
    absoluteAttachments: options.absoluteAttachments,
  })

  // Sanitize HTML if enabled (must be last before stringify)
  if (enableSanitize) {
    processor.use(rehypeSanitize, refmdSanitizeSchema)
  }

  // Stringify to HTML
  processor.use(rehypeStringify, {
    allowDangerousHtml: true,
  })

  // Process the markdown
  const file = await processor.process(markdown)
  const html = String(file)

  // Compute hash for caching
  const hash = await computeHash(markdown, options)

  return {
    html,
    placeholders,
    hash,
  }
}

/**
 * Render multiple Markdown documents
 */
export async function renderMarkdownMany(
  items: Array<{ text: string; options?: RenderOptions }>
): Promise<RenderResponse[]> {
  return Promise.all(items.map((item) => renderMarkdown(item.text, item.options)))
}

export { initHighlighter } from './plugins'
