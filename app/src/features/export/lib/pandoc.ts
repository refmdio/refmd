/**
 * Pandoc WASM Wrapper
 *
 * Provides client-side document conversion using wasm-pandoc.
 * Uses dynamic import for lazy loading (WASM is ~56MB).
 * All processing happens client-side for E2EE compliance.
 */

import type { pandoc as PandocFn } from 'wasm-pandoc'

import type { PandocOutputFormat } from './formats'

// Pandoc function (lazy loaded)
let pandocFn: typeof PandocFn | null = null
let initPromise: Promise<typeof PandocFn> | null = null

export interface PandocOptions {
  standalone?: boolean
  title?: string
  /** Function to resolve attachment paths to their contents */
  resolveAttachment?: (path: string) => Promise<Blob | null>
}

/**
 * Initialize wasm-pandoc (lazy loaded on first use)
 */
async function getPandoc(): Promise<typeof PandocFn> {
  if (pandocFn) {
    return pandocFn
  }

  if (initPromise) {
    return initPromise
  }

  initPromise = (async () => {
    // Dynamic import - only loads when actually needed
    const { pandoc } = await import('wasm-pandoc')
    pandocFn = pandoc
    return pandoc
  })()

  return initPromise
}

/**
 * Extract attachment paths from markdown
 */
function extractAttachmentPaths(markdown: string): { fullMatch: string; path: string }[] {
  const results: { fullMatch: string; path: string }[] = []
  // Match markdown images: ![alt](path) or ![alt](path "title")
  const mdImageRegex = /!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g

  let match
  while ((match = mdImageRegex.exec(markdown)) !== null) {
    const path = match[2]
    if (!path.startsWith('http://') && !path.startsWith('https://') && !path.startsWith('data:')) {
      results.push({ fullMatch: match[0], path })
    }
  }

  return results
}

/**
 * Replace attachment paths in markdown with data URIs
 */
async function embedAttachmentsInMarkdown(
  markdown: string,
  resolveAttachment: (path: string) => Promise<Blob | null>
): Promise<string> {
  const attachments = extractAttachmentPaths(markdown)
  if (attachments.length === 0) {
    return markdown
  }

  // Resolve all attachments in parallel
  const resolved = await Promise.all(
    attachments.map(async ({ fullMatch, path }) => {
      try {
        const blob = await resolveAttachment(path)
        if (!blob) {
          return { fullMatch, path, dataUri: null }
        }

        // Convert blob to data URI
        const dataUri = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader()
          reader.onloadend = () => resolve(reader.result as string)
          reader.onerror = reject
          reader.readAsDataURL(blob)
        })

        return { fullMatch, path, dataUri }
      } catch (error) {
        console.warn('[Pandoc] Failed to resolve attachment:', path, error)
        return { fullMatch, path, dataUri: null }
      }
    })
  )

  // Replace paths with data URIs in markdown
  let result = markdown
  for (const { fullMatch, dataUri } of resolved) {
    if (dataUri) {
      // Extract alt text from the full match
      const altMatch = fullMatch.match(/!\[([^\]]*)\]/)
      const altText = altMatch ? altMatch[1] : ''
      const replacement = `![${altText}](${dataUri})`
      result = result.replace(fullMatch, replacement)
    }
  }

  return result
}

/**
 * Convert markdown to the specified format using wasm-pandoc
 *
 * @param markdown - Input markdown text
 * @param format - Target output format (pandoc format name)
 * @param options - Additional pandoc options
 * @returns Converted content as string or Blob
 */
export async function convertWithPandoc(
  markdown: string,
  format: PandocOutputFormat,
  options?: PandocOptions
): Promise<string | Blob> {
  const pandoc = await getPandoc()

  // Build command line arguments
  const args: string[] = ['-f', 'markdown', '-t', format]

  // Add standalone flag for formats that support it
  if (options?.standalone !== false) {
    const standaloneFormats = [
      'html', 'html5', 'latex', 'beamer', 'context',
      'docx', 'odt', 'rtf', 'epub', 'epub3',
    ]
    if (standaloneFormats.includes(format)) {
      args.push('-s')
    }
  }

  // Add metadata for title if provided
  if (options?.title) {
    args.push('-M', `title=${options.title}`)
  }

  // Embed attachments as data URIs if resolver is provided
  let processedMarkdown = markdown
  if (options?.resolveAttachment) {
    processedMarkdown = await embedAttachmentsInMarkdown(markdown, options.resolveAttachment)
  }

  const result = await pandoc(args.join(' '), processedMarkdown)

  return result.out
}

/**
 * Convert markdown and return as Blob
 */
export async function exportWithPandoc(
  markdown: string,
  format: PandocOutputFormat,
  mimeType: string,
  options?: PandocOptions
): Promise<Blob> {
  const result = await convertWithPandoc(markdown, format, options)

  if (result instanceof Blob) {
    return result
  }

  return new Blob([result], { type: mimeType })
}

/**
 * Check if wasm-pandoc is loaded
 */
export function isPandocLoaded(): boolean {
  return pandocFn !== null
}

/**
 * Preload wasm-pandoc (optional, for better UX)
 * Call this when user opens export dialog to start loading in background
 */
export async function preloadPandoc(): Promise<void> {
  try {
    await getPandoc()
  } catch {
    // Silently fail - will retry on actual export
  }
}
