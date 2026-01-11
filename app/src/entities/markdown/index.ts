/**
 * Markdown rendering entity
 *
 * This module provides client-side Markdown rendering using unified/remark/rehype.
 * It replaces the server-side Comrak rendering for E2EE support.
 *
 * The API remains compatible with the original server API for seamless migration.
 */

import { renderMarkdown as localRenderMarkdown } from '@/features/markdown'
import type { RenderManyRequest, RenderManyResponse, RenderRequest, RenderResponseBody } from '@/shared/api'

// Re-export types for compatibility
export type { RenderRequest as MarkdownRenderRequest, RenderResponseBody as MarkdownRenderResponse } from '@/shared/api'

/**
 * Render Markdown to HTML using client-side renderer
 *
 * @param request - Render request with text and options
 * @returns Rendered HTML, placeholders, and hash
 */
export async function renderMarkdown(request: RenderRequest): Promise<RenderResponseBody> {
  const options = request.options || {}

  const result = await localRenderMarkdown(request.text, {
    flavor: options.flavor ?? undefined,
    features: options.features ?? undefined,
    hardbreaks: options.hardbreaks ?? undefined,
    theme: options.theme ?? undefined,
    docId: options.doc_id ?? undefined,
    token: options.token ?? undefined,
    baseOrigin: options.base_origin ?? undefined,
    sanitize: options.sanitize ?? undefined,
    absoluteAttachments: options.absolute_attachments ?? undefined,
  })

  return {
    html: result.html,
    hash: result.hash,
    placeholders: result.placeholders,
  }
}

/**
 * Render multiple Markdown documents
 *
 * @param request - Request with array of items to render
 * @returns Array of rendered results
 */
export async function renderMarkdownMany(request: RenderManyRequest): Promise<RenderManyResponse> {
  const results = await Promise.all(
    request.items.map((item) => renderMarkdown(item))
  )

  return {
    items: results,
  }
}
