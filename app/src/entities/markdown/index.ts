/**
 * Markdown rendering entity
 *
 * This module provides client-side Markdown rendering using unified/remark/rehype.
 * It replaces the server-side Comrak rendering for E2EE support.
 *
 * The API remains compatible with the original server API for seamless migration.
 */

import { renderMarkdown as localRenderMarkdown } from '@/features/markdown'

// Types defined locally (previously from OpenAPI, now removed for E2EE)
export interface RenderOptionsPayload {
  flavor?: string | null
  features?: string[] | null
  hardbreaks?: boolean | null
  theme?: string | null
  doc_id?: string | null
  token?: string | null
  base_origin?: string | null
  sanitize?: boolean | null
  absolute_attachments?: boolean | null
  placeholder_kinds?: string[] | null
}

export interface PlaceholderItemPayload {
  kind: string
  id: string
  code: string
}

export interface RenderRequest {
  text: string
  options?: RenderOptionsPayload | null
}

export interface RenderResponseBody {
  html: string
  hash?: string | null
  placeholders?: PlaceholderItemPayload[] | null
}

export interface RenderManyRequest {
  items: RenderRequest[]
}

export interface RenderManyResponse {
  items: RenderResponseBody[]
}

// Re-export types for compatibility
export type MarkdownRenderRequest = RenderRequest
export type MarkdownRenderResponse = RenderResponseBody

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
    placeholderKinds: options.placeholder_kinds ?? undefined,
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
