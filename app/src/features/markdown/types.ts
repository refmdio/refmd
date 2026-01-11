/**
 * Markdown rendering types
 * Compatible with backend Comrak API
 */

export interface RenderOptions {
  /** Document flavor: 'doc' | 'commonmark' */
  flavor?: string
  /** Enabled features: ['gfm', 'highlight'] */
  features?: string[]
  /** Treat soft line breaks as <br> */
  hardbreaks?: boolean
  /** Syntax highlight theme name */
  theme?: string
  /** Document ID for attachment URL rewriting */
  docId?: string
  /** Share token for attachment URLs */
  token?: string
  /** Base origin for absolute URLs */
  baseOrigin?: string
  /** Plugin placeholder kinds to detect */
  placeholderKinds?: string[]
  /** Enable HTML sanitization (default: true) */
  sanitize?: boolean
  /** Rewrite attachment URLs to absolute */
  absoluteAttachments?: boolean
}

export interface PlaceholderItem {
  kind: string
  id: string
  code: string
}

export interface RenderResponse {
  html: string
  placeholders: PlaceholderItem[]
  hash: string
}

/**
 * API-compatible request type
 */
export interface RenderRequest {
  text: string
  flavor?: string
  features?: string[]
  hardbreaks?: boolean
  theme?: string
  doc_id?: string
  token?: string
  base_origin?: string
  placeholder_kinds?: string[]
  sanitize?: boolean
  absolute_attachments?: boolean
}

/**
 * Convert API request to internal options
 */
export function requestToOptions(request: RenderRequest): RenderOptions {
  return {
    flavor: request.flavor,
    features: request.features,
    hardbreaks: request.hardbreaks,
    theme: request.theme,
    docId: request.doc_id,
    token: request.token,
    baseOrigin: request.base_origin,
    placeholderKinds: request.placeholder_kinds,
    sanitize: request.sanitize,
    absoluteAttachments: request.absolute_attachments,
  }
}
