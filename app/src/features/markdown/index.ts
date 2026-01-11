/**
 * Client-side Markdown rendering feature
 * Replaces server-side Comrak rendering for E2EE support
 */

export { renderMarkdown, renderMarkdownMany, initHighlighter } from './renderer'
export type {
  RenderOptions,
  RenderResponse,
  PlaceholderItem,
  RenderRequest,
  requestToOptions,
} from './types'
