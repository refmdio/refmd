/**
 * Markdown plugins for unified/remark/rehype pipeline
 */

// Remark plugins (mdast)
export { remarkSourcepos } from './sourcepos'

// Rehype plugins (hast)
export { rehypeWikilink } from './wikilink'
export { rehypeHashtag } from './hashtag'
export { rehypeMention } from './mention'

export { rehypePlaceholder, resetPlaceholderCounter } from './placeholder'
export type { PlaceholderOptions } from './placeholder'

export { rehypeHighlight, initHighlighter } from './highlight'
export type { HighlightOptions } from './highlight'

export { rehypeAttachments } from './attachments'
export type { AttachmentOptions } from './attachments'

// Sanitization schema
export { refmdSanitizeSchema } from './sanitize'
