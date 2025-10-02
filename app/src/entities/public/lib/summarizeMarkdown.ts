const CODE_BLOCK_RE = /```[\s\S]*?```/g
const INLINE_CODE_RE = /`[^`]*`/g
const IMAGE_RE = /!\[[^\]]*\]\([^)]*\)/g
const LINK_RE = /\[([^\]]*)\]\(([^)]*)\)/g
const MARKDOWN_CHAR_RE = /[\*_>#`~\-]/g

function squashWhitespace(value: string): string {
  return value
    .replace(/\s+/g, ' ')
    .trim()
}

export function summarizeMarkdown(input: string, fallback: string, maxLength = 200): string {
  if (!input || !input.trim()) return fallback

  const withoutCodeBlocks = input.replace(CODE_BLOCK_RE, ' ')
  const withoutInlineCode = withoutCodeBlocks.replace(INLINE_CODE_RE, ' ')
  const withoutImages = withoutInlineCode.replace(IMAGE_RE, ' ')
  const linksRestored = withoutImages.replace(LINK_RE, (_, __, href: string) => href ?? ' ')
  const cleaned = linksRestored.replace(MARKDOWN_CHAR_RE, ' ')
  const normalized = squashWhitespace(cleaned)

  if (!normalized) return fallback

  const summary = normalized.slice(0, maxLength)
  return summary || fallback
}
