/**
 * Tag extraction from markdown content
 *
 * Compatible with backend implementation:
 * api/crates/infrastructure/src/core/markdown/mod.rs:256-282
 *
 * Pattern: #[A-Za-z0-9_]{1,50}
 * Exclusions:
 * - Preceded by alphanumeric or special chars: / : @ . - _ + ~ = ? & %
 * - Inside code blocks (fenced ``` or inline `)
 */

/** Characters that invalidate a hashtag when immediately preceding # */
const INVALID_PRECEDING_CHARS = /[A-Za-z0-9\/:@.\-_+~=?&%]/

/** Maximum tag length */
const MAX_TAG_LENGTH = 50

/** Pattern for fenced code blocks */
const FENCED_CODE_BLOCK_PATTERN = /```[\s\S]*?```/g

/** Pattern for inline code */
const INLINE_CODE_PATTERN = /`[^`\n]+`/g

/**
 * Remove code blocks from markdown to avoid extracting tags from code.
 */
function removeCodeBlocks(markdown: string): string {
  return markdown
    .replace(FENCED_CODE_BLOCK_PATTERN, '')
    .replace(INLINE_CODE_PATTERN, '')
}

/**
 * Check if a character at position invalidates the hashtag.
 */
function isInvalidPrecedingChar(char: string): boolean {
  return INVALID_PRECEDING_CHARS.test(char)
}

/**
 * Extract hashtags from markdown content.
 *
 * @param markdown - Raw markdown text
 * @returns Array of unique tag names (without # prefix), lowercased
 *
 * @example
 * extractTags("Hello #world and #Foo_Bar")
 * // → ["world", "foo_bar"]
 *
 * @example
 * extractTags("URL https://example.com#anchor")
 * // → [] (# preceded by alphanumeric)
 *
 * @example
 * extractTags("```\n#code_tag\n```\n#real_tag")
 * // → ["real_tag"]
 */
export function extractTags(markdown: string): string[] {
  if (!markdown || typeof markdown !== 'string') {
    return []
  }

  // Remove code blocks first
  const cleanText = removeCodeBlocks(markdown)

  const tags = new Set<string>()
  let i = 0

  while (i < cleanText.length) {
    // Find next #
    const hashIndex = cleanText.indexOf('#', i)
    if (hashIndex === -1) {
      break
    }

    // Check preceding character
    if (hashIndex > 0) {
      const prevChar = cleanText[hashIndex - 1]
      if (prevChar && isInvalidPrecedingChar(prevChar)) {
        // Not a valid tag start, skip this #
        i = hashIndex + 1
        continue
      }
    }

    // Extract tag body: [A-Za-z0-9_]{1,50}
    let tagEnd = hashIndex + 1
    let tagLength = 0

    while (tagEnd < cleanText.length && tagLength < MAX_TAG_LENGTH) {
      const char = cleanText[tagEnd]
      if (!char) break

      // Check if character is valid for tag: alphanumeric or underscore
      if (/[A-Za-z0-9_]/.test(char)) {
        tagEnd++
        tagLength++
      } else {
        break
      }
    }

    // Valid tag must have at least 1 character
    if (tagLength > 0) {
      const tagBody = cleanText.slice(hashIndex + 1, tagEnd)
      // Normalize to lowercase for consistency
      tags.add(tagBody.toLowerCase())
    }

    i = tagEnd
  }

  return Array.from(tags)
}

/**
 * Extract tags and return with original casing (first occurrence).
 * Useful when you need to preserve user's original casing.
 *
 * @param markdown - Raw markdown text
 * @returns Array of unique tag names with original casing
 */
export function extractTagsPreserveCase(markdown: string): string[] {
  if (!markdown || typeof markdown !== 'string') {
    return []
  }

  const cleanText = removeCodeBlocks(markdown)
  const seenLowercase = new Set<string>()
  const tags: string[] = []
  let i = 0

  while (i < cleanText.length) {
    const hashIndex = cleanText.indexOf('#', i)
    if (hashIndex === -1) {
      break
    }

    if (hashIndex > 0) {
      const prevChar = cleanText[hashIndex - 1]
      if (prevChar && isInvalidPrecedingChar(prevChar)) {
        i = hashIndex + 1
        continue
      }
    }

    let tagEnd = hashIndex + 1
    let tagLength = 0

    while (tagEnd < cleanText.length && tagLength < MAX_TAG_LENGTH) {
      const char = cleanText[tagEnd]
      if (!char) break

      if (/[A-Za-z0-9_]/.test(char)) {
        tagEnd++
        tagLength++
      } else {
        break
      }
    }

    if (tagLength > 0) {
      const tagBody = cleanText.slice(hashIndex + 1, tagEnd)
      const lowerTag = tagBody.toLowerCase()

      if (!seenLowercase.has(lowerTag)) {
        seenLowercase.add(lowerTag)
        tags.push(tagBody)
      }
    }

    i = tagEnd
  }

  return tags
}
