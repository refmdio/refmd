/**
 * Japanese + English tokenizer for search indexing
 */

// TinySegmenter doesn't have type definitions, so we need to declare the module
// @ts-expect-error - tiny-segmenter doesn't have type definitions
import TinySegmenter from 'tiny-segmenter'

const segmenter = new TinySegmenter()

/**
 * Tokenize text for both Japanese and English content.
 * - Japanese: Uses TinySegmenter for morphological analysis
 * - English: Simple whitespace split with lowercasing
 */
export function tokenize(text: string): string[] {
  if (!text || typeof text !== 'string') {
    return []
  }

  // Japanese tokenization via TinySegmenter
  const japaneseTokens: string[] = segmenter.segment(text)

  // English tokenization (simple whitespace split)
  const englishTokens = text
    .toLowerCase()
    .split(/\s+/)
    .filter((token) => token.length > 0)

  // Combine and deduplicate
  return [...new Set([...japaneseTokens, ...englishTokens])]
}
