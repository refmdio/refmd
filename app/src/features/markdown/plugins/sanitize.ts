/**
 * Sanitization schema for rehype-sanitize
 * Compatible with Ammonia settings used in Comrak backend
 *
 * Ammonia compatibility:
 * - Allow common attributes: class, id, title, data-*
 * - Allow placeholder metadata attributes
 * - Allow code-related tags with style for syntax highlighting
 * - Allow input for tasklist checkboxes
 * - Allow custom elements like refmd-wikilink
 */

import { defaultSchema } from 'rehype-sanitize'

/**
 * Merge two arrays, avoiding duplicates
 */
function mergeArrays<T>(a: T[] | null | undefined, b: T[]): T[] {
  const set = new Set([...(a || []), ...b])
  return Array.from(set)
}

/**
 * Sanitization schema compatible with Ammonia
 */
export const refmdSanitizeSchema = {
  ...defaultSchema,

  // Allow custom elements
  tagNames: mergeArrays(defaultSchema.tagNames, [
    // Custom components
    'refmd-wikilink',
    // Form elements for tasklist
    'input',
    // Keep existing allowed tags
    'pre',
    'code',
    'span',
    'div',
  ]),

  attributes: {
    ...defaultSchema.attributes,

    // Global attributes allowed on all elements
    '*': mergeArrays(defaultSchema.attributes?.['*'], [
      'className',
      'class',
      'id',
      'title',
      // Placeholder attributes
      'data-refmd-placeholder',
      'data-placeholder-id',
      'data-placeholder-kind',
      'data-placeholder-hydrate',
      'data-placeholder-hydrate-export',
      'data-placeholder-hydrate-context',
      'data-placeholder-plugin',
      'data-placeholder-version',
      'data-placeholder-scope',
      // Editor sync
      'data-sourcepos',
      // Link metadata
      'data-wiki-target',
      'data-mention-target',
      'data-embed-target',
      // Syntax highlighting (inline styles)
      'style',
    ]),

    // Custom wikilink element
    'refmd-wikilink': ['target', 'href', 'variant', 'class'],

    // Tasklist checkbox
    input: ['type', 'checked', 'disabled', 'class'],

    // Links
    a: mergeArrays(defaultSchema.attributes?.a, [
      'href',
      'rel',
      'target',
      'class',
      'data-wiki-target',
      'data-mention-target',
    ]),

    // Images
    img: mergeArrays(defaultSchema.attributes?.img, ['src', 'alt', 'title', 'class']),

    // Code blocks with syntax highlighting
    pre: ['class', 'style', 'data-language'],
    code: ['class', 'style', 'data-language'],
    span: ['class', 'style'],

    // Divs for placeholders and not-prose wrapper
    div: ['class', 'style', 'data-refmd-placeholder', 'data-placeholder-id', 'data-placeholder-kind'],
  },

  // Allow relative URLs and hash URLs
  protocols: {
    ...defaultSchema.protocols,
    href: ['http', 'https', 'mailto', '#', 'data'],
    src: ['http', 'https', 'data'],
  },

  // Strip certain elements completely
  strip: ['script', 'style'],

  // Allow clobbering for specific attributes (needed for some functionality)
  clobberPrefix: '',
  clobber: [],

  // Required attributes
  required: {
    input: {
      type: 'checkbox',
      disabled: true,
    },
  },
}

export default refmdSanitizeSchema
