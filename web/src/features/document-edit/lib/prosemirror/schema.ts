/**
 * ProseMirror Markdown Schema
 *
 * Based on prosemirror-schema-basic with security overrides
 * for XSS sanitization (threat-model.md).
 */

import { Schema } from 'prosemirror-model'
import { schema as basicSchema } from 'prosemirror-schema-basic'
import { addListNodes } from 'prosemirror-schema-list'

// Start from basicSchema nodes, add list nodes
let nodes = addListNodes(basicSchema.spec.nodes, 'paragraph block*', 'block')

// Override hard_break: filter ProseMirror-trailingBreak
nodes = nodes.update('hard_break', {
  ...basicSchema.spec.nodes.get('hard_break')!,
  parseDOM: [{
    tag: 'br',
    getAttrs(dom: HTMLElement) {
      return dom.classList.contains('ProseMirror-trailingBreak') ? false : null
    },
  }],
})

// Override image: add XSS sanitization in toDOM
nodes = nodes.update('image', {
  ...basicSchema.spec.nodes.get('image')!,
  toDOM(node) {
    const { src, alt, title } = node.attrs
    // Sanitize src: only allow https, blob, and non-SVG data:image (threat-model.md)
    const safeSrc =
      /^(https:|blob:)/i.test(src) ||
      (/^data:image\//i.test(src) && !/^data:image\/svg/i.test(src))
        ? src
        : undefined
    return ['img', { src: safeSrc, alt, title }]
  },
})

// Start from basicSchema marks
let marks = basicSchema.spec.marks

// Override link: add XSS sanitization + rel attr
marks = marks.update('link', {
  ...basicSchema.spec.marks.get('link')!,
  toDOM(node) {
    const { href, title } = node.attrs
    // Sanitize href: only allow https and mailto (threat-model.md)
    const safeHref = /^(https|mailto):/i.test(href) ? href : undefined
    return ['a', { href: safeHref, title, rel: 'noopener noreferrer' }, 0]
  },
})

// Add strikethrough mark (not in basicSchema)
marks = marks.addToEnd('strikethrough', {
  parseDOM: [{ tag: 's' }, { tag: 'del' }, { style: 'text-decoration=line-through' }],
  toDOM() { return ['del', 0] },
})

export const markdownSchema = new Schema({ nodes, marks })
