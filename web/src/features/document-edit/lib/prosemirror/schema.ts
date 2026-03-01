/**
 * ProseMirror Markdown Schema
 *
 * Defines the document structure for the WYSIWYG editor,
 * supporting common Markdown elements.
 */

import { Schema } from 'prosemirror-model'

export const markdownSchema = new Schema({
  nodes: {
    doc: { content: 'block+' },

    paragraph: {
      content: 'inline*',
      group: 'block',
      parseDOM: [{ tag: 'p' }],
      toDOM() {
        return ['p', 0]
      },
    },

    heading: {
      attrs: { level: { default: 1 } },
      content: 'inline*',
      group: 'block',
      defining: true,
      parseDOM: [
        { tag: 'h1', attrs: { level: 1 } },
        { tag: 'h2', attrs: { level: 2 } },
        { tag: 'h3', attrs: { level: 3 } },
        { tag: 'h4', attrs: { level: 4 } },
        { tag: 'h5', attrs: { level: 5 } },
        { tag: 'h6', attrs: { level: 6 } },
      ],
      toDOM(node) {
        return [`h${node.attrs.level}`, 0]
      },
    },

    blockquote: {
      content: 'block+',
      group: 'block',
      defining: true,
      parseDOM: [{ tag: 'blockquote' }],
      toDOM() {
        return ['blockquote', 0]
      },
    },

    code_block: {
      content: 'text*',
      marks: '',
      group: 'block',
      code: true,
      defining: true,
      parseDOM: [{ tag: 'pre', preserveWhitespace: 'full' }],
      toDOM() {
        return ['pre', ['code', 0]]
      },
    },

    horizontal_rule: {
      group: 'block',
      parseDOM: [{ tag: 'hr' }],
      toDOM() {
        return ['hr']
      },
    },

    bullet_list: {
      content: 'list_item+',
      group: 'block',
      parseDOM: [{ tag: 'ul' }],
      toDOM() {
        return ['ul', 0]
      },
    },

    ordered_list: {
      content: 'list_item+',
      group: 'block',
      attrs: { order: { default: 1 } },
      parseDOM: [
        {
          tag: 'ol',
          getAttrs(dom) {
            return {
              order: (dom as HTMLOListElement).hasAttribute('start')
                ? +(dom as HTMLOListElement).getAttribute('start')!
                : 1,
            }
          },
        },
      ],
      toDOM(node) {
        return node.attrs.order === 1
          ? ['ol', 0]
          : ['ol', { start: node.attrs.order }, 0]
      },
    },

    list_item: {
      content: 'paragraph block*',
      parseDOM: [{ tag: 'li' }],
      toDOM() {
        return ['li', 0]
      },
      defining: true,
    },

    text: { group: 'inline' },

    hard_break: {
      inline: true,
      group: 'inline',
      selectable: false,
      parseDOM: [{ tag: 'br' }],
      toDOM() {
        return ['br']
      },
    },

    image: {
      inline: true,
      attrs: {
        src: {},
        alt: { default: null },
        title: { default: null },
      },
      group: 'inline',
      draggable: true,
      parseDOM: [
        {
          tag: 'img[src]',
          getAttrs(dom) {
            return {
              src: (dom as HTMLImageElement).getAttribute('src'),
              title: (dom as HTMLImageElement).getAttribute('title'),
              alt: (dom as HTMLImageElement).getAttribute('alt'),
            }
          },
        },
      ],
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
    },
  },

  marks: {
    strong: {
      parseDOM: [
        { tag: 'strong' },
        { tag: 'b' },
        {
          style: 'font-weight',
          getAttrs: (value) =>
            /^(bold(er)?|[5-9]\d{2,})$/.test(value as string) && null,
        },
      ],
      toDOM() {
        return ['strong', 0]
      },
    },

    em: {
      parseDOM: [
        { tag: 'i' },
        { tag: 'em' },
        { style: 'font-style=italic' },
      ],
      toDOM() {
        return ['em', 0]
      },
    },

    code: {
      parseDOM: [{ tag: 'code' }],
      toDOM() {
        return ['code', 0]
      },
    },

    link: {
      attrs: {
        href: {},
        title: { default: null },
      },
      inclusive: false,
      parseDOM: [
        {
          tag: 'a[href]',
          getAttrs(dom) {
            return {
              href: (dom as HTMLAnchorElement).getAttribute('href'),
              title: (dom as HTMLAnchorElement).getAttribute('title'),
            }
          },
        },
      ],
      toDOM(node) {
        const { href, title } = node.attrs
        // Sanitize href: only allow https and mailto (threat-model.md)
        const safeHref = /^(https|mailto):/i.test(href) ? href : undefined
        return ['a', { href: safeHref, title, rel: 'noopener noreferrer' }, 0]
      },
    },

    strikethrough: {
      parseDOM: [{ tag: 's' }, { tag: 'del' }, { style: 'text-decoration=line-through' }],
      toDOM() {
        return ['del', 0]
      },
    },
  },
})
