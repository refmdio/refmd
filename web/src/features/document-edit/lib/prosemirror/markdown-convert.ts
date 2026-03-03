/**
 * Remark-based Markdown <-> ProseMirror conversion
 *
 * Uses remark with remarkBreaks + join:[()=>0] to match the @pm-cm demo
 * behavior: Enter in ProseMirror produces a single newline in CodeMirror
 * (not a blank line).
 */

import type {
  BlockContent,
  Content,
  Delete,
  Emphasis,
  Heading,
  Image,
  InlineCode,
  Link,
  List,
  ListItem,
  PhrasingContent,
  Root,
  Strong,
  Text,
} from 'mdast'
import type { Mark, Node as ProseMirrorNode, Schema } from 'prosemirror-model'
import { unified } from 'unified'
import remarkBreaks from 'remark-breaks'
import remarkGfm from 'remark-gfm'
import remarkParse from 'remark-parse'
import remarkStringify from 'remark-stringify'

const markdownParser = unified().use(remarkParse).use(remarkGfm).use(remarkBreaks)
const markdownStringifier = unified()
  .use(remarkGfm)
  .use(remarkStringify, {
    bullet: '-',
    fences: true,
    listItemIndent: 'one',
    join: [() => 0],
  })

export function normalizeMarkdown(value: string): string {
  // Strip trailing \n to match proseMirrorDocToMarkdown which also strips it.
  // Without this, the bridge's canonical check (normalize(serialize(doc)) vs
  // normalize(text)) detects a mismatch and writes back to Y.Text. That
  // write-back fires yCollab's Y.Text observer during CM's ViewPlugin.update,
  // causing a reentrant EditorView.update that permanently destroys yCollab.
  return value.replace(/\r\n?/g, '\n').replace(/\n+$/, '')
}

function appendMark(marks: Mark[], nextMark: Mark): Mark[] {
  if (marks.some((mark) => mark.type === nextMark.type)) return marks
  return [...marks, nextMark]
}

function textNode(schema: Schema, value: string, marks: Mark[] = []): ProseMirrorNode {
  return schema.text(value, marks)
}

function inlineChildrenToProseMirror(
  children: PhrasingContent[],
  schema: Schema,
  activeMarks: Mark[] = [],
): ProseMirrorNode[] {
  const inlineNodes: ProseMirrorNode[] = []

  for (const child of children) {
    switch (child.type) {
      case 'text': {
        const text = child as Text
        if (text.value.length > 0) {
          inlineNodes.push(textNode(schema, text.value, activeMarks))
        }
        break
      }
      case 'strong': {
        const strong = child as Strong
        const strongMark = schema.marks.strong
        if (!strongMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(strong.children, schema, activeMarks))
          break
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            strong.children,
            schema,
            appendMark(activeMarks, strongMark.create()),
          ),
        )
        break
      }
      case 'emphasis': {
        const emphasis = child as Emphasis
        const emMark = schema.marks.em
        if (!emMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(emphasis.children, schema, activeMarks))
          break
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            emphasis.children,
            schema,
            appendMark(activeMarks, emMark.create()),
          ),
        )
        break
      }
      case 'delete': {
        const deletion = child as Delete
        const strikeMark = schema.marks.strikethrough
        if (!strikeMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(deletion.children, schema, activeMarks))
          break
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            deletion.children,
            schema,
            appendMark(activeMarks, strikeMark.create()),
          ),
        )
        break
      }
      case 'inlineCode': {
        const inlineCode = child as InlineCode
        const codeMark = schema.marks.code
        if (!codeMark) {
          inlineNodes.push(textNode(schema, inlineCode.value, activeMarks))
          break
        }
        inlineNodes.push(textNode(schema, inlineCode.value, appendMark(activeMarks, codeMark.create())))
        break
      }
      case 'link': {
        const link = child as Link
        const linkMark = schema.marks.link
        if (!linkMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(link.children, schema, activeMarks))
          break
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            link.children,
            schema,
            appendMark(
              activeMarks,
              linkMark.create({ href: link.url, title: link.title ?? null }),
            ),
          ),
        )
        break
      }
      case 'image': {
        const image = child as Image
        if (schema.nodes.image) {
          inlineNodes.push(
            schema.nodes.image.create({
              src: image.url,
              alt: image.alt ?? null,
              title: image.title ?? null,
            }),
          )
        }
        break
      }
      default:
        break
    }
  }

  return inlineNodes
}

function blockChildrenToProseMirror(children: Content[], schema: Schema): ProseMirrorNode[] {
  const blockNodes: ProseMirrorNode[] = []

  for (const child of children) {
    switch (child.type) {
      case 'paragraph': {
        const inlineNodes = inlineChildrenToProseMirror(child.children, schema)
        blockNodes.push(schema.nodes.paragraph.create(null, inlineNodes))
        break
      }
      case 'heading': {
        const heading = child as Heading
        const level = Math.max(1, Math.min(6, heading.depth))
        const inlineNodes = inlineChildrenToProseMirror(heading.children, schema)
        blockNodes.push(schema.nodes.heading.create({ level }, inlineNodes))
        break
      }
      case 'blockquote': {
        const nested = blockChildrenToProseMirror(child.children, schema)
        blockNodes.push(schema.nodes.blockquote.create(null, nested))
        break
      }
      case 'code': {
        blockNodes.push(
          schema.nodes.code_block.create(null, child.value ? schema.text(child.value) : undefined),
        )
        break
      }
      case 'thematicBreak': {
        blockNodes.push(schema.nodes.horizontal_rule.create())
        break
      }
      case 'list': {
        const list = child as List
        const listItems = list.children.map((listItem) => {
          const item = listItem as ListItem
          const itemChildren = blockChildrenToProseMirror(item.children as Content[], schema)
          const normalized =
            itemChildren.length > 0 ? itemChildren : [schema.nodes.paragraph.create()]
          return schema.nodes.list_item.create(null, normalized)
        })

        if (listItems.length === 0) break

        if (list.ordered) {
          blockNodes.push(
            schema.nodes.ordered_list.create({ order: list.start ?? 1 }, listItems),
          )
        } else {
          blockNodes.push(schema.nodes.bullet_list.create(null, listItems))
        }
        break
      }
      default:
        break
    }
  }

  return blockNodes
}

function markToMdastNode(
  markName: string,
  child: PhrasingContent,
  attrs?: Record<string, unknown>,
): PhrasingContent {
  switch (markName) {
    case 'strong':
      return { type: 'strong', children: [child] }
    case 'em':
      return { type: 'emphasis', children: [child] }
    case 'strikethrough':
      return { type: 'delete', children: [child] }
    case 'link':
      return {
        type: 'link',
        url: String(attrs?.href ?? ''),
        title: attrs?.title ? String(attrs.title) : null,
        children: [child],
      }
    default:
      return child
  }
}

function textWithMarksToMdast(text: string, marks: readonly Mark[]): PhrasingContent[] {
  const hasCode = marks.some((mark) => mark.type.name === 'code')
  if (hasCode) {
    return [{ type: 'inlineCode', value: text }]
  }

  let node: PhrasingContent = { type: 'text', value: text }
  const priority = ['strong', 'em', 'strikethrough', 'link'] as const

  for (const name of priority) {
    const mark = marks.find((m) => m.type.name === name)
    if (mark) {
      node = markToMdastNode(name, node, mark.attrs as Record<string, unknown>)
    }
  }

  return [node]
}

function inlineFromProseMirror(node: ProseMirrorNode): PhrasingContent[] {
  const inlineChildren: PhrasingContent[] = []

  node.forEach((childNode) => {
    switch (childNode.type.name) {
      case 'text': {
        if (childNode.text) {
          inlineChildren.push(...textWithMarksToMdast(childNode.text, childNode.marks))
        }
        break
      }
      case 'image': {
        inlineChildren.push({
          type: 'image',
          url: String(childNode.attrs.src ?? ''),
          alt: childNode.attrs.alt ? String(childNode.attrs.alt) : null,
          title: childNode.attrs.title ? String(childNode.attrs.title) : null,
        })
        break
      }
      default:
        if (childNode.textContent.length > 0) {
          inlineChildren.push({ type: 'text', value: childNode.textContent })
        }
        break
    }
  })

  return inlineChildren
}

function blockFromProseMirror(node: ProseMirrorNode): BlockContent | null {
  switch (node.type.name) {
    case 'paragraph':
      return { type: 'paragraph', children: inlineFromProseMirror(node) }
    case 'heading': {
      const depth = Math.max(1, Math.min(6, Number(node.attrs.level ?? 1))) as
        | 1
        | 2
        | 3
        | 4
        | 5
        | 6
      return { type: 'heading', depth, children: inlineFromProseMirror(node) }
    }
    case 'blockquote': {
      const children: BlockContent[] = []
      node.forEach((childNode) => {
        const mapped = blockFromProseMirror(childNode)
        if (mapped) children.push(mapped)
      })
      return { type: 'blockquote', children }
    }
    case 'code_block':
      return { type: 'code', lang: null, value: node.textContent }
    case 'horizontal_rule':
      return { type: 'thematicBreak' }
    case 'bullet_list': {
      const children: ListItem[] = []
      node.forEach((childNode) => {
        if (childNode.type.name !== 'list_item') return
        const listItemChildren: BlockContent[] = []
        childNode.forEach((c) => {
          const mapped = blockFromProseMirror(c)
          if (mapped) listItemChildren.push(mapped)
        })
        children.push({ type: 'listItem', spread: false, children: listItemChildren })
      })
      return { type: 'list', ordered: false, spread: false, children }
    }
    case 'ordered_list': {
      const children: ListItem[] = []
      node.forEach((childNode) => {
        if (childNode.type.name !== 'list_item') return
        const listItemChildren: BlockContent[] = []
        childNode.forEach((c) => {
          const mapped = blockFromProseMirror(c)
          if (mapped) listItemChildren.push(mapped)
        })
        children.push({ type: 'listItem', spread: false, children: listItemChildren })
      })
      return {
        type: 'list',
        ordered: true,
        start: Number(node.attrs.order ?? 1),
        spread: false,
        children,
      }
    }
    default:
      return null
  }
}

/** Preserve intentional blank lines from markdown source as empty paragraphs */
function insertEmptyParagraphsForGaps(children: Content[]): Content[] {
  const result: Content[] = []

  for (let i = 0; i < children.length; i++) {
    const child = children[i]

    if (child.type === 'blockquote') {
      child.children = insertEmptyParagraphsForGaps(child.children) as BlockContent[]
    } else if (child.type === 'list') {
      for (const item of child.children) {
        item.children = insertEmptyParagraphsForGaps(item.children) as BlockContent[]
      }
    }

    if (i > 0) {
      const prev = children[i - 1]
      if (prev.position && child.position) {
        const gap = child.position.start.line - prev.position.end.line - 1
        for (let j = 0; j < gap; j++) {
          result.push({ type: 'paragraph', children: [] })
        }
      }
    }

    result.push(child)
  }

  return result
}

/** Convert remark break nodes into separate paragraphs */
function splitBreakParagraphs(children: Content[]): Content[] {
  const result: Content[] = []

  for (const child of children) {
    if (child.type === 'blockquote') {
      child.children = splitBreakParagraphs(child.children) as BlockContent[]
    } else if (child.type === 'list') {
      for (const item of child.children) {
        item.children = splitBreakParagraphs(item.children) as BlockContent[]
      }
    }

    if (child.type !== 'paragraph') {
      result.push(child)
      continue
    }

    if (!child.children.some((c) => c.type === 'break')) {
      result.push(child)
      continue
    }

    let current: PhrasingContent[] = []
    for (const inline of child.children) {
      if (inline.type === 'break') {
        result.push({ type: 'paragraph', children: current })
        current = []
      } else {
        current.push(inline)
      }
    }
    result.push({ type: 'paragraph', children: current })
  }

  return result
}

export function markdownToProseMirrorDoc(
  markdown: string,
  schema: Schema,
): ProseMirrorNode {
  try {
    const parsedTree = markdownParser.runSync(
      markdownParser.parse(normalizeMarkdown(markdown)),
    ) as Root
    parsedTree.children = insertEmptyParagraphsForGaps(parsedTree.children) as Root['children']
    parsedTree.children = splitBreakParagraphs(parsedTree.children) as Root['children']
    const blockNodes = blockChildrenToProseMirror(parsedTree.children, schema)

    if (blockNodes.length === 0) {
      return schema.node('doc', null, [schema.nodes.paragraph.create()])
    }

    return schema.node('doc', null, blockNodes)
  } catch {
    return schema.node('doc', null, [schema.nodes.paragraph.create(null, schema.text(markdown))])
  }
}

export function proseMirrorDocToMarkdown(doc: ProseMirrorNode): string {
  const root: Root = { type: 'root', children: [] }

  doc.forEach((childNode) => {
    const mapped = blockFromProseMirror(childNode)
    if (mapped) root.children.push(mapped)
  })

  const markdown = markdownStringifier.stringify(root)
  return typeof markdown === 'string' ? markdown.replace(/\n$/, '') : ''
}
