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
} from "mdast";
import type { Mark, Node as ProseMirrorNode, Schema } from "prosemirror-model";
import remarkBreaks from "remark-breaks";
import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import { unified } from "unified";
import { normalizeMarkdown } from "./normalize";

const markdownParser = unified().use(remarkParse).use(remarkGfm).use(remarkBreaks);

function appendMark(marks: Mark[], nextMark: Mark): Mark[] {
  if (marks.some((mark) => mark.type === nextMark.type)) return marks;
  return [...marks, nextMark];
}

function textNode(schema: Schema, value: string, marks: Mark[] = []): ProseMirrorNode {
  return schema.text(value, marks);
}

function inlineChildrenToProseMirror(
  children: PhrasingContent[],
  schema: Schema,
  activeMarks: Mark[] = [],
): ProseMirrorNode[] {
  const inlineNodes: ProseMirrorNode[] = [];

  for (const child of children) {
    switch (child.type) {
      case "text": {
        const text = child as Text;
        if (text.value.length > 0) {
          inlineNodes.push(textNode(schema, text.value, activeMarks));
        }
        break;
      }
      case "strong": {
        const strong = child as Strong;
        const strongMark = schema.marks.strong;
        if (!strongMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(strong.children, schema, activeMarks));
          break;
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            strong.children,
            schema,
            appendMark(activeMarks, strongMark.create()),
          ),
        );
        break;
      }
      case "emphasis": {
        const emphasis = child as Emphasis;
        const emMark = schema.marks.em;
        if (!emMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(emphasis.children, schema, activeMarks));
          break;
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            emphasis.children,
            schema,
            appendMark(activeMarks, emMark.create()),
          ),
        );
        break;
      }
      case "delete": {
        const deletion = child as Delete;
        const strikeMark = schema.marks.strikethrough;
        if (!strikeMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(deletion.children, schema, activeMarks));
          break;
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            deletion.children,
            schema,
            appendMark(activeMarks, strikeMark.create()),
          ),
        );
        break;
      }
      case "inlineCode": {
        const inlineCode = child as InlineCode;
        const codeMark = schema.marks.code;
        if (!codeMark) {
          inlineNodes.push(textNode(schema, inlineCode.value, activeMarks));
          break;
        }
        inlineNodes.push(
          textNode(schema, inlineCode.value, appendMark(activeMarks, codeMark.create())),
        );
        break;
      }
      case "link": {
        const link = child as Link;
        const linkMark = schema.marks.link;
        if (!linkMark) {
          inlineNodes.push(...inlineChildrenToProseMirror(link.children, schema, activeMarks));
          break;
        }
        inlineNodes.push(
          ...inlineChildrenToProseMirror(
            link.children,
            schema,
            appendMark(activeMarks, linkMark.create({ href: link.url, title: link.title ?? null })),
          ),
        );
        break;
      }
      case "image": {
        const image = child as Image;
        if (schema.nodes.image) {
          inlineNodes.push(
            schema.nodes.image.create({
              src: image.url,
              alt: image.alt ?? null,
              title: image.title ?? null,
            }),
          );
        }
        break;
      }
      default:
        break;
    }
  }

  return inlineNodes;
}

function blockChildrenToProseMirror(children: Content[], schema: Schema): ProseMirrorNode[] {
  const blockNodes: ProseMirrorNode[] = [];

  for (const child of children) {
    switch (child.type) {
      case "paragraph": {
        const inlineNodes = inlineChildrenToProseMirror(child.children, schema);
        blockNodes.push(schema.nodes.paragraph.create(null, inlineNodes));
        break;
      }
      case "heading": {
        const heading = child as Heading;
        const level = Math.max(1, Math.min(6, heading.depth));
        const inlineNodes = inlineChildrenToProseMirror(heading.children, schema);
        blockNodes.push(schema.nodes.heading.create({ level }, inlineNodes));
        break;
      }
      case "blockquote": {
        const nested = blockChildrenToProseMirror(child.children, schema);
        blockNodes.push(schema.nodes.blockquote.create(null, nested));
        break;
      }
      case "code": {
        blockNodes.push(
          schema.nodes.code_block.create(null, child.value ? schema.text(child.value) : undefined),
        );
        break;
      }
      case "thematicBreak": {
        blockNodes.push(schema.nodes.horizontal_rule.create());
        break;
      }
      case "list": {
        const list = child as List;
        const listItems = list.children.map((listItem) => {
          const item = listItem as ListItem;
          const itemChildren = blockChildrenToProseMirror(item.children as Content[], schema);
          const normalized =
            itemChildren.length > 0 ? itemChildren : [schema.nodes.paragraph.create()];
          return schema.nodes.list_item.create(null, normalized);
        });

        if (listItems.length === 0) break;

        if (list.ordered) {
          blockNodes.push(schema.nodes.ordered_list.create({ order: list.start ?? 1 }, listItems));
        } else {
          blockNodes.push(schema.nodes.bullet_list.create(null, listItems));
        }
        break;
      }
      default:
        break;
    }
  }

  return blockNodes;
}

function insertEmptyParagraphsForGaps(children: Content[]): Content[] {
  const result: Content[] = [];

  for (let i = 0; i < children.length; i++) {
    const child = children[i];

    if (child.type === "blockquote") {
      child.children = insertEmptyParagraphsForGaps(child.children) as BlockContent[];
    } else if (child.type === "list") {
      for (const item of child.children) {
        item.children = insertEmptyParagraphsForGaps(item.children) as BlockContent[];
      }
    }

    if (i > 0) {
      const prev = children[i - 1];
      if (prev.position && child.position) {
        const gap = child.position.start.line - prev.position.end.line - 1;
        for (let j = 0; j < gap; j++) {
          result.push({ type: "paragraph", children: [] });
        }
      }
    }

    result.push(child);
  }

  return result;
}

function splitBreakParagraphs(children: Content[]): Content[] {
  const result: Content[] = [];

  for (const child of children) {
    if (child.type === "blockquote") {
      child.children = splitBreakParagraphs(child.children) as BlockContent[];
    } else if (child.type === "list") {
      for (const item of child.children) {
        item.children = splitBreakParagraphs(item.children) as BlockContent[];
      }
    }

    if (child.type !== "paragraph") {
      result.push(child);
      continue;
    }

    if (!child.children.some((c) => c.type === "break")) {
      result.push(child);
      continue;
    }

    let current: PhrasingContent[] = [];
    for (const inline of child.children) {
      if (inline.type === "break") {
        result.push({ type: "paragraph", children: current });
        current = [];
      } else {
        current.push(inline);
      }
    }
    result.push({ type: "paragraph", children: current });
  }

  return result;
}

export function markdownToProseMirrorDoc(markdown: string, schema: Schema): ProseMirrorNode {
  try {
    const parsedTree = markdownParser.runSync(
      markdownParser.parse(normalizeMarkdown(markdown)),
    ) as Root;
    parsedTree.children = insertEmptyParagraphsForGaps(parsedTree.children) as Root["children"];
    parsedTree.children = splitBreakParagraphs(parsedTree.children) as Root["children"];
    const blockNodes = blockChildrenToProseMirror(parsedTree.children, schema);

    if (blockNodes.length === 0) {
      return schema.node("doc", null, [schema.nodes.paragraph.create()]);
    }

    return schema.node("doc", null, blockNodes);
  } catch {
    return schema.node("doc", null, [schema.nodes.paragraph.create(null, schema.text(markdown))]);
  }
}
