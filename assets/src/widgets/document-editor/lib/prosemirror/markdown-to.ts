import type { BlockContent, ListItem, PhrasingContent, Root } from "mdast";
import type { Mark, Node as ProseMirrorNode } from "prosemirror-model";
import remarkGfm from "remark-gfm";
import remarkStringify from "remark-stringify";
import { unified } from "unified";

const markdownStringifier = unified()
  .use(remarkGfm)
  .use(remarkStringify, {
    bullet: "-",
    fences: true,
    listItemIndent: "one",
    join: [() => 0],
  });

function isEmptyParagraph(node: ProseMirrorNode): boolean {
  return node.type.name === "paragraph" && node.content.size === 0;
}

function hasTrailingEmptyParagraph(doc: ProseMirrorNode): boolean {
  return doc.childCount > 1 && !!doc.lastChild && isEmptyParagraph(doc.lastChild);
}

function markToMdastNode(
  markName: string,
  child: PhrasingContent,
  attrs?: Record<string, unknown>,
): PhrasingContent {
  switch (markName) {
    case "strong":
      return { type: "strong", children: [child] };
    case "em":
      return { type: "emphasis", children: [child] };
    case "strikethrough":
      return { type: "delete", children: [child] };
    case "link":
      return {
        type: "link",
        url: String(attrs?.href ?? ""),
        title: attrs?.title ? String(attrs.title) : null,
        children: [child],
      };
    default:
      return child;
  }
}

function textWithMarksToMdast(text: string, marks: readonly Mark[]): PhrasingContent[] {
  const hasCode = marks.some((mark) => mark.type.name === "code");
  if (hasCode) {
    return [{ type: "inlineCode", value: text }];
  }

  let node: PhrasingContent = { type: "text", value: text };
  const priority = ["strong", "em", "strikethrough", "link"] as const;

  for (const name of priority) {
    const mark = marks.find((m) => m.type.name === name);
    if (mark) {
      node = markToMdastNode(name, node, mark.attrs as Record<string, unknown>);
    }
  }

  return [node];
}

function inlineFromProseMirror(node: ProseMirrorNode): PhrasingContent[] {
  const inlineChildren: PhrasingContent[] = [];

  node.forEach((childNode) => {
    switch (childNode.type.name) {
      case "text": {
        if (childNode.text) {
          inlineChildren.push(...textWithMarksToMdast(childNode.text, childNode.marks));
        }
        break;
      }
      case "image": {
        inlineChildren.push({
          type: "image",
          url: String(childNode.attrs.src ?? ""),
          alt: childNode.attrs.alt ? String(childNode.attrs.alt) : null,
          title: childNode.attrs.title ? String(childNode.attrs.title) : null,
        });
        break;
      }
      default:
        if (childNode.textContent.length > 0) {
          inlineChildren.push({ type: "text", value: childNode.textContent });
        }
        break;
    }
  });

  return inlineChildren;
}

function blockFromProseMirror(node: ProseMirrorNode): BlockContent | null {
  switch (node.type.name) {
    case "paragraph":
      return { type: "paragraph", children: inlineFromProseMirror(node) };
    case "heading": {
      const depth = Math.max(1, Math.min(6, Number(node.attrs.level ?? 1))) as
        | 1
        | 2
        | 3
        | 4
        | 5
        | 6;
      return {
        type: "heading",
        depth,
        children: inlineFromProseMirror(node),
      };
    }
    case "blockquote": {
      const children: BlockContent[] = [];
      node.forEach((childNode) => {
        const mapped = blockFromProseMirror(childNode);
        if (mapped) children.push(mapped);
      });
      return { type: "blockquote", children };
    }
    case "code_block":
      return {
        type: "code",
        lang: typeof node.attrs.language === "string" ? node.attrs.language : null,
        value: node.textContent,
      };
    case "horizontal_rule":
      return { type: "thematicBreak" };
    case "bullet_list": {
      const children: ListItem[] = [];
      node.forEach((childNode) => {
        if (childNode.type.name !== "list_item") return;
        const listItemChildren: BlockContent[] = [];
        childNode.forEach((c) => {
          const mapped = blockFromProseMirror(c);
          if (mapped) listItemChildren.push(mapped);
        });
        children.push({
          type: "listItem",
          spread: false,
          children: listItemChildren,
        });
      });
      return { type: "list", ordered: false, spread: false, children };
    }
    case "ordered_list": {
      const children: ListItem[] = [];
      node.forEach((childNode) => {
        if (childNode.type.name !== "list_item") return;
        const listItemChildren: BlockContent[] = [];
        childNode.forEach((c) => {
          const mapped = blockFromProseMirror(c);
          if (mapped) listItemChildren.push(mapped);
        });
        children.push({
          type: "listItem",
          spread: false,
          children: listItemChildren,
        });
      });
      return {
        type: "list",
        ordered: true,
        start: Number(node.attrs.order ?? 1),
        spread: false,
        children,
      };
    }
    default:
      return null;
  }
}

export function proseMirrorDocToMarkdown(doc: ProseMirrorNode): string {
  const root: Root = { type: "root", children: [] };

  doc.forEach((childNode) => {
    const mapped = blockFromProseMirror(childNode);
    if (mapped) root.children.push(mapped);
  });

  const markdown = markdownStringifier.stringify(root);
  if (typeof markdown !== "string") return "";
  return hasTrailingEmptyParagraph(doc) ? markdown : markdown.replace(/\n$/, "");
}
