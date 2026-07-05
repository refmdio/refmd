import type { BlockContent, Content, PhrasingContent, Root } from "mdast";
import remarkBreaks from "remark-breaks";
import remarkGfm from "remark-gfm";
import remarkParse from "remark-parse";
import { unified } from "unified";
import { normalizeMarkdown } from "./normalize";

const markdownParser = unified().use(remarkParse).use(remarkGfm).use(remarkBreaks);

function countTrailingNewlines(value: string): number {
  const match = value.match(/\n+$/);
  return match ? match[0].length : 0;
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

    if (!child.children.some((c) => c.type === "break" && !c.position)) {
      result.push(child);
      continue;
    }

    let current: PhrasingContent[] = [];
    for (const inline of child.children) {
      if (inline.type === "break" && !inline.position) {
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

export function parseMarkdownRoot(markdown: string): {
  root: Root;
  trailingNewlines: number;
} {
  const normalized = normalizeMarkdown(markdown);
  const trailingNewlines = countTrailingNewlines(normalized);
  const root = markdownParser.runSync(markdownParser.parse(normalized)) as Root;
  root.children = insertEmptyParagraphsForGaps(root.children) as Root["children"];
  root.children = splitBreakParagraphs(root.children) as Root["children"];

  return { root, trailingNewlines };
}
