import { describe, expect, test } from "vite-plus/test";
import type { Paragraph, RootContent } from "mdast";
import { parsePublicMarkdown } from "./PublicMarkdownView";

function paragraphAt(children: RootContent[], index: number): Paragraph {
  const child = children[index];
  expect(child?.type).toBe("paragraph");
  return child as Paragraph;
}

describe("parsePublicMarkdown", () => {
  test.each([
    ["Body", 1],
    ["Body\n", 2],
    ["Body\n\n", 3],
    ["Body\n\n\n", 4],
    ["\n", 2],
    ["\n\n", 3],
  ])("preserves WYSIWYG trailing breaks for %j", (markdown, expectedParagraphs) => {
    const root = parsePublicMarkdown(markdown);

    expect(root.children).toHaveLength(expectedParagraphs);
    expect(root.children.every((child) => child.type === "paragraph")).toBe(true);
  });

  test("keeps empty paragraphs for body gaps", () => {
    const root = parsePublicMarkdown("First\n\nSecond");

    expect(root.children).toHaveLength(3);
    expect(paragraphAt(root.children, 0).children).toHaveLength(1);
    expect(paragraphAt(root.children, 1).children).toHaveLength(0);
    expect(paragraphAt(root.children, 2).children).toHaveLength(1);
  });
});
