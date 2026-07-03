import { describe, expect, it } from "vitest";
import * as Y from "yjs";
import { prosemirrorToYXmlFragment } from "y-prosemirror";
import { markdownToProseMirrorDoc } from "./markdown-from";
import { ensureYDocMarkdownText, readYDocMarkdownPreview } from "./preview-text";
import { markdownSchema } from "./schema";

function legacyProseMirrorOnlyDoc(markdown: string): Y.Doc {
  const yDoc = new Y.Doc();
  const doc = markdownToProseMirrorDoc(markdown, markdownSchema);
  prosemirrorToYXmlFragment(doc, yDoc.getXmlFragment("prosemirror"));
  return yDoc;
}

describe("readYDocMarkdownPreview", () => {
  it("reads legacy ProseMirror XML when canonical Markdown text is absent", () => {
    const yDoc = legacyProseMirrorOnlyDoc("# Legacy heading\n\nLegacy body");

    expect(yDoc.getText("content").toString()).toBe("");
    expect(readYDocMarkdownPreview(yDoc)).toContain("Legacy body");
  });

  it("seeds canonical Markdown text from legacy ProseMirror XML", () => {
    const yDoc = legacyProseMirrorOnlyDoc("# Legacy heading\n\nLegacy body");
    const yText = ensureYDocMarkdownText(yDoc);

    expect(yText.toString()).toContain("Legacy heading");
    expect(yText.toString()).toContain("Legacy body");
    expect(ensureYDocMarkdownText(yDoc)).toBe(yText);
  });
});
