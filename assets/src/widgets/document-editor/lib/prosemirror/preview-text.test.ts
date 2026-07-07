import { describe, expect, it } from "vite-plus/test";
import * as Y from "yjs";
import { ensureYDocMarkdownText, readYDocMarkdownPreview } from "./preview-text";

describe("readYDocMarkdownPreview", () => {
  it("reads canonical Markdown text", () => {
    const yDoc = new Y.Doc();
    yDoc.getText("content").insert(0, "# Heading\n\nBody");

    expect(readYDocMarkdownPreview(yDoc)).toBe("# Heading\n\nBody");

    yDoc.destroy();
  });

  it("does not bootstrap canonical text from ProseMirror XML", () => {
    const yDoc = new Y.Doc();
    yDoc.getXmlFragment("prosemirror").insert(0, [new Y.XmlElement("paragraph")]);
    const yText = ensureYDocMarkdownText(yDoc);

    expect(yText.toString()).toBe("");
    expect(readYDocMarkdownPreview(yDoc)).toBe("");
    expect(ensureYDocMarkdownText(yDoc)).toBe(yText);

    yDoc.destroy();
  });
});
