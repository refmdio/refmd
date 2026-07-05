import { describe, expect, it } from "vitest";
import { isBlankProseMirrorDocument } from "./blank-document";
import { markdownSchema } from "./schema";

describe("isBlankProseMirrorDocument", () => {
  it("treats a single empty textblock as blank", () => {
    const doc = markdownSchema.node("doc", null, [markdownSchema.nodes.paragraph.create()]);

    expect(isBlankProseMirrorDocument(doc)).toBe(true);
  });

  it("does not treat text content as blank", () => {
    const doc = markdownSchema.node("doc", null, [
      markdownSchema.nodes.paragraph.create(null, markdownSchema.text("hello")),
    ]);

    expect(isBlankProseMirrorDocument(doc)).toBe(false);
  });

  it("does not treat multiple empty blocks as blank", () => {
    const doc = markdownSchema.node("doc", null, [
      markdownSchema.nodes.paragraph.create(),
      markdownSchema.nodes.paragraph.create(),
    ]);

    expect(isBlankProseMirrorDocument(doc)).toBe(false);
  });

  it("does not treat an empty code block as blank", () => {
    const doc = markdownSchema.node("doc", null, [markdownSchema.nodes.code_block.create()]);

    expect(isBlankProseMirrorDocument(doc)).toBe(false);
  });
});
