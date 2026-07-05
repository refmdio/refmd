import { describe, expect, test } from "vitest";
import { baseKeymap } from "prosemirror-commands";
import { EditorState, TextSelection } from "prosemirror-state";
import { markdownSchema } from "./schema";
import { markdownToProseMirrorDoc } from "./markdown-from";
import { proseMirrorDocToMarkdown } from "./markdown-to";

function roundTrip(markdown: string): string {
  return proseMirrorDocToMarkdown(markdownToProseMirrorDoc(markdown, markdownSchema));
}

function firstRowAlignments(markdown: string): unknown[] {
  const doc = markdownToProseMirrorDoc(markdown, markdownSchema);
  const table = doc.firstChild;
  const firstRow = table?.firstChild;
  const alignments: unknown[] = [];
  firstRow?.forEach((cell) => {
    alignments.push(cell.attrs.align);
  });
  return alignments;
}

describe("ProseMirror markdown trailing newlines", () => {
  test.each(["Body", "Body\n", "Body\n\n", "Body\n\n\n", "\n", "\n\n"])(
    "preserves %j",
    (markdown) => {
      expect(roundTrip(markdown)).toBe(markdown);
    },
  );

  test("preserves trailing empty paragraphs after body gaps", () => {
    expect(roundTrip("First\n\nSecond\n\n")).toBe("First\n\nSecond\n\n");
  });

  test("serializes Enter on a trailing empty paragraph as an additional newline", () => {
    const doc = markdownToProseMirrorDoc("# uuu\naaa\n", markdownSchema);
    const state = EditorState.create({
      schema: markdownSchema,
      doc,
      selection: TextSelection.create(doc, doc.content.size - 1),
    });

    let nextState: EditorState | null = null;
    const handled = baseKeymap.Enter?.(state, (transaction) => {
      nextState = state.apply(transaction);
    });

    expect(handled).toBe(true);
    expect(nextState).not.toBeNull();
    expect(proseMirrorDocToMarkdown(nextState!.doc)).toBe("# uuu\naaa\n\n");
  });

  test("does not drop WYSIWYG hard breaks from canonical Markdown", () => {
    const doc = markdownSchema.node("doc", null, [
      markdownSchema.nodes.paragraph.create(null, [
        markdownSchema.text("alpha"),
        markdownSchema.nodes.hard_break.create(),
        markdownSchema.text("beta"),
      ]),
    ]);

    expect(proseMirrorDocToMarkdown(doc)).toBe("alpha\\\nbeta");
  });

  test("preserves imported Markdown hard breaks", () => {
    expect(roundTrip("alpha\\\nbeta")).toBe("alpha\\\nbeta");
  });

  test("preserves GFM task list state", () => {
    expect(roundTrip("- [ ] Todo\n- [x] Done")).toBe("- [ ] Todo\n- [x] Done");
  });

  test("preserves GFM tables as editable table nodes", () => {
    expect(roundTrip("| Name | Status |\n| - | - |\n| RefMD | Active |")).toBe(
      "| Name  | Status |\n| ----- | ------ |\n| RefMD | Active |",
    );
  });

  test("preserves GFM table alignment semantically", () => {
    const markdown = "| Left | Center | Right |\n| :--- | :---: | ---: |\n| a | b | c |";
    const exported = roundTrip(markdown);

    expect(firstRowAlignments(exported)).toEqual(["left", "center", "right"]);
  });
});
