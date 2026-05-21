import { describe, expect, test } from "vitest";
import { baseKeymap } from "prosemirror-commands";
import { EditorState, TextSelection } from "prosemirror-state";
import { markdownSchema } from "./schema";
import { markdownToProseMirrorDoc } from "./markdown-from";
import { proseMirrorDocToMarkdown } from "./markdown-to";

function roundTrip(markdown: string): string {
  return proseMirrorDocToMarkdown(markdownToProseMirrorDoc(markdown, markdownSchema));
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
});
