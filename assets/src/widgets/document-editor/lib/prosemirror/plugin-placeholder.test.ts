import { afterEach, describe, expect, it } from "vite-plus/test";
import { EditorState } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { placeholderPlugin } from "./plugin-placeholder";
import { markdownSchema } from "./schema";

const cleanupFns: (() => void)[] = [];

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
});

function createContainer(): HTMLElement {
  const container = document.createElement("div");
  document.body.append(container);
  cleanupFns.push(() => container.remove());
  return container;
}

describe("ProseMirror placeholder plugin", () => {
  it("shows blank-document guidance in an empty WYSIWYG document", () => {
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [markdownSchema.nodes.paragraph.create()]),
        plugins: [placeholderPlugin()],
      }),
    });
    cleanupFns.push(() => view.destroy());

    const emptyParagraph = container.querySelector<HTMLElement>(".is-doc-empty");
    expect(emptyParagraph).toBeInstanceOf(HTMLElement);
    expect(emptyParagraph?.dataset.placeholder).toBe("Start writing, or type / for blocks");
    expect(emptyParagraph?.dataset.placeholderDetail).toBe(
      "Add headings, tables, tasks, code, and more from the slash menu.",
    );
  });
});
