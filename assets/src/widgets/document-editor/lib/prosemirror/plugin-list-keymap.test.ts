import { afterEach, describe, expect, it } from "vite-plus/test";
import { EditorState, TextSelection } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { proseMirrorDocToMarkdown } from "./markdown-to";
import { buildCollabPlugins } from "./plugin-base";
import { markdownSchema } from "./schema";

const cleanupFns: (() => void)[] = [];

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
  document.body.replaceChildren();
});

function createContainer(): HTMLElement {
  const container = document.createElement("div");
  document.body.append(container);
  cleanupFns.push(() => container.remove());
  return container;
}

function press(view: EditorView, key: string, init: KeyboardEventInit = {}): boolean {
  const event = new KeyboardEvent("keydown", {
    bubbles: true,
    cancelable: true,
    key,
    ...init,
  });
  let handled = false;
  view.someProp("handleKeyDown", (handler) => {
    if (handled) return true;
    handled = handler(view, event) === true;
    return handled;
  });
  return handled;
}

function setSelectionInText(view: EditorView, text: string): void {
  let selectionPos: number | null = null;
  view.state.doc.descendants((node, pos) => {
    if (!node.isText || node.text !== text) return true;
    selectionPos = pos + text.length;
    return false;
  });
  expect(selectionPos).not.toBeNull();
  view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, selectionPos!)));
}

function createView(doc: EditorState["doc"]): EditorView {
  const view = new EditorView(createContainer(), {
    state: EditorState.create({
      doc,
      plugins: buildCollabPlugins(markdownSchema),
    }),
  });
  cleanupFns.push(() => view.destroy());
  return view;
}

describe("ProseMirror list keymap", () => {
  it("indents and outdents list items with Tab and Shift-Tab", () => {
    const view = createView(
      markdownSchema.node("doc", null, [
        markdownSchema.nodes.bullet_list.create(null, [
          markdownSchema.nodes.list_item.create(null, [
            markdownSchema.nodes.paragraph.create(null, [markdownSchema.text("One")]),
          ]),
          markdownSchema.nodes.list_item.create(null, [
            markdownSchema.nodes.paragraph.create(null, [markdownSchema.text("Two")]),
          ]),
        ]),
      ]),
    );
    setSelectionInText(view, "Two");

    expect(press(view, "Tab")).toBe(true);
    expect(proseMirrorDocToMarkdown(view.state.doc)).toBe("- One\n  - Two");

    setSelectionInText(view, "Two");
    expect(press(view, "Tab", { shiftKey: true })).toBe(true);
    expect(proseMirrorDocToMarkdown(view.state.doc)).toBe("- One\n- Two");
  });

  it("keeps table-cell Tab navigation before list indentation fallback", () => {
    const view = createView(
      markdownSchema.node("doc", null, [
        markdownSchema.nodes.table.create(null, [
          markdownSchema.nodes.table_row.create(null, [
            markdownSchema.nodes.table_cell.create(null, [
              markdownSchema.nodes.paragraph.create(null, [markdownSchema.text("A")]),
            ]),
            markdownSchema.nodes.table_cell.create(null, [
              markdownSchema.nodes.paragraph.create(null, [markdownSchema.text("B")]),
            ]),
          ]),
        ]),
      ]),
    );
    setSelectionInText(view, "A");

    expect(press(view, "Tab")).toBe(true);
    expect(view.state.selection.$from.parent.textContent).toBe("B");
  });
});
