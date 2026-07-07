import { afterEach, describe, expect, it } from "vite-plus/test";
import { EditorState, TextSelection } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { markdownSchema } from "./schema";
import { taskListPlugin } from "./plugin-task-list";

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

describe("task list ProseMirror plugin", () => {
  it("toggles task item state through the rendered checkbox", () => {
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.bullet_list.create(null, [
            markdownSchema.nodes.list_item.create({ checked: false }, [
              markdownSchema.nodes.paragraph.create(null, [markdownSchema.text("Todo")]),
            ]),
          ]),
        ]),
        plugins: [taskListPlugin()],
      }),
    });
    cleanupFns.push(() => view.destroy());

    const checkbox = container.querySelector<HTMLInputElement>('input[type="checkbox"]');
    expect(checkbox).toBeInstanceOf(HTMLInputElement);

    checkbox?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));

    expect(view.state.doc.firstChild?.firstChild?.attrs.checked).toBe(true);
  });

  it("toggles the selected task item with Mod-Enter", () => {
    const view = new EditorView(createContainer(), {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.bullet_list.create(null, [
            markdownSchema.nodes.list_item.create({ checked: false }, [
              markdownSchema.nodes.paragraph.create(null, [markdownSchema.text("Todo")]),
            ]),
          ]),
        ]),
        plugins: [taskListPlugin()],
      }),
    });
    cleanupFns.push(() => view.destroy());

    setSelectionInText(view, "Todo");

    expect(press(view, "Enter", { ctrlKey: true })).toBe(true);
    expect(view.state.doc.firstChild?.firstChild?.attrs.checked).toBe(true);

    expect(press(view, "Enter", { metaKey: true })).toBe(true);
    expect(view.state.doc.firstChild?.firstChild?.attrs.checked).toBe(false);
  });
});
