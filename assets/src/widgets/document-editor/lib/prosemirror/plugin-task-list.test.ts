import { afterEach, describe, expect, it } from "vitest";
import { EditorState } from "prosemirror-state";
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
});
