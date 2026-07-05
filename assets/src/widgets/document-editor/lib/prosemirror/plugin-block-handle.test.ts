import { afterEach, describe, expect, it, vi } from "vitest";
import { EditorState, TextSelection } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { blockHandlePlugin } from "./plugin-block-handle";
import { markdownSchema } from "./schema";

const cleanupFns: (() => void)[] = [];

afterEach(() => {
  vi.useRealTimers();
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
});

function createContainer(): HTMLElement {
  const container = document.createElement("div");
  document.body.append(container);
  cleanupFns.push(() => container.remove());
  return container;
}

function paragraph(text: string) {
  return markdownSchema.nodes.paragraph.create(null, markdownSchema.text(text));
}

function createView() {
  const container = createContainer();
  const doc = markdownSchema.node("doc", null, [paragraph("First"), paragraph("Second")]);
  const view = new EditorView(container, {
    state: EditorState.create({
      doc,
      plugins: [blockHandlePlugin()],
    }),
  });
  cleanupFns.push(() => view.destroy());
  return { container, view };
}

describe("block handle ProseMirror plugin", () => {
  it("shows the handle for the focused selection block", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector(".pm-block-handle");
    expect(handle?.classList.contains("visible")).toBe(true);
  });

  it("inserts a paragraph below the active block from the add button click path", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const addButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-add");
    expect(addButton).not.toBeNull();
    addButton?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));

    expect(view.state.doc.childCount).toBe(3);
    expect(view.state.doc.child(0).textContent).toBe("First");
    expect(view.state.doc.child(1).textContent).toBe("");
    expect(view.state.doc.child(2).textContent).toBe("Second");
  });

  it("keeps the handle touchable when the pointer moves from the editor to the handle", () => {
    vi.useFakeTimers();
    const { container, view } = createView();

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const addButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-add");
    expect(handle).not.toBeNull();
    expect(addButton).not.toBeNull();
    handle?.classList.add("visible");

    view.dom.dispatchEvent(
      new MouseEvent("mouseleave", {
        bubbles: false,
        cancelable: true,
        relatedTarget: addButton,
      }),
    );
    vi.advanceTimersByTime(200);

    expect(handle?.classList.contains("visible")).toBe(true);
  });
});
