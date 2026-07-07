import { afterEach, describe, expect, it, vi } from "vitest";
import { EditorState, TextSelection } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import {
  blockHandlePlugin,
  type BlockHandlePluginViewFactory,
  type BlockHandleViewState,
} from "./plugin-block-handle";
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

function applyBlockHandleState(handle: HTMLElement, state: BlockHandleViewState) {
  handle.classList.toggle("visible", state.visible);
  handle.classList.toggle("dragging", state.dragging);
  handle.style.left = `${state.left}px`;
  handle.style.top = `${state.top}px`;
  handle.style.height = `${state.height}px`;
}

const createTestBlockHandleView: BlockHandlePluginViewFactory = (view, controller) => {
  const handle = document.createElement("div");
  handle.className = "pm-block-handle";
  handle.dataset.refmdEditorChrome = "block-handle";

  const addButton = document.createElement("button");
  addButton.type = "button";
  addButton.className = "pm-block-handle-add";
  addButton.setAttribute("aria-label", "Open block menu below");

  const dragButton = document.createElement("button");
  dragButton.type = "button";
  dragButton.className = "pm-block-handle-drag";
  dragButton.draggable = true;
  dragButton.setAttribute("aria-label", "Drag to move block");

  const bridge = document.createElement("span");
  bridge.className = "pm-block-handle-bridge";
  bridge.setAttribute("aria-hidden", "true");

  handle.append(addButton, dragButton, bridge);
  view.dom.parentElement?.append(handle);

  const abort = new AbortController();
  const eventOptions = { signal: abort.signal };
  const unsubscribe = controller.subscribe((state) => applyBlockHandleState(handle, state));

  controller.attachHandleElement(handle);
  addButton.addEventListener("mousedown", (event) => event.preventDefault(), eventOptions);
  addButton.addEventListener("click", (event) => controller.openBlockMenu(event), eventOptions);
  dragButton.addEventListener(
    "dragstart",
    (event) => controller.beginNativeDrag(event),
    eventOptions,
  );
  dragButton.addEventListener("dragend", () => controller.finishDrag(), eventOptions);
  dragButton.addEventListener(
    "pointerdown",
    (event) => controller.beginPointerDrag(event),
    eventOptions,
  );
  dragButton.addEventListener(
    "mousedown",
    (event) => controller.beginMouseDrag(event),
    eventOptions,
  );
  handle.addEventListener("mouseenter", () => controller.setMenuFrozen(true), eventOptions);
  handle.addEventListener("mouseleave", () => controller.setMenuFrozen(false), eventOptions);
  handle.addEventListener(
    "focusin",
    () => {
      controller.setMenuFrozen(true);
      controller.refreshVisibleHandle();
    },
    eventOptions,
  );
  handle.addEventListener(
    "focusout",
    () => queueMicrotask(() => controller.setMenuFrozen(false)),
    eventOptions,
  );

  return {
    destroy() {
      abort.abort();
      unsubscribe();
      controller.attachHandleElement(null);
      handle.remove();
    },
  };
};

function createBlockHandlePlugin(
  options: {
    openBlockMenuBelow?: (view: EditorView, blockPos: number) => boolean;
  } = {},
) {
  return blockHandlePlugin({
    createHandleView: createTestBlockHandleView,
    ...options,
  });
}

function stubEditorChildRects(view: EditorView, rowHeight = 24) {
  Array.from(view.dom.children).forEach((child, index) => {
    if (!(child instanceof HTMLElement)) return;
    child.getBoundingClientRect = () => new DOMRect(96, 20 + index * rowHeight, 320, 20);
  });
}

function createView(
  plugin = createBlockHandlePlugin(),
  doc = markdownSchema.node("doc", null, [paragraph("First"), paragraph("Second")]),
) {
  const container = createContainer();
  Object.defineProperty(container, "clientWidth", {
    configurable: true,
    value: 640,
  });
  container.getBoundingClientRect = () => new DOMRect(0, 0, 640, 480);

  const view = new EditorView(container, {
    state: EditorState.create({
      doc,
      plugins: [plugin],
    }),
  });
  view.dom.getBoundingClientRect = () => new DOMRect(80, 20, 520, 240);
  view.coordsAtPos = () =>
    ({
      bottom: 40,
      left: 96,
      right: 97,
      top: 20,
    }) as ReturnType<EditorView["coordsAtPos"]>;
  stubEditorChildRects(view);
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

  it("opens the block menu from the add button when the editor provides one", () => {
    const openBlockMenuBelow = vi.fn(() => true);
    const { container, view } = createView(createBlockHandlePlugin({ openBlockMenuBelow }));

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const addButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-add");
    expect(addButton).not.toBeNull();
    addButton?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));

    expect(openBlockMenuBelow).toHaveBeenCalledOnce();
    expect(view.state.doc.childCount).toBe(2);
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

  it("keeps the handle visible when the pointer enters the bridge between text and controls", () => {
    vi.useFakeTimers();
    const { container, view } = createView();

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const bridge = container.querySelector<HTMLElement>(".pm-block-handle-bridge");
    expect(handle).not.toBeNull();
    expect(bridge).not.toBeNull();
    handle?.classList.add("visible");

    view.dom.dispatchEvent(
      new MouseEvent("mouseleave", {
        bubbles: false,
        cancelable: true,
        relatedTarget: bridge,
      }),
    );
    vi.advanceTimersByTime(200);

    expect(handle?.classList.contains("visible")).toBe(true);
  });

  it("locks the handle while native block dragging is active", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(handle).not.toBeNull();
    expect(dragButton).not.toBeNull();
    expect(handle?.classList.contains("visible")).toBe(true);

    const dataTransfer = {
      effectAllowed: "none",
      setData: vi.fn(),
      setDragImage: vi.fn(),
    };
    const dragStart = new Event("dragstart", { bubbles: true, cancelable: true });
    Object.defineProperty(dragStart, "dataTransfer", { value: dataTransfer });
    dragButton?.dispatchEvent(dragStart);

    expect(handle?.classList.contains("visible")).toBe(true);
    expect(handle?.classList.contains("dragging")).toBe(true);
    expect(dataTransfer.setData).toHaveBeenCalledWith("text/plain", "First");
    expect(dataTransfer.setDragImage).toHaveBeenCalled();

    dragButton?.dispatchEvent(new Event("dragend", { bubbles: true, cancelable: true }));

    expect(handle?.classList.contains("dragging")).toBe(false);
    expect(document.querySelector(".pm-block-drag-preview")).toBeNull();
  });

  it("restores the global cursor when the editor is destroyed during pointer drag", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(dragButton).not.toBeNull();

    document.body.style.cursor = "crosshair";
    dragButton?.dispatchEvent(
      new PointerEvent("pointerdown", {
        bubbles: true,
        button: 0,
        clientX: 92,
        clientY: 30,
        pointerId: 7,
      }),
    );
    expect(document.body.style.cursor).toBe("grabbing");

    view.destroy();
    expect(document.body.style.cursor).toBe("crosshair");
    document.body.style.cursor = "";
  });

  it("does not clear pointer drag feedback from native mouse drag events", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(handle).not.toBeNull();
    expect(dragButton).not.toBeNull();

    dragButton?.dispatchEvent(
      new PointerEvent("pointerdown", {
        bubbles: true,
        button: 0,
        clientX: 92,
        clientY: 30,
        pointerId: 11,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    view.dom.dispatchEvent(new Event("dragend", { bubbles: true, cancelable: true }));
    expect(handle?.classList.contains("dragging")).toBe(true);

    view.dom.dispatchEvent(new Event("drop", { bubbles: true, cancelable: true }));
    expect(handle?.classList.contains("dragging")).toBe(true);

    document.dispatchEvent(
      new PointerEvent("pointercancel", {
        bubbles: true,
        clientX: 92,
        clientY: 30,
        pointerId: 11,
        pointerType: "mouse",
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    document.dispatchEvent(
      new PointerEvent("pointercancel", {
        bubbles: true,
        clientX: 92,
        clientY: 30,
        pointerId: 11,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    document.dispatchEvent(
      new PointerEvent("pointerup", {
        bubbles: true,
        clientX: 92,
        clientY: 30,
        pointerId: 11,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    document.dispatchEvent(
      new MouseEvent("mouseup", {
        bubbles: true,
        clientX: 92,
        clientY: 30,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(false);
  });

  it("starts drag from the mouse fallback when pointerdown is not delivered", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(handle).not.toBeNull();
    expect(dragButton).not.toBeNull();

    dragButton?.dispatchEvent(
      new MouseEvent("mousedown", {
        bubbles: true,
        button: 0,
        clientX: 92,
        clientY: 30,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    document.dispatchEvent(
      new MouseEvent("mousemove", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
      }),
    );
    expect(document.querySelector(".refmd-wysiwyg-dropcursor")).not.toBeNull();

    document.dispatchEvent(
      new MouseEvent("mouseup", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
      }),
    );

    expect(handle?.classList.contains("dragging")).toBe(false);
    expect(document.querySelector(".refmd-wysiwyg-dropcursor")).toBeNull();
  });

  it("keeps pointer drag active when an unrelated document change preserves the source block", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(handle).not.toBeNull();
    expect(dragButton).not.toBeNull();

    document.body.style.cursor = "crosshair";
    dragButton?.dispatchEvent(
      new PointerEvent("pointerdown", {
        bubbles: true,
        button: 0,
        clientX: 92,
        clientY: 30,
        pointerId: 9,
      }),
    );
    expect(document.body.style.cursor).toBe("grabbing");

    document.dispatchEvent(
      new PointerEvent("pointermove", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
        pointerId: 9,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);
    expect(document.querySelector(".refmd-wysiwyg-dropcursor")).not.toBeNull();

    view.dispatch(view.state.tr.insert(view.state.doc.content.size, paragraph("Remote")));
    stubEditorChildRects(view);

    expect(handle?.classList.contains("dragging")).toBe(true);
    expect(document.querySelector(".refmd-wysiwyg-dropcursor")).not.toBeNull();
    expect(document.body.style.cursor).toBe("grabbing");

    expect(() =>
      document.dispatchEvent(
        new PointerEvent("pointerup", {
          bubbles: true,
          clientX: 132,
          clientY: 140,
          pointerId: 9,
        }),
      ),
    ).not.toThrow();
    expect(handle?.classList.contains("dragging")).toBe(true);

    document.dispatchEvent(
      new MouseEvent("mouseup", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
      }),
    );

    expect(
      Array.from(
        { length: view.state.doc.childCount },
        (_, index) => view.state.doc.child(index).textContent,
      ),
    ).toEqual(["Second", "Remote", "First"]);
    expect(handle?.classList.contains("dragging")).toBe(false);
    expect(document.querySelector(".refmd-wysiwyg-dropcursor")).toBeNull();
    expect(document.body.style.cursor).toBe("crosshair");
    document.body.style.cursor = "";
  });

  it("keeps drag active through a transient empty sync document and drops after restore", () => {
    const doc = markdownSchema.node("doc", null, [
      paragraph("First"),
      paragraph("Second"),
      paragraph("Third"),
    ]);
    const { container, view } = createView(createBlockHandlePlugin(), doc);

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(handle).not.toBeNull();
    expect(dragButton).not.toBeNull();

    dragButton?.dispatchEvent(
      new MouseEvent("mousedown", {
        bubbles: true,
        button: 0,
        clientX: 92,
        clientY: 30,
      }),
    );
    document.dispatchEvent(
      new MouseEvent("mousemove", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    view.dispatch(
      view.state.tr.replaceWith(
        0,
        view.state.doc.content.size,
        markdownSchema.nodes.paragraph.create(),
      ),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    view.dispatch(
      view.state.tr.replaceWith(0, view.state.doc.content.size, [
        paragraph("First"),
        paragraph("Second"),
        paragraph("Third"),
      ]),
    );
    stubEditorChildRects(view);

    document.dispatchEvent(
      new MouseEvent("mouseup", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
      }),
    );

    expect(
      Array.from(
        { length: view.state.doc.childCount },
        (_, index) => view.state.doc.child(index).textContent,
      ),
    ).toEqual(["Second", "Third", "First"]);
    expect(handle?.classList.contains("dragging")).toBe(false);
  });

  it("cleans up drag when an empty sync document does not restore", () => {
    vi.useFakeTimers();
    const doc = markdownSchema.node("doc", null, [
      paragraph("First"),
      paragraph("Second"),
      paragraph("Third"),
    ]);
    const { container, view } = createView(createBlockHandlePlugin(), doc);

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(handle).not.toBeNull();
    expect(dragButton).not.toBeNull();

    document.body.style.cursor = "crosshair";
    dragButton?.dispatchEvent(
      new MouseEvent("mousedown", {
        bubbles: true,
        button: 0,
        clientX: 92,
        clientY: 30,
      }),
    );
    document.dispatchEvent(
      new MouseEvent("mousemove", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);
    expect(document.body.style.cursor).toBe("grabbing");

    view.dispatch(
      view.state.tr.replaceWith(
        0,
        view.state.doc.content.size,
        markdownSchema.nodes.paragraph.create(),
      ),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    vi.advanceTimersByTime(260);

    expect(handle?.classList.contains("dragging")).toBe(false);
    expect(document.querySelector(".refmd-wysiwyg-dropcursor")).toBeNull();
    expect(document.body.style.cursor).toBe("crosshair");
    document.body.style.cursor = "";
  });

  it("fails closed when the source block changes during pointer drag", () => {
    const { container, view } = createView();

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 1)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    const dragButton = container.querySelector<HTMLButtonElement>(".pm-block-handle-drag");
    expect(handle).not.toBeNull();
    expect(dragButton).not.toBeNull();

    document.body.style.cursor = "crosshair";
    dragButton?.dispatchEvent(
      new PointerEvent("pointerdown", {
        bubbles: true,
        button: 0,
        clientX: 92,
        clientY: 30,
        pointerId: 9,
      }),
    );
    document.dispatchEvent(
      new PointerEvent("pointermove", {
        bubbles: true,
        clientX: 132,
        clientY: 140,
        pointerId: 9,
      }),
    );
    expect(handle?.classList.contains("dragging")).toBe(true);

    view.dispatch(view.state.tr.insertText("!", 1, 1));

    expect(handle?.classList.contains("dragging")).toBe(false);
    expect(document.querySelector(".refmd-wysiwyg-dropcursor")).toBeNull();
    expect(document.body.style.cursor).toBe("crosshair");
    document.body.style.cursor = "";
  });

  it("does not expose a drag handle for unsupported nested list content", () => {
    const listItem = markdownSchema.nodes.list_item.create(null, paragraph("Nested"));
    const list = markdownSchema.nodes.bullet_list.create(null, listItem);
    const doc = markdownSchema.node("doc", null, [list, paragraph("After")]);
    const { container, view } = createView(createBlockHandlePlugin(), doc);

    view.dom.getBoundingClientRect = () => new DOMRect(80, 20, 520, 240);
    view.coordsAtPos = () =>
      ({
        bottom: 40,
        left: 116,
        right: 117,
        top: 20,
      }) as ReturnType<EditorView["coordsAtPos"]>;
    stubEditorChildRects(view, 36);

    view.focus();
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, 3)));

    const handle = container.querySelector<HTMLElement>(".pm-block-handle");
    expect(handle?.classList.contains("visible")).toBe(false);
  });
});
