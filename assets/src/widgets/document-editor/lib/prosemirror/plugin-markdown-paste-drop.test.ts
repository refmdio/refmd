import { afterEach, describe, expect, it, vi } from "vitest";
import { Slice } from "prosemirror-model";
import { EditorState } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { proseMirrorDocToMarkdown } from "./markdown-to";
import { markdownPasteDropPlugin } from "./plugin-markdown-paste-drop";
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

function createView(): EditorView {
  const view = new EditorView(createContainer(), {
    state: EditorState.create({
      doc: markdownSchema.node("doc", null, [markdownSchema.nodes.paragraph.create()]),
      plugins: [markdownPasteDropPlugin(markdownSchema)],
    }),
  });
  cleanupFns.push(() => view.destroy());
  return view;
}

function dataTransfer(text: string, files: File[] = []): DataTransfer {
  return {
    files,
    getData: (type: string) => (type === "text/markdown" || type === "text/plain" ? text : ""),
  } as unknown as DataTransfer;
}

function clipboardEvent(text: string): ClipboardEvent {
  const event = new Event("paste", { bubbles: true, cancelable: true }) as ClipboardEvent;
  Object.defineProperty(event, "clipboardData", {
    value: dataTransfer(text),
  });
  return event;
}

function dropEvent(text: string, files: File[] = []): DragEvent {
  const event = new Event("drop", { bubbles: true, cancelable: true }) as DragEvent;
  Object.defineProperties(event, {
    clientX: { value: 0 },
    clientY: { value: 0 },
    dataTransfer: { value: dataTransfer(text, files) },
  });
  return event;
}

function paste(view: EditorView, text: string): boolean {
  const event = clipboardEvent(text);
  let handled = false;
  view.someProp("handlePaste", (handler) => {
    if (handled) return true;
    handled = handler(view, event, Slice.empty) === true;
    return handled;
  });
  return handled;
}

function drop(view: EditorView, text: string, files: File[] = []): boolean {
  const event = dropEvent(text, files);
  vi.spyOn(view, "posAtCoords").mockReturnValue({ pos: 1, inside: -1 });
  let handled = false;
  view.someProp("handleDrop", (handler) => {
    if (handled) return true;
    handled = handler(view, event, Slice.empty, false) === true;
    return handled;
  });
  return handled;
}

function hasCheckedTaskItem(view: EditorView): boolean {
  let found = false;
  view.state.doc.descendants((node) => {
    if (node.type === markdownSchema.nodes.list_item && node.attrs.checked === true) {
      found = true;
      return false;
    }
    return true;
  });
  return found;
}

function hasTable(view: EditorView): boolean {
  let found = false;
  view.state.doc.descendants((node) => {
    if (node.type === markdownSchema.nodes.table) {
      found = true;
      return false;
    }
    return true;
  });
  return found;
}

describe("markdownPasteDropPlugin", () => {
  it("normalizes pasted Markdown blocks through the ProseMirror markdown parser", () => {
    const view = createView();

    expect(
      paste(
        view,
        [
          "# Title",
          "",
          "- [x] Done",
          "",
          "| Name | Status |",
          "| --- | --- |",
          "| RefMD | Active |",
        ].join("\n"),
      ),
    ).toBe(true);

    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.heading);
    expect(hasCheckedTaskItem(view)).toBe(true);
    expect(hasTable(view)).toBe(true);
  });

  it("keeps single-paragraph Markdown as inline content at the selection", () => {
    const view = createView();

    expect(paste(view, "**Bold** text")).toBe(true);

    expect(proseMirrorDocToMarkdown(view.state.doc)).toBe("**Bold** text");
  });

  it("normalizes dropped Markdown text unless the drop contains files", () => {
    const view = createView();

    expect(drop(view, "```bash\npnpm test\n```")).toBe(true);
    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.code_block);
    expect(proseMirrorDocToMarkdown(view.state.doc)).toBe("```bash\npnpm test\n```");

    const fileView = createView();
    expect(drop(fileView, "# Ignored", [new File(["x"], "x.txt")])).toBe(false);
    expect(proseMirrorDocToMarkdown(fileView.state.doc)).toBe("");
  });
});
