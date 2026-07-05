import { afterEach, describe, expect, it } from "vitest";
import { EditorState, TextSelection } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { proseMirrorDocToMarkdown } from "../../lib/prosemirror/markdown-to";
import { markdownSchema } from "../../lib/prosemirror/schema";
import {
  isFloatingToolbarActionActive,
  runFloatingToolbarAction,
} from "./floating-toolbar-commands";

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

function createView(text = "Selection"): EditorView {
  const view = new EditorView(createContainer(), {
    state: EditorState.create({
      doc: markdownSchema.node("doc", null, [
        markdownSchema.nodes.paragraph.create(null, [markdownSchema.text(text)]),
      ]),
    }),
  });
  cleanupFns.push(() => view.destroy());
  view.dispatch(
    view.state.tr.setSelection(TextSelection.create(view.state.doc, 1, 1 + text.length)),
  );
  return view;
}

describe("floating toolbar commands", () => {
  it("applies schema-backed inline marks including links", () => {
    const view = createView("Link me");

    expect(runFloatingToolbarAction(view, "strong")).toBe(true);
    expect(runFloatingToolbarAction(view, "link", { href: "https://example.com" })).toBe(true);

    expect(proseMirrorDocToMarkdown(view.state.doc)).toBe("[**Link me**](https://example.com)");
    expect(isFloatingToolbarActionActive(view.state, "link")).toBe(true);
  });

  it("transforms selected text into headings, paragraphs, and quotes", () => {
    const view = createView("Title");

    expect(runFloatingToolbarAction(view, "heading1")).toBe(true);
    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.heading);
    expect(view.state.doc.firstChild?.attrs.level).toBe(1);

    expect(runFloatingToolbarAction(view, "paragraph")).toBe(true);
    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.paragraph);

    expect(runFloatingToolbarAction(view, "blockquote")).toBe(true);
    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.blockquote);
  });

  it("wraps selected text in list and task-list blocks", () => {
    const bulletView = createView("Bullet");
    expect(runFloatingToolbarAction(bulletView, "bullet_list")).toBe(true);
    expect(bulletView.state.doc.firstChild?.type).toBe(markdownSchema.nodes.bullet_list);

    const orderedView = createView("Ordered");
    expect(runFloatingToolbarAction(orderedView, "ordered_list")).toBe(true);
    expect(orderedView.state.doc.firstChild?.type).toBe(markdownSchema.nodes.ordered_list);

    const taskView = createView("Todo");
    expect(runFloatingToolbarAction(taskView, "task_list")).toBe(true);
    expect(taskView.state.doc.firstChild?.type).toBe(markdownSchema.nodes.bullet_list);
    expect(taskView.state.doc.firstChild?.firstChild?.attrs.checked).toBe(false);
  });
});
