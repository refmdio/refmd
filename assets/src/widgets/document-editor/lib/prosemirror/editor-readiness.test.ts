import { afterEach, describe, expect, it } from "vitest";
import { EditorState } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import {
  BLANK_WYSIWYG_EDITOR_LABEL,
  focusBlankWysiwygEditor,
  syncWysiwygEditorAccessibility,
  WYSIWYG_EDITOR_LABEL,
} from "./editor-readiness";
import { markdownSchema } from "./schema";

const cleanupFns: (() => void)[] = [];

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
  document.body.replaceChildren();
});

function createView(markdownText = ""): EditorView {
  const container = document.createElement("div");
  document.body.append(container);
  const paragraph =
    markdownText.length > 0
      ? markdownSchema.nodes.paragraph.create(null, markdownSchema.text(markdownText))
      : markdownSchema.nodes.paragraph.create();
  const view = new EditorView(container, {
    state: EditorState.create({
      doc: markdownSchema.node("doc", null, [paragraph]),
    }),
  });
  cleanupFns.push(
    () => view.destroy(),
    () => container.remove(),
  );
  return view;
}

describe("WYSIWYG editor readiness", () => {
  it("labels an empty editable document with its blank guide", () => {
    const view = createView();

    syncWysiwygEditorAccessibility(view, {
      emptyGuideId: "empty-guide",
      readOnly: false,
    });

    expect(view.dom.getAttribute("aria-label")).toBe(BLANK_WYSIWYG_EDITOR_LABEL);
    expect(view.dom.getAttribute("aria-describedby")).toBe("empty-guide");
    expect(view.dom.dataset.refmdWysiwygBlankEditor).toBe("true");
  });

  it("focuses an empty editable document at the first text position", () => {
    const view = createView();

    focusBlankWysiwygEditor(view, { readOnly: false });

    expect(document.activeElement).toBe(view.dom);
    expect(view.state.selection.empty).toBe(true);
    expect(view.state.selection.from).toBe(1);
  });

  it("uses the regular editor label for non-empty or read-only documents", () => {
    const nonEmptyView = createView("Body");
    syncWysiwygEditorAccessibility(nonEmptyView, {
      emptyGuideId: "empty-guide",
      readOnly: false,
    });

    expect(nonEmptyView.dom.getAttribute("aria-label")).toBe(WYSIWYG_EDITOR_LABEL);
    expect(nonEmptyView.dom.hasAttribute("aria-describedby")).toBe(false);
    expect(nonEmptyView.dom.hasAttribute("data-refmd-wysiwyg-blank-editor")).toBe(false);

    const readOnlyBlankView = createView();
    syncWysiwygEditorAccessibility(readOnlyBlankView, {
      emptyGuideId: "empty-guide",
      readOnly: true,
    });

    expect(readOnlyBlankView.dom.getAttribute("aria-label")).toBe(WYSIWYG_EDITOR_LABEL);
    expect(readOnlyBlankView.dom.hasAttribute("aria-describedby")).toBe(false);
    expect(readOnlyBlankView.dom.hasAttribute("data-refmd-wysiwyg-blank-editor")).toBe(false);
  });
});
