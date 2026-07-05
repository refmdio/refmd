import { TextSelection } from "prosemirror-state";
import type { EditorView } from "prosemirror-view";
import { isBlankProseMirrorDocument } from "./blank-document";

export const WYSIWYG_EDITOR_LABEL = "WYSIWYG markdown editor";
export const BLANK_WYSIWYG_EDITOR_LABEL = "Blank WYSIWYG markdown editor";

interface WysiwygReadinessOptions {
  emptyGuideId: string;
  readOnly?: boolean;
}

export function syncWysiwygEditorAccessibility(
  editorView: EditorView,
  options: WysiwygReadinessOptions,
): void {
  const isEditableBlank = !options.readOnly && isBlankProseMirrorDocument(editorView.state.doc);
  if (isEditableBlank) {
    editorView.dom.setAttribute("aria-label", BLANK_WYSIWYG_EDITOR_LABEL);
    editorView.dom.setAttribute("aria-describedby", options.emptyGuideId);
    editorView.dom.setAttribute("data-refmd-wysiwyg-blank-editor", "true");
    return;
  }

  editorView.dom.setAttribute("aria-label", WYSIWYG_EDITOR_LABEL);
  editorView.dom.removeAttribute("aria-describedby");
  editorView.dom.removeAttribute("data-refmd-wysiwyg-blank-editor");
}

export function focusBlankWysiwygEditor(
  editorView: EditorView,
  options: Pick<WysiwygReadinessOptions, "readOnly">,
): void {
  if (options.readOnly || !isBlankProseMirrorDocument(editorView.state.doc)) return;
  const doc = editorView.state.doc;
  if (!doc.firstChild) return;

  try {
    const cursorPosition = 1;
    if (!editorView.state.selection.empty || editorView.state.selection.from !== cursorPosition) {
      editorView.dispatch(
        editorView.state.tr
          .setSelection(TextSelection.create(doc, cursorPosition))
          .scrollIntoView(),
      );
    }
  } catch {
    // The collab document may briefly be between schema states during mount.
  }

  editorView.focus();
}
