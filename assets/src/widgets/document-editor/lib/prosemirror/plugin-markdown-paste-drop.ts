import type { Schema } from "prosemirror-model";
import { Slice } from "prosemirror-model";
import { TextSelection, Plugin } from "prosemirror-state";
import { markdownToProseMirrorDoc } from "./markdown-from";

function textFromClipboard(event: ClipboardEvent): string {
  return (
    event.clipboardData?.getData("text/markdown") ||
    event.clipboardData?.getData("text/plain") ||
    ""
  );
}

function textFromDrop(event: DragEvent): string {
  const transfer = event.dataTransfer;
  if (!transfer || transfer.files.length > 0) return "";
  return transfer.getData("text/markdown") || transfer.getData("text/plain") || "";
}

function sliceFromMarkdownText(text: string, schema: Schema): Slice | null {
  if (text.length === 0) return null;

  const doc = markdownToProseMirrorDoc(text, schema);
  if (doc.childCount === 1 && doc.firstChild?.type === schema.nodes.paragraph) {
    return new Slice(doc.firstChild.content, 0, 0);
  }

  return new Slice(doc.content, 0, 0);
}

export function markdownPasteDropPlugin(schema: Schema): Plugin {
  return new Plugin({
    props: {
      handlePaste(view, event) {
        const slice = sliceFromMarkdownText(textFromClipboard(event), schema);
        if (!slice) return false;

        event.preventDefault();
        view.dispatch(view.state.tr.replaceSelection(slice).scrollIntoView());
        return true;
      },
      handleDrop(view, event, _slice, moved) {
        if (moved) return false;

        const slice = sliceFromMarkdownText(textFromDrop(event), schema);
        if (!slice) return false;

        event.preventDefault();
        const position = view.posAtCoords({ left: event.clientX, top: event.clientY });
        let tr = view.state.tr;
        if (position) {
          tr = tr.setSelection(TextSelection.near(tr.doc.resolve(position.pos)));
        }
        view.dispatch(tr.replaceSelection(slice).scrollIntoView());
        return true;
      },
    },
  });
}
