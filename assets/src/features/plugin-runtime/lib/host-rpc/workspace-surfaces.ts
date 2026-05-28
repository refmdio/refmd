import {
  createPluginRendererSourceStore,
  type PluginHostRendererServices,
  type PluginRendererSlot,
} from "../renderer/host-renderer";
import type { PluginHostCommandEditor } from "./workspace-adapter";

export function rendererServicesFromSlots(
  slots: readonly PluginRendererSlot[] | undefined,
  sourceStore: ReturnType<typeof createPluginRendererSourceStore>,
): PluginHostRendererServices | undefined {
  if (!slots || slots.length === 0) return undefined;
  return { slots, sourceStore };
}

export function pluginEditorHasSelection(editor: unknown): boolean {
  if (!editor || typeof editor !== "object") return false;
  const candidate = editor as { somethingSelected?: unknown };
  return (
    typeof candidate.somethingSelected === "function" && candidate.somethingSelected() === true
  );
}

export function commandEditorPlaintextContext(
  editor: PluginHostCommandEditor,
  preferSelection: boolean,
) {
  const maxBytes = 16 * 1024;
  if (preferSelection && editor.somethingSelected()) {
    const from = editor.posToOffset(editor.getCursor("from"));
    const to = editor.posToOffset(editor.getCursor("to"));
    return {
      kind: "selection" as const,
      range: { anchor: from, head: to },
      plaintext: editor.getSelection().slice(0, maxBytes),
      maxBytes,
    };
  }

  const value = editor.getValue();
  const cursor = editor.posToOffset(editor.getCursor("head"));
  const from = Math.max(0, cursor - maxBytes / 2);
  const to = Math.min(value.length, from + maxBytes);
  return {
    kind: "context" as const,
    range: { anchor: from, head: to },
    plaintext: value.slice(from, to),
    maxBytes,
  };
}

export function pluginCommandDocumentId(view: unknown): string | null {
  if (!view || typeof view !== "object") return null;
  const candidate = view as { id?: unknown };
  return typeof candidate.id === "string" && candidate.id.length > 0 ? candidate.id : null;
}
