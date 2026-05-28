import type { Node as ProseMirrorNode } from "prosemirror-model";
import { Plugin, PluginKey } from "prosemirror-state";
import { Decoration, DecorationSet } from "prosemirror-view";
import {
  getDefaultPluginRendererSlotRegistry,
  type PluginRendererSlot,
} from "@/features/plugin-runtime";

const MAX_RENDERER_SOURCE_BYTES = 256 * 1024;
const INLINE_CODE_RENDERER_SLOT: PluginRendererSlot = { kind: "inline", type: "code" };
const SLOT_TYPE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const FORBIDDEN_SLOT_TYPES = new Set(["markdown", "md", "document", "full-document"]);
const pluginRendererSlotPluginKey = new PluginKey("pluginRendererSlots");

interface RendererSlotPluginOptions {
  documentId: string;
  workspaceId?: string | null;
}

export function pluginRendererSlotPlugin(options: RendererSlotPluginOptions): Plugin {
  let destroyed = false;

  return new Plugin({
    key: pluginRendererSlotPluginKey,
    view(editorView) {
      const unsubscribeRegistry = getDefaultPluginRendererSlotRegistry().subscribe(() => {
        queueMicrotask(() => {
          if (destroyed) return;
          editorView.dispatch(
            editorView.state.tr.setMeta(
              pluginRendererSlotPluginKey,
              getDefaultPluginRendererSlotRegistry().snapshotVersion(),
            ),
          );
        });
      });
      return {
        destroy() {
          destroyed = true;
          unsubscribeRegistry();
        },
      };
    },
    props: {
      decorations(state) {
        return rendererSlotDecorations(state.doc, options);
      },
    },
  });
}

function rendererSlotFromNode(node: ProseMirrorNode): PluginRendererSlot | null {
  const language = languageFromNode(node);
  if (!language || !rendererSlotTypeAllowed(language)) return null;
  return { kind: "block", type: language };
}

function rendererSlotDecorations(
  doc: ProseMirrorNode,
  options: RendererSlotPluginOptions,
): DecorationSet {
  return DecorationSet.create(doc, [
    ...blockRendererDecorations(doc, options),
    ...inlineRendererDecorations(doc, options),
  ]);
}

function blockRendererDecorations(
  doc: ProseMirrorNode,
  options: RendererSlotPluginOptions,
): Decoration[] {
  const registry = getDefaultPluginRendererSlotRegistry();
  const decorations: Decoration[] = [];

  doc.descendants((node, position) => {
    if (node.type.name !== "code_block") return;
    const slot = rendererSlotFromNode(node);
    if (!slot || !registry.hasSlot(slot, options.workspaceId)) return;
    const source = node.textContent;
    const blockId = `${options.documentId}:${position}`;
    decorations.push(
      Decoration.node(
        position,
        position + node.nodeSize,
        {
          class: "refmd-plugin-renderer-source-hidden",
          "aria-hidden": "true",
        },
        { key: `${blockId}:source:${slot.kind}:${slot.type}` },
      ),
      Decoration.widget(
        position + node.nodeSize,
        (view) => {
          const container = view.dom.ownerDocument.createElement("div");
          container.className = "refmd-plugin-renderer-slot refmd-plugin-renderer-block-slot";
          container.dataset.rendererKind = slot.kind;
          container.dataset.rendererType = slot.type;
          container.style.minHeight = "48px";
          const mounted = registry.mount({
            slot,
            workspaceId: options.workspaceId,
            documentId: options.documentId,
            blockId,
            source,
            maxBytes: MAX_RENDERER_SOURCE_BYTES,
            container,
            title: `${slot.type} renderer`,
          });
          if (mounted) {
            (container as HTMLElement & { __refmdDispose?: () => void }).__refmdDispose = () =>
              mounted.dispose();
          }
          return container;
        },
        {
          key: `${blockId}:renderer:${slot.kind}:${slot.type}:${source}`,
          side: 1,
          destroy(node) {
            (node as HTMLElement & { __refmdDispose?: () => void }).__refmdDispose?.();
          },
        },
      ),
    );
  });

  return decorations;
}

function inlineRendererDecorations(
  doc: ProseMirrorNode,
  options: RendererSlotPluginOptions,
): Decoration[] {
  const registry = getDefaultPluginRendererSlotRegistry();
  if (!registry.hasSlot(INLINE_CODE_RENDERER_SLOT, options.workspaceId)) {
    return [];
  }

  const decorations: Decoration[] = [];
  doc.descendants((node, position) => {
    if (!node.isText || !node.text) return;
    if (!node.marks.some((mark) => mark.type.name === "code")) return;
    const source = node.text;
    const key = `${options.documentId}:inline:${position}:${source}`;
    decorations.push(
      Decoration.inline(
        position,
        position + node.nodeSize,
        {
          class: "refmd-plugin-renderer-source-hidden",
          "aria-hidden": "true",
        },
        { key: `${key}:source` },
      ),
      Decoration.widget(
        position + node.nodeSize,
        (view) => {
          const container = view.dom.ownerDocument.createElement("span");
          container.className = "refmd-plugin-renderer-slot refmd-plugin-renderer-inline-slot";
          container.dataset.rendererKind = INLINE_CODE_RENDERER_SLOT.kind;
          container.dataset.rendererType = INLINE_CODE_RENDERER_SLOT.type;
          const mounted = registry.mount({
            slot: INLINE_CODE_RENDERER_SLOT,
            workspaceId: options.workspaceId,
            documentId: options.documentId,
            blockId: key,
            source,
            maxBytes: MAX_RENDERER_SOURCE_BYTES,
            container,
            title: `${INLINE_CODE_RENDERER_SLOT.type} renderer`,
          });
          if (mounted) {
            (container as HTMLElement & { __refmdDispose?: () => void }).__refmdDispose = () =>
              mounted.dispose();
          }
          return container;
        },
        {
          key,
          side: 1,
          destroy(node) {
            (node as HTMLElement & { __refmdDispose?: () => void }).__refmdDispose?.();
          },
        },
      ),
    );
  });

  return decorations;
}

function languageFromNode(node: ProseMirrorNode): string | null {
  return typeof node.attrs.language === "string" && node.attrs.language.trim() !== ""
    ? node.attrs.language.trim()
    : null;
}

function rendererSlotTypeAllowed(type: string): boolean {
  return SLOT_TYPE_PATTERN.test(type) && !FORBIDDEN_SLOT_TYPES.has(type);
}
