import { RangeSetBuilder, StateEffect, type Extension } from "@codemirror/state";
import {
  Decoration,
  EditorView,
  ViewPlugin,
  WidgetType,
  type DecorationSet,
  type ViewUpdate,
} from "@codemirror/view";
import {
  getDefaultPluginRendererSlotRegistry,
  type PluginRendererSlot,
} from "@/features/plugin-runtime";

const MAX_RENDERER_SOURCE_BYTES = 256 * 1024;
const INLINE_CODE_RENDERER_SLOT: PluginRendererSlot = { kind: "inline", type: "code" };
const SLOT_TYPE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const FORBIDDEN_SLOT_TYPES = new Set(["markdown", "md", "document", "full-document"]);
const registryRefreshEffect = StateEffect.define<number>();

interface RendererSlotExtensionOptions {
  documentId: string;
  workspaceId?: string | null;
}

interface FencedBlock {
  marker: "`" | "~";
  markerLength: number;
  slot: PluginRendererSlot | null;
  sourceStart: number;
  blockStart: number;
}

interface RendererSlotWidgetParams {
  slot: PluginRendererSlot;
  workspaceId?: string | null;
  documentId: string;
  blockId: string;
  source: string;
}

export function pluginRendererSlotExtension(options: RendererSlotExtensionOptions): Extension {
  return [
    ViewPlugin.fromClass(
      class {
        decorations: DecorationSet;
        private destroyed = false;
        private readonly unsubscribe: () => void;
        private readonly view: EditorView;

        constructor(view: EditorView) {
          this.view = view;
          this.decorations = rendererSlotDecorations(view, options);
          this.unsubscribe = getDefaultPluginRendererSlotRegistry().subscribe(() => {
            queueMicrotask(() => {
              if (this.destroyed) return;
              this.view.dispatch({
                effects: registryRefreshEffect.of(
                  getDefaultPluginRendererSlotRegistry().snapshotVersion(),
                ),
              });
            });
          });
        }

        update(update: ViewUpdate) {
          const registryChanged = update.transactions.some((transaction) =>
            transaction.effects.some((effect) => effect.is(registryRefreshEffect)),
          );
          if (!update.docChanged && !registryChanged) return;
          this.decorations = rendererSlotDecorations(update.view, options);
        }

        destroy() {
          this.destroyed = true;
          this.unsubscribe();
        }
      },
      {
        decorations: (plugin) => plugin.decorations,
      },
    ),
    EditorView.baseTheme({
      ".refmd-plugin-renderer-source-hidden": {
        height: "0 !important",
        minHeight: "0 !important",
        margin: "0 !important",
        padding: "0 !important",
        overflow: "hidden !important",
        lineHeight: "0 !important",
        fontSize: "0 !important",
        opacity: "0",
        pointerEvents: "none",
      },
    }),
  ];
}

function rendererSlotDecorations(
  view: EditorView,
  options: RendererSlotExtensionOptions,
): DecorationSet {
  const registry = getDefaultPluginRendererSlotRegistry();
  const builder = new RangeSetBuilder<Decoration>();
  const inlineAvailable = registry.hasSlot(INLINE_CODE_RENDERER_SLOT, options.workspaceId);
  let fencedBlock: FencedBlock | null = null;

  for (let lineNumber = 1; lineNumber <= view.state.doc.lines; lineNumber += 1) {
    const line = view.state.doc.line(lineNumber);
    const lineText = line.text;

    if (fencedBlock) {
      if (isClosingFence(lineText, fencedBlock)) {
        if (fencedBlock.slot) {
          const source = trimFenceDelimiterNewline(
            view.state.doc.sliceString(fencedBlock.sourceStart, line.from),
          );
          addHiddenFencedBlockSourceLines(builder, view, fencedBlock.blockStart, lineNumber);
          builder.add(
            line.from,
            line.to,
            Decoration.replace({
              widget: new RendererSlotWidget({
                slot: fencedBlock.slot,
                workspaceId: options.workspaceId,
                documentId: options.documentId,
                blockId: `${options.documentId}:${fencedBlock.blockStart}`,
                source,
              }),
            }),
          );
        }
        fencedBlock = null;
      }
      continue;
    }

    const fence = openingFence(lineText);
    if (fence) {
      const slot =
        fence.type && rendererSlotTypeAllowed(fence.type)
          ? ({ kind: "block", type: fence.type } satisfies PluginRendererSlot)
          : null;
      fencedBlock = {
        marker: fence.marker,
        markerLength: fence.markerLength,
        slot: slot && registry.hasSlot(slot, options.workspaceId) ? slot : null,
        sourceStart: Math.min(view.state.doc.length, line.to + 1),
        blockStart: line.from,
      };
      continue;
    }

    if (inlineAvailable) {
      addInlineRendererWidgets(builder, line.from, lineText, options);
    }
  }

  return builder.finish();
}

function addHiddenFencedBlockSourceLines(
  builder: RangeSetBuilder<Decoration>,
  view: EditorView,
  blockStart: number,
  closingLineNumber: number,
): void {
  const openingLineNumber = view.state.doc.lineAt(blockStart).number;
  for (let lineNumber = openingLineNumber; lineNumber < closingLineNumber; lineNumber += 1) {
    const line = view.state.doc.line(lineNumber);
    builder.add(
      line.from,
      line.from,
      Decoration.line({ class: "refmd-plugin-renderer-source-hidden" }),
    );
  }
}

function addInlineRendererWidgets(
  builder: RangeSetBuilder<Decoration>,
  lineStart: number,
  lineText: string,
  options: RendererSlotExtensionOptions,
): void {
  let index = 0;
  while (index < lineText.length) {
    if (lineText[index] !== "`" || escapedBacktick(lineText, index)) {
      index += 1;
      continue;
    }
    const markerLength = countRun(lineText, index, "`");
    const closeIndex = lineText.indexOf("`".repeat(markerLength), index + markerLength);
    if (closeIndex < 0) return;
    const source = lineText.slice(index + markerLength, closeIndex);
    if (source.length > 0) {
      const from = lineStart + index;
      const to = lineStart + closeIndex + markerLength;
      builder.add(
        from,
        to,
        Decoration.replace({
          widget: new RendererSlotWidget({
            slot: INLINE_CODE_RENDERER_SLOT,
            workspaceId: options.workspaceId,
            documentId: options.documentId,
            blockId: `${options.documentId}:inline:${lineStart + index}:${source}`,
            source,
          }),
        }),
      );
    }
    index = closeIndex + markerLength;
  }
}

function openingFence(
  lineText: string,
): { marker: "`" | "~"; markerLength: number; type: string | null } | null {
  const match = /^(\s*)(`{3,}|~{3,})(.*)$/.exec(lineText);
  if (!match) return null;
  const markerRun = match[2];
  const rest = match[3]?.trim() ?? "";
  const type = rest.split(/\s+/)[0]?.trim() || null;
  return {
    marker: markerRun[0] as "`" | "~",
    markerLength: markerRun.length,
    type,
  };
}

function isClosingFence(lineText: string, block: FencedBlock): boolean {
  const trimmed = lineText.trim();
  if (trimmed.length < block.markerLength) return false;
  return [...trimmed].every((character) => character === block.marker);
}

function trimFenceDelimiterNewline(source: string): string {
  return source.replace(/\r?\n$/, "");
}

function rendererSlotTypeAllowed(type: string): boolean {
  return SLOT_TYPE_PATTERN.test(type) && !FORBIDDEN_SLOT_TYPES.has(type);
}

function escapedBacktick(lineText: string, index: number): boolean {
  let slashCount = 0;
  for (let cursor = index - 1; cursor >= 0 && lineText[cursor] === "\\"; cursor -= 1) {
    slashCount += 1;
  }
  return slashCount % 2 === 1;
}

function countRun(text: string, start: number, character: string): number {
  let length = 0;
  while (text[start + length] === character) length += 1;
  return length;
}

class RendererSlotWidget extends WidgetType {
  private readonly params: RendererSlotWidgetParams;

  constructor(params: RendererSlotWidgetParams) {
    super();
    this.params = params;
  }

  eq(other: WidgetType): boolean {
    return (
      other instanceof RendererSlotWidget &&
      other.params.slot.kind === this.params.slot.kind &&
      other.params.slot.type === this.params.slot.type &&
      other.params.workspaceId === this.params.workspaceId &&
      other.params.documentId === this.params.documentId &&
      other.params.blockId === this.params.blockId &&
      other.params.source === this.params.source
    );
  }

  toDOM(view: EditorView): HTMLElement {
    const container =
      this.params.slot.kind === "block"
        ? view.dom.ownerDocument.createElement("div")
        : view.dom.ownerDocument.createElement("span");
    container.className = [
      "refmd-plugin-renderer-slot",
      `refmd-plugin-renderer-${this.params.slot.kind}-slot`,
    ].join(" ");
    container.dataset.rendererKind = this.params.slot.kind;
    container.dataset.rendererType = this.params.slot.type;
    if (this.params.slot.kind === "block") container.style.minHeight = "48px";

    const mounted = getDefaultPluginRendererSlotRegistry().mount({
      slot: this.params.slot,
      workspaceId: this.params.workspaceId,
      documentId: this.params.documentId,
      blockId: this.params.blockId,
      source: this.params.source,
      maxBytes: MAX_RENDERER_SOURCE_BYTES,
      container,
      title: `${this.params.slot.type} renderer`,
    });
    if (mounted) {
      (container as HTMLElement & { __refmdDispose?: () => void }).__refmdDispose = () =>
        mounted.dispose();
    }
    return container;
  }

  destroy(dom: HTMLElement): void {
    (dom as HTMLElement & { __refmdDispose?: () => void }).__refmdDispose?.();
  }
}
