import { Plugin, PluginKey, TextSelection } from "prosemirror-state";
import {
  Decoration,
  DecorationSet,
  EditorView as PMEditorView,
  type DecorationSource,
} from "prosemirror-view";
import type { Node as ProseMirrorNode } from "prosemirror-model";
import type {
  EditorLike,
  EditorPluginDecoration,
  EditorPosition,
  EditorRange,
  EditorSelection,
  EditorTransaction,
} from "@/features/editor";

function offsetToPosition(text: string, offset: number): EditorPosition {
  let line = 0;
  let col = 0;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === "\n") {
      line++;
      col = 0;
    } else {
      col++;
    }
  }
  return { line, ch: col };
}

function positionToOffset(text: string, pos: EditorPosition): number {
  let line = 0;
  let offset = 0;
  for (; offset < text.length && line < pos.line; offset++) {
    if (text[offset] === "\n") line++;
  }
  return offset + pos.ch;
}

interface YTextWritable {
  toString(): string;
  insert(offset: number, text: string): void;
  delete(offset: number, length: number): void;
  readonly length: number;
  readonly doc: { transact(fn: () => void): void } | null;
}

interface PluginDecorationMeta {
  kind: "set" | "clear";
  sourceId: string;
  decorations?: readonly EditorPluginDecoration[];
}

interface PluginDecorationState {
  sources: Map<string, readonly EditorPluginDecoration[]>;
  decorations: DecorationSet;
}

const pluginDecorationsKey = new PluginKey<PluginDecorationState>(
  "refmd-plugin-editor-decorations",
);

function pluginDecorationClass(decoration: EditorPluginDecoration): string {
  return [
    "refmd-plugin-editor-decoration",
    `refmd-plugin-editor-decoration-${decoration.style}`,
    `refmd-plugin-editor-decoration-${decoration.tone}`,
  ].join(" ");
}

function buildPluginDecorations(
  doc: PMEditorView["state"]["doc"],
  sources: Map<string, readonly EditorPluginDecoration[]>,
): DecorationSet {
  const decorations = [...sources.values()]
    .flat()
    .filter((decoration) => decoration.range.to > decoration.range.from)
    .sort(
      (a, b) => a.range.from - b.range.from || a.range.to - b.range.to || a.id.localeCompare(b.id),
    )
    .map((decoration) =>
      Decoration.inline(
        textOffsetToProseMirrorPos(doc, decoration.range.from),
        textOffsetToProseMirrorPos(doc, decoration.range.to),
        { class: pluginDecorationClass(decoration) },
      ),
    );
  return DecorationSet.create(doc, decorations);
}

function textOffsetToProseMirrorPos(doc: ProseMirrorNode, offset: number): number {
  const target = Math.max(0, offset);
  let consumed = 0;
  let position = doc.content.size;
  doc.descendants((node, pos) => {
    if (!node.isText) return true;
    const length = node.text?.length ?? 0;
    if (consumed + length >= target) {
      position = pos + (target - consumed);
      return false;
    }
    consumed += length;
    return true;
  });
  return Math.max(0, Math.min(doc.content.size, position));
}

export function pluginEditorDecorationsPlugin(): Plugin {
  return new Plugin<PluginDecorationState>({
    key: pluginDecorationsKey,
    state: {
      init(_config, state) {
        const sources = new Map<string, readonly EditorPluginDecoration[]>();
        return { sources, decorations: buildPluginDecorations(state.doc, sources) };
      },
      apply(tr, value, _oldState, newState) {
        const meta = tr.getMeta(pluginDecorationsKey) as PluginDecorationMeta | undefined;
        if (!meta && !tr.docChanged) return value;
        if (!meta) {
          const sources = new Map<string, readonly EditorPluginDecoration[]>();
          return { sources, decorations: DecorationSet.empty };
        }
        const sources = new Map(value.sources);
        if (meta.kind === "set") sources.set(meta.sourceId, [...(meta.decorations ?? [])]);
        if (meta.kind === "clear") sources.delete(meta.sourceId);
        return { sources, decorations: buildPluginDecorations(newState.doc, sources) };
      },
    },
    props: {
      decorations(state): DecorationSource | null | undefined {
        return pluginDecorationsKey.getState(state)?.decorations;
      },
    },
  });
}

export class ProseMirrorEditorApi implements EditorLike {
  readonly pm: PMEditorView;
  private yText: YTextWritable | null;
  private undoManager: { undo(): void; redo(): void } | null;

  constructor(
    pmView: PMEditorView,
    yText?: YTextWritable,
    undoManager?: { undo(): void; redo(): void },
  ) {
    this.pm = pmView;
    this.yText = yText ?? null;
    this.undoManager = undoManager ?? null;
  }

  getValue(): string {
    return this.yText?.toString() ?? this.pm.state.doc.textContent;
  }

  setValue(content: string): void {
    if (this.yText) {
      this.yText.doc!.transact(() => {
        this.yText!.delete(0, this.yText!.length);
        this.yText!.insert(0, content);
      });
    } else {
      const { tr } = this.pm.state;
      tr.replaceWith(0, tr.doc.content.size, this.pm.state.schema.text(content));
      this.pm.dispatch(tr);
    }
  }

  getLine(line: number): string {
    const text = this.getValue();
    const lines = text.split("\n");
    return lines[line] ?? "";
  }

  setLine(line: number, text: string): void {
    const fullText = this.getValue();
    const lines = fullText.split("\n");
    if (line < 0 || line >= lines.length) return;
    const from = positionToOffset(fullText, { line, ch: 0 });
    const len = lines[line].length;
    if (this.yText) {
      this.yText.doc!.transact(() => {
        this.yText!.delete(from, len);
        this.yText!.insert(from, text);
      });
    } else {
      const { tr } = this.pm.state;
      tr.replaceWith(from, from + len, this.pm.state.schema.text(text));
      this.pm.dispatch(tr);
    }
  }

  lineCount(): number {
    return this.getValue().split("\n").length;
  }

  getSelection(): string {
    const { from, to } = this.pm.state.selection;
    return this.pm.state.doc.textBetween(from, to);
  }

  somethingSelected(): boolean {
    const { from, to } = this.pm.state.selection;
    return from !== to;
  }

  replaceSelection(text: string): void {
    const { tr } = this.pm.state;
    tr.replaceSelectionWith(this.pm.state.schema.text(text), false);
    this.pm.dispatch(tr);
  }

  getRange(from: EditorPosition, to: EditorPosition): string {
    const fullText = this.getValue();
    const f = positionToOffset(fullText, from);
    const t = positionToOffset(fullText, to);
    return fullText.slice(f, t);
  }

  replaceRange(text: string, from: EditorPosition, to?: EditorPosition): void {
    const fullText = this.getValue();
    const f = positionToOffset(fullText, from);
    const t = to ? positionToOffset(fullText, to) : f;
    if (this.yText) {
      this.yText.doc!.transact(() => {
        if (t > f) this.yText!.delete(f, t - f);
        if (text) this.yText!.insert(f, text);
      });
    } else {
      const { tr } = this.pm.state;
      tr.replaceWith(f, t, this.pm.state.schema.text(text));
      this.pm.dispatch(tr);
    }
  }

  transaction(tx: EditorTransaction): void {
    if (tx.replaceSelection !== undefined) {
      this.replaceSelection(tx.replaceSelection);
      return;
    }
    if (tx.changes && tx.changes.length > 0 && this.yText) {
      const snapshot = this.getValue();
      this.yText.doc!.transact(() => {
        let offsetShift = 0;
        for (const change of tx.changes!) {
          const from = positionToOffset(snapshot, change.from) + offsetShift;
          const to = change.to ? positionToOffset(snapshot, change.to) + offsetShift : from;
          if (to > from) this.yText!.delete(from, to - from);
          if (change.text) this.yText!.insert(from, change.text);
          offsetShift += change.text.length - (to - from);
        }
      });
    } else if (tx.changes && tx.changes.length > 0) {
      const { tr } = this.pm.state;
      for (const change of tx.changes) {
        const from = this.posToOffset(change.from);
        const to = change.to ? this.posToOffset(change.to) : from;
        tr.replaceWith(from, to, this.pm.state.schema.text(change.text));
      }
      this.pm.dispatch(tr);
    }
    if (tx.selection) {
      const anchor = this.posToOffset(tx.selection.anchor);
      const head = tx.selection.head ? this.posToOffset(tx.selection.head) : anchor;
      const { tr } = this.pm.state;
      tr.setSelection(TextSelection.create(tr.doc, anchor, head));
      this.pm.dispatch(tr);
    }
  }

  getCursor(side?: "from" | "to" | "head" | "anchor"): EditorPosition {
    const sel = this.pm.state.selection;
    let offset: number;
    switch (side) {
      case "from":
        offset = sel.from;
        break;
      case "to":
        offset = sel.to;
        break;
      case "anchor":
        offset = sel.$anchor.pos;
        break;
      default:
        offset = sel.$head.pos;
    }
    return this.offsetToPos(offset);
  }

  setCursor(pos: EditorPosition): void {
    const offset = this.posToOffset(pos);
    const { tr } = this.pm.state;
    tr.setSelection(TextSelection.create(tr.doc, offset));
    this.pm.dispatch(tr);
  }

  setSelection(anchor: EditorPosition, head?: EditorPosition): void {
    const a = this.posToOffset(anchor);
    const h = head ? this.posToOffset(head) : a;
    const { tr } = this.pm.state;
    tr.setSelection(TextSelection.create(tr.doc, a, h));
    this.pm.dispatch(tr);
  }

  listSelections(): EditorSelection[] {
    const sel = this.pm.state.selection;
    return [{ anchor: this.offsetToPos(sel.$anchor.pos), head: this.offsetToPos(sel.$head.pos) }];
  }

  private get scrollEl(): HTMLElement {
    return (this.pm.dom.parentElement as HTMLElement) ?? (this.pm.dom as HTMLElement);
  }

  getScrollInfo(): { top: number; left: number } {
    const el = this.scrollEl;
    return { top: el.scrollTop, left: el.scrollLeft };
  }

  scrollTo(x?: number | null, y?: number | null): void {
    const el = this.scrollEl;
    if (y != null) el.scrollTop = y;
    if (x != null) el.scrollLeft = x;
  }

  scrollIntoView(range: EditorRange, center?: boolean): void {
    const from = this.posToOffset(range.from);
    const to = this.posToOffset(range.to);
    const resolvedFrom = Math.min(from, this.pm.state.doc.content.size);
    const resolvedTo = Math.min(to, this.pm.state.doc.content.size);
    const { tr } = this.pm.state;
    tr.setSelection(TextSelection.create(tr.doc, resolvedFrom, resolvedTo));
    tr.scrollIntoView();
    this.pm.dispatch(tr);
    if (!center) return;
    const coords = this.pm.coordsAtPos(resolvedFrom);
    if (coords) {
      const el = this.scrollEl;
      const rect = el.getBoundingClientRect();
      const targetY = coords.top - rect.top + el.scrollTop - rect.height / 2;
      el.scrollTop = Math.max(0, targetY);
    }
  }

  undo(): void {
    this.undoManager?.undo();
  }

  redo(): void {
    this.undoManager?.redo();
  }

  focus(): void {
    this.pm.focus();
  }

  blur(): void {
    (this.pm.dom as HTMLElement).blur();
  }

  hasFocus(): boolean {
    return this.pm.hasFocus();
  }

  posToOffset(pos: EditorPosition): number {
    return positionToOffset(this.getValue(), pos);
  }

  offsetToPos(offset: number): EditorPosition {
    return offsetToPosition(this.getValue(), offset);
  }

  setPluginDecorations(sourceId: string, decorations: readonly EditorPluginDecoration[]): void {
    this.pm.dispatch(
      this.pm.state.tr.setMeta(pluginDecorationsKey, {
        kind: "set",
        sourceId,
        decorations,
      } satisfies PluginDecorationMeta),
    );
  }

  clearPluginDecorations(sourceId: string): void {
    this.pm.dispatch(
      this.pm.state.tr.setMeta(pluginDecorationsKey, {
        kind: "clear",
        sourceId,
      } satisfies PluginDecorationMeta),
    );
  }
}
