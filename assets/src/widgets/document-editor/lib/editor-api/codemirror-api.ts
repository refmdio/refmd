import {
  EditorSelection as CMEditorSelection,
  RangeSetBuilder,
  StateEffect,
  StateField,
  type ChangeSpec,
} from "@codemirror/state";
import { Decoration, EditorView as CMEditorView, type DecorationSet } from "@codemirror/view";
import type {
  EditorLike,
  EditorPluginDecoration,
  EditorPosition,
  EditorRange,
  EditorSelection,
  EditorTransaction,
} from "@/features/editor";

interface PluginDecorationFieldState {
  sources: Map<string, readonly EditorPluginDecoration[]>;
  decorations: DecorationSet;
}

const setPluginDecorationsEffect = StateEffect.define<{
  sourceId: string;
  decorations: readonly EditorPluginDecoration[];
}>();
const clearPluginDecorationsEffect = StateEffect.define<string>();

function pluginDecorationClass(decoration: EditorPluginDecoration): string {
  return [
    "refmd-plugin-editor-decoration",
    `refmd-plugin-editor-decoration-${decoration.style}`,
    `refmd-plugin-editor-decoration-${decoration.tone}`,
  ].join(" ");
}

function buildPluginDecorations(
  docLength: number,
  sources: Map<string, readonly EditorPluginDecoration[]>,
): DecorationSet {
  const ranges = [...sources.values()]
    .flat()
    .map((decoration) => ({
      ...decoration,
      from: Math.max(0, Math.min(docLength, decoration.range.from)),
      to: Math.max(0, Math.min(docLength, decoration.range.to)),
    }))
    .filter((decoration) => decoration.to > decoration.from)
    .sort((a, b) => a.from - b.from || a.to - b.to || a.id.localeCompare(b.id));
  const builder = new RangeSetBuilder<Decoration>();
  for (const decoration of ranges) {
    builder.add(
      decoration.from,
      decoration.to,
      Decoration.mark({ class: pluginDecorationClass(decoration) }),
    );
  }
  return builder.finish();
}

const pluginDecorationsField = StateField.define<PluginDecorationFieldState>({
  create(state) {
    const sources = new Map<string, readonly EditorPluginDecoration[]>();
    return { sources, decorations: buildPluginDecorations(state.doc.length, sources) };
  },
  update(value, tr) {
    let sources = value.sources;
    let changed = false;
    for (const effect of tr.effects) {
      if (effect.is(setPluginDecorationsEffect)) {
        if (!changed) sources = new Map(sources);
        sources.set(effect.value.sourceId, [...effect.value.decorations]);
        changed = true;
      } else if (effect.is(clearPluginDecorationsEffect)) {
        if (!changed) sources = new Map(sources);
        sources.delete(effect.value);
        changed = true;
      }
    }
    if (!changed && !tr.docChanged) return value;
    if (tr.docChanged && !changed) sources = new Map();
    return { sources, decorations: buildPluginDecorations(tr.state.doc.length, sources) };
  },
  provide: (field) => CMEditorView.decorations.from(field, (value) => value.decorations),
});

export const pluginEditorDecorationsExtension = [pluginDecorationsField];

export class EditorApi implements EditorLike {
  readonly cm: CMEditorView;
  private undoManager: { undo(): void; redo(): void } | null;

  constructor(cmView: CMEditorView, undoManager?: { undo(): void; redo(): void }) {
    this.cm = cmView;
    this.undoManager = undoManager ?? null;
  }

  getValue(): string {
    return this.cm.state.doc.toString();
  }

  setValue(content: string): void {
    this.cm.dispatch({
      changes: { from: 0, to: this.cm.state.doc.length, insert: content },
    });
  }

  getLine(line: number): string {
    return this.cm.state.doc.line(line + 1).text;
  }

  setLine(line: number, text: string): void {
    const lineObj = this.cm.state.doc.line(line + 1);
    this.cm.dispatch({
      changes: { from: lineObj.from, to: lineObj.to, insert: text },
    });
  }

  lineCount(): number {
    return this.cm.state.doc.lines;
  }

  getSelection(): string {
    const { from, to } = this.cm.state.selection.main;
    return this.cm.state.sliceDoc(from, to);
  }

  somethingSelected(): boolean {
    const { from, to } = this.cm.state.selection.main;
    return from !== to;
  }

  replaceSelection(text: string): void {
    this.cm.dispatch(this.cm.state.replaceSelection(text));
  }

  getRange(from: EditorPosition, to: EditorPosition): string {
    return this.cm.state.sliceDoc(this.posToOffset(from), this.posToOffset(to));
  }

  replaceRange(text: string, from: EditorPosition, to?: EditorPosition): void {
    const fromOffset = this.posToOffset(from);
    const toOffset = to ? this.posToOffset(to) : fromOffset;
    this.cm.dispatch({
      changes: { from: fromOffset, to: toOffset, insert: text },
    });
  }

  transaction(tx: EditorTransaction): void {
    if (tx.replaceSelection !== undefined) {
      this.cm.dispatch(this.cm.state.replaceSelection(tx.replaceSelection));
      return;
    }

    const specs: { changes?: ChangeSpec; selection?: { anchor: number; head?: number } } = {};
    if (tx.changes && tx.changes.length > 0) {
      specs.changes = tx.changes.map((change) => ({
        from: this.posToOffset(change.from),
        to: change.to ? this.posToOffset(change.to) : undefined,
        insert: change.text,
      }));
    }
    if (tx.selection) {
      const anchor = this.posToOffset(tx.selection.anchor);
      const head = tx.selection.head ? this.posToOffset(tx.selection.head) : anchor;
      specs.selection = { anchor, head };
    }
    this.cm.dispatch(specs);
  }

  getCursor(side?: "from" | "to" | "head" | "anchor"): EditorPosition {
    const sel = this.cm.state.selection.main;
    let offset: number;
    switch (side) {
      case "from":
        offset = sel.from;
        break;
      case "to":
        offset = sel.to;
        break;
      case "anchor":
        offset = sel.anchor;
        break;
      default:
        offset = sel.head;
    }
    return this.offsetToPos(offset);
  }

  setCursor(pos: EditorPosition): void {
    const offset = this.posToOffset(pos);
    this.cm.dispatch({ selection: { anchor: offset } });
  }

  setSelection(anchor: EditorPosition, head?: EditorPosition): void {
    const a = this.posToOffset(anchor);
    const h = head ? this.posToOffset(head) : a;
    this.cm.dispatch({ selection: { anchor: a, head: h } });
  }

  listSelections(): EditorSelection[] {
    return this.cm.state.selection.ranges.map((range) => ({
      anchor: this.offsetToPos(range.anchor),
      head: this.offsetToPos(range.head),
    }));
  }

  getScrollInfo(): { top: number; left: number } {
    return { top: this.cm.scrollDOM.scrollTop, left: this.cm.scrollDOM.scrollLeft };
  }

  scrollTo(x?: number | null, y?: number | null): void {
    if (y != null) this.cm.scrollDOM.scrollTop = y;
    if (x != null) this.cm.scrollDOM.scrollLeft = x;
  }

  scrollIntoView(range: EditorRange, center?: boolean): void {
    const from = this.posToOffset(range.from);
    const to = this.posToOffset(range.to);
    this.cm.dispatch({
      effects: CMEditorView.scrollIntoView(CMEditorSelection.range(from, to), {
        y: center ? "center" : "nearest",
      }),
    });
  }

  undo(): void {
    this.undoManager?.undo();
  }

  redo(): void {
    this.undoManager?.redo();
  }

  focus(): void {
    this.cm.focus();
  }

  blur(): void {
    this.cm.contentDOM.blur();
  }

  hasFocus(): boolean {
    return this.cm.hasFocus;
  }

  posToOffset(pos: EditorPosition): number {
    const line = this.cm.state.doc.line(pos.line + 1);
    return line.from + pos.ch;
  }

  offsetToPos(offset: number): EditorPosition {
    const line = this.cm.state.doc.lineAt(offset);
    return { line: line.number - 1, ch: offset - line.from };
  }

  setPluginDecorations(sourceId: string, decorations: readonly EditorPluginDecoration[]): void {
    this.cm.dispatch({
      effects: setPluginDecorationsEffect.of({ sourceId, decorations }),
    });
  }

  clearPluginDecorations(sourceId: string): void {
    this.cm.dispatch({
      effects: clearPluginDecorationsEffect.of(sourceId),
    });
  }
}
