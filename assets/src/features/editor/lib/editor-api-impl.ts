import { EditorView as CMEditorView } from "@codemirror/view";
import { EditorSelection as CMEditorSelection, type ChangeSpec } from "@codemirror/state";
import { undo as cmUndo, redo as cmRedo } from "@codemirror/commands";
import { EditorView as PMEditorView } from "prosemirror-view";
import { TextSelection } from "prosemirror-state";
import type {
  EditorLike,
  EditorPosition,
  EditorRange,
  EditorSelection,
  EditorTransaction,
} from "./editor-api";

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

export class EditorApi implements EditorLike {
  readonly cm: CMEditorView;

  constructor(cmView: CMEditorView) {
    this.cm = cmView;
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
    cmUndo(this.cm);
  }

  redo(): void {
    cmRedo(this.cm);
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
}

interface YTextWritable {
  toString(): string;
  insert(offset: number, text: string): void;
  delete(offset: number, length: number): void;
  readonly length: number;
  readonly doc: { transact(fn: () => void): void } | null;
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
}
