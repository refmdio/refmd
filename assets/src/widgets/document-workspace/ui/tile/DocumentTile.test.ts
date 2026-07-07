import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import {
  registerEditor,
  unregisterEditor,
  type EditorLike,
  type EditorPosition,
} from "@/features/editor";
import { clearPluginEditorProviderState } from "./DocumentTile";

const panelId = "document-one:markdown";

afterEach(() => {
  unregisterEditor(panelId);
});

describe("clearPluginEditorProviderState", () => {
  it("clears tracked decorations when provider entries disappear", () => {
    const clearPluginDecorations = vi.fn();
    registerEditor(panelId, createEditor({ clearPluginDecorations }));
    const decorationSources = new Set(["source-one", "source-two"]);
    const setDiagnostics = vi.fn();
    const setSuggestions = vi.fn();

    clearPluginEditorProviderState({
      panelId,
      decorationSources,
      setDiagnostics,
      setSuggestions,
    });

    expect(clearPluginDecorations.mock.calls.map(([sourceId]) => sourceId)).toEqual([
      "source-one",
      "source-two",
    ]);
    expect([...decorationSources]).toEqual([]);
    expect(setDiagnostics).toHaveBeenCalledWith([]);
    expect(setSuggestions).toHaveBeenCalledWith([]);
  });
});

function createEditor(overrides: Partial<EditorLike> = {}): EditorLike {
  const position: EditorPosition = { line: 0, ch: 0 };
  return {
    getValue: () => "",
    setValue: vi.fn(),
    getLine: () => "",
    setLine: vi.fn(),
    lineCount: () => 1,
    getSelection: () => "",
    somethingSelected: () => false,
    replaceSelection: vi.fn(),
    getRange: () => "",
    replaceRange: vi.fn(),
    transaction: vi.fn(),
    getCursor: () => position,
    setCursor: vi.fn(),
    setSelection: vi.fn(),
    listSelections: () => [{ anchor: position, head: position }],
    getScrollInfo: () => ({ top: 0, left: 0 }),
    scrollTo: vi.fn(),
    scrollIntoView: vi.fn(),
    undo: vi.fn(),
    redo: vi.fn(),
    focus: vi.fn(),
    blur: vi.fn(),
    hasFocus: () => false,
    posToOffset: () => 0,
    offsetToPos: () => position,
    setPluginDecorations: vi.fn(),
    clearPluginDecorations: vi.fn(),
    ...overrides,
  };
}
