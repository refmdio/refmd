import { EditorState as CMEditorState } from "@codemirror/state";
import { EditorView as CMEditorView } from "@codemirror/view";
import { EditorState as PMEditorState } from "prosemirror-state";
import { EditorView as PMEditorView } from "prosemirror-view";
import { describe, expect, it } from "vitest";
import { EditorApi, pluginEditorDecorationsExtension } from "./codemirror-api";
import { ProseMirrorEditorApi, pluginEditorDecorationsPlugin } from "./prosemirror-api";
import { markdownSchema } from "../prosemirror/schema";

describe("plugin editor decoration adapters", () => {
  it("renders and clears CodeMirror plugin decorations through the editor adapter", () => {
    const parent = document.createElement("div");
    document.body.append(parent);
    const view = new CMEditorView({
      parent,
      state: CMEditorState.create({
        doc: "hello world",
        extensions: [pluginEditorDecorationsExtension],
      }),
    });
    const editor = new EditorApi(view);

    editor.setPluginDecorations("source-1", [
      {
        id: "mark.hello",
        range: { from: 0, to: 5 },
        style: "highlight",
        tone: "info",
      },
    ]);
    expect(parent.querySelector(".refmd-plugin-editor-decoration-highlight")).toBeInstanceOf(
      HTMLElement,
    );

    editor.clearPluginDecorations("source-1");
    expect(parent.querySelector(".refmd-plugin-editor-decoration-highlight")).toBeNull();
    view.destroy();
    parent.remove();
  });

  it("renders and clears ProseMirror plugin decorations through the editor adapter", () => {
    const parent = document.createElement("div");
    document.body.append(parent);
    const doc = markdownSchema.node("doc", null, [
      markdownSchema.node("paragraph", null, [markdownSchema.text("hello world")]),
    ]);
    const view = new PMEditorView(parent, {
      state: PMEditorState.create({
        doc,
        plugins: [pluginEditorDecorationsPlugin()],
      }),
    });
    const editor = new ProseMirrorEditorApi(view);

    editor.setPluginDecorations("source-1", [
      {
        id: "mark.hello",
        range: { from: 0, to: 5 },
        style: "highlight",
        tone: "info",
      },
    ]);
    expect(parent.querySelector(".refmd-plugin-editor-decoration-highlight")).toBeInstanceOf(
      HTMLElement,
    );

    editor.clearPluginDecorations("source-1");
    expect(parent.querySelector(".refmd-plugin-editor-decoration-highlight")).toBeNull();
    view.destroy();
    parent.remove();
  });
});
