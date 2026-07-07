import { afterEach, describe, expect, it } from "vitest";
import { EditorState, TextSelection } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { buildCollabPlugins } from "./plugin-base";
import {
  executeSlashCommand,
  openSlashCommandMenuBelow,
  type SlashMenuState,
  slashCommandsPlugin,
} from "./plugin-slash-commands";
import { markdownSchema } from "./schema";

const cleanupFns: (() => void)[] = [];

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
});

function createContainer(): HTMLElement {
  const container = document.createElement("div");
  document.body.append(container);
  cleanupFns.push(() => container.remove());
  return container;
}

function paragraph(text: string) {
  return markdownSchema.nodes.paragraph.create(null, markdownSchema.text(text));
}

function createView() {
  const slashPlugin = slashCommandsPlugin(markdownSchema);
  const view = new EditorView(createContainer(), {
    state: EditorState.create({
      doc: markdownSchema.node("doc", null, [markdownSchema.nodes.paragraph.create()]),
      plugins: [slashPlugin, ...buildCollabPlugins(markdownSchema)],
    }),
  });
  cleanupFns.push(() => view.destroy());

  return {
    slashState: () => slashPlugin.getState(view.state) as SlashMenuState,
    view,
  };
}

function createCodeBlockView() {
  const slashPlugin = slashCommandsPlugin(markdownSchema);
  const view = new EditorView(createContainer(), {
    state: EditorState.create({
      doc: markdownSchema.node("doc", null, [markdownSchema.nodes.code_block.create()]),
      plugins: [slashPlugin, ...buildCollabPlugins(markdownSchema)],
    }),
  });
  cleanupFns.push(() => view.destroy());

  return {
    slashState: () => slashPlugin.getState(view.state) as SlashMenuState,
    view,
  };
}

function press(view: EditorView, key: string): boolean {
  const event = new KeyboardEvent("keydown", {
    bubbles: true,
    cancelable: true,
    key,
  });
  let handled = false;
  view.someProp("handleKeyDown", (handler) => {
    if (handled) return true;
    handled = handler(view, event) === true;
    return handled;
  });
  return handled;
}

function inputText(view: EditorView, text: string): boolean {
  const { from, to } = view.state.selection;
  let handled = false;
  view.someProp("handleTextInput", (handler) => {
    if (handled) return true;
    handled =
      handler(view, from, to, text, () => view.state.tr.insertText(text, from, to)) === true;
    return handled;
  });
  return handled;
}

function insertDefaultText(view: EditorView, text: string): void {
  const { from, to } = view.state.selection;
  const tr = view.state.tr.insertText(text, from, to);
  tr.setSelection(TextSelection.create(tr.doc, from + text.length));
  view.dispatch(tr);
}

function insertHardBreak(view: EditorView): void {
  const { from, to } = view.state.selection;
  const tr = view.state.tr.replaceRangeWith(from, to, markdownSchema.nodes.hard_break.create());
  tr.setSelection(TextSelection.create(tr.doc, from + 1));
  view.dispatch(tr);
}

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe("slash commands ProseMirror plugin", () => {
  it("opens the menu from the text-input path when slash keydown is not handled", () => {
    const { slashState, view } = createView();

    expect(inputText(view, "/")).toBe(true);

    expect(slashState()).toMatchObject({
      active: true,
      query: "",
      selectedIndex: 0,
    });
    expect(slashState().commands.length).toBeGreaterThan(0);
    expect(view.state.doc.textContent).toBe("/");
  });

  it("opens and filters the menu after slash arrives through a normal text transaction", async () => {
    const { slashState, view } = createView();

    insertDefaultText(view, "/");
    expect(slashState()).toMatchObject({
      active: true,
      query: "",
    });

    insertDefaultText(view, "h");
    insertDefaultText(view, "1");
    expect(slashState()).toMatchObject({
      active: true,
      query: "h1",
      selectedIndex: 0,
    });
    expect(slashState().commands.map((command) => command.label)).toContain("Heading 1");

    expect(press(view, "Enter")).toBe(true);
    await flushMicrotasks();

    expect(slashState().active).toBe(false);
    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.heading);
    expect(view.state.doc.firstChild?.attrs.level).toBe(1);
    expect(view.state.doc.textContent).toBe("");
  });

  it("opens the menu after typing a title and pressing Enter to a new paragraph", () => {
    const { slashState, view } = createView();

    insertDefaultText(view, "Document title");
    expect(press(view, "Enter")).toBe(true);
    insertDefaultText(view, "/");

    expect(view.state.doc.textContent).toBe("Document title/");
    expect(slashState()).toMatchObject({
      active: true,
      query: "",
      selectedIndex: 0,
    });
    expect(slashState().commands.length).toBeGreaterThan(0);
  });

  it("opens the menu when slash starts a visual line after a hard break", () => {
    const { slashState, view } = createView();

    insertDefaultText(view, "Document title");
    insertHardBreak(view);
    expect(press(view, "/")).toBe(true);

    expect(slashState()).toMatchObject({
      active: true,
      query: "",
      selectedIndex: 0,
    });
    expect(slashState().commands.length).toBeGreaterThan(0);
  });

  it("opens the menu after a normal text transaction inserts slash on a hard-break line", () => {
    const { slashState, view } = createView();

    insertDefaultText(view, "Document title");
    insertHardBreak(view);
    insertDefaultText(view, "/");

    expect(slashState()).toMatchObject({
      active: true,
      query: "",
      selectedIndex: 0,
    });
    expect(slashState().commands.length).toBeGreaterThan(0);
  });

  it("executes the highlighted command with Enter before the base keymap handles it", async () => {
    const { slashState, view } = createView();

    expect(press(view, "/")).toBe(true);
    expect(press(view, "h")).toBe(true);
    expect(press(view, "1")).toBe(true);
    expect(slashState().commands.map((command) => command.label)).toContain("Heading 1");

    expect(press(view, "Enter")).toBe(true);
    await flushMicrotasks();

    expect(slashState().active).toBe(false);
    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.heading);
    expect(view.state.doc.firstChild?.attrs.level).toBe(1);
    expect(view.state.doc.textContent).toBe("");
  });

  it("executes the highlighted command with Space while the menu is active", async () => {
    const { slashState, view } = createView();

    for (const key of ["/", "h", "2"]) {
      expect(press(view, key)).toBe(true);
    }
    expect(slashState().commands.map((command) => command.label)).toContain("Heading 2");

    expect(press(view, " ")).toBe(true);
    await flushMicrotasks();

    expect(slashState().active).toBe(false);
    expect(view.state.doc.firstChild?.type).toBe(markdownSchema.nodes.heading);
    expect(view.state.doc.firstChild?.attrs.level).toBe(2);
    expect(view.state.doc.textContent).toBe("");
  });

  it("keeps query input visible for an empty result set", () => {
    const { slashState, view } = createView();

    expect(press(view, "/")).toBe(true);
    expect(press(view, "x")).toBe(true);
    expect(press(view, "x")).toBe(true);
    expect(press(view, "x")).toBe(true);

    expect(slashState()).toMatchObject({
      active: true,
      commands: [],
      query: "xxx",
    });
    expect(view.state.doc.textContent).toBe("/xxx");
    expect(press(view, "ArrowDown")).toBe(true);
    expect(slashState().active).toBe(true);
  });

  it("does not trap Enter, Space, or Tab when no slash command matches", () => {
    for (const key of ["Enter", " ", "Tab"]) {
      const { slashState, view } = createView();

      expect(press(view, "/")).toBe(true);
      for (const char of ["x", "x", "x"]) {
        expect(press(view, char)).toBe(true);
      }
      expect(slashState()).toMatchObject({
        active: true,
        commands: [],
        query: "xxx",
      });

      const handled = press(view, key);

      expect(slashState().active).toBe(false);
      if (key === "Enter") {
        expect(handled).toBe(true);
        expect(view.state.doc.childCount).toBe(2);
      } else {
        expect(handled).toBe(false);
      }
    }
  });

  it("treats slash as code text inside code blocks", () => {
    const { slashState, view } = createCodeBlockView();

    expect(inputText(view, "/")).toBe(false);
    insertDefaultText(view, "/");

    expect(view.state.doc.textContent).toBe("/");
    expect(slashState().active).toBe(false);
  });

  it("opens the block-handle menu without writing a slash into the document", () => {
    const { slashState, view } = createView();
    insertDefaultText(view, "First");

    expect(openSlashCommandMenuBelow(view, 0)).toBe(true);
    expect(slashState()).toMatchObject({
      active: true,
      anchorPos: view.state.doc.child(0).nodeSize,
      insertAfterBlockPos: 0,
      mode: "virtual",
      query: "",
    });
    expect(view.state.doc.textContent).toBe("First");

    expect(press(view, "Escape")).toBe(true);
    expect(slashState().active).toBe(false);
    expect(view.state.doc.textContent).toBe("First");
    expect(view.state.doc.childCount).toBe(1);
  });

  it("applies a block-handle menu command only after selection", async () => {
    const { slashState, view } = createView();
    insertDefaultText(view, "First");

    expect(openSlashCommandMenuBelow(view, 0)).toBe(true);
    expect(press(view, "h")).toBe(true);
    expect(press(view, "2")).toBe(true);
    expect(view.state.doc.textContent).toBe("First");
    expect(slashState().query).toBe("h2");

    expect(press(view, "Enter")).toBe(true);
    await flushMicrotasks();

    expect(slashState().active).toBe(false);
    expect(view.state.doc.childCount).toBe(2);
    expect(view.state.doc.child(0).textContent).toBe("First");
    expect(view.state.doc.child(1).type).toBe(markdownSchema.nodes.heading);
    expect(view.state.doc.child(1).attrs.level).toBe(2);
    expect(view.state.doc.textContent).toBe("First");
  });

  it("keeps the block-handle virtual menu when an unrelated document change preserves the source block", () => {
    const { slashState, view } = createView();
    insertDefaultText(view, "First");

    expect(openSlashCommandMenuBelow(view, 0)).toBe(true);
    expect(slashState().active).toBe(true);

    view.dispatch(view.state.tr.insert(view.state.doc.content.size, paragraph("Remote")));

    expect(slashState()).toMatchObject({
      active: true,
      insertAfterBlockPos: 0,
      mode: "virtual",
    });
    expect(view.state.doc.childCount).toBe(2);
    expect(view.state.doc.child(0).textContent).toBe("First");
    expect(view.state.doc.child(1).textContent).toBe("Remote");
  });

  it("closes the block-handle virtual menu when the source block changes before selection", () => {
    const { slashState, view } = createView();
    insertDefaultText(view, "First");

    expect(openSlashCommandMenuBelow(view, 0)).toBe(true);
    expect(slashState().active).toBe(true);

    view.dispatch(view.state.tr.insertText("!", 1, 1));

    expect(slashState().active).toBe(false);
    expect(view.state.doc.child(0).textContent).toBe("!First");
  });

  it("rejects stale block-handle virtual menu state after the document changes", async () => {
    const { slashState, view } = createView();
    insertDefaultText(view, "First");

    expect(openSlashCommandMenuBelow(view, 0)).toBe(true);
    const staleState = {
      ...slashState(),
      commands: slashState().commands.filter((command) => command.label === "Heading 2"),
      selectedIndex: 0,
    } satisfies SlashMenuState;

    view.dispatch(view.state.tr.insert(view.state.doc.content.size, paragraph("Remote")));

    expect(executeSlashCommand(view, staleState)).toBe(false);
    await flushMicrotasks();

    expect(view.state.doc.childCount).toBe(2);
    expect(view.state.doc.child(0).textContent).toBe("First");
    expect(view.state.doc.child(1).textContent).toBe("Remote");
    expect(view.state.doc.child(1).type).toBe(markdownSchema.nodes.paragraph);
  });

  it("creates task list and table blocks from slash commands", async () => {
    const taskEditor = createView();

    for (const key of ["/", "t", "o", "d", "o", "Enter"]) {
      expect(press(taskEditor.view, key)).toBe(true);
    }
    await flushMicrotasks();

    const taskList = taskEditor.view.state.doc.firstChild;
    expect(taskList?.type).toBe(markdownSchema.nodes.bullet_list);
    expect(taskList?.firstChild?.attrs.checked).toBe(false);

    const tableEditor = createView();
    for (const key of ["/", "t", "a", "b", "l", "e", "Enter"]) {
      expect(press(tableEditor.view, key)).toBe(true);
    }
    await flushMicrotasks();

    const table = tableEditor.view.state.doc.firstChild;
    expect(table?.type).toBe(markdownSchema.nodes.table);
    expect(table?.childCount).toBe(3);
    expect(table?.firstChild?.childCount).toBe(3);
  });
});
