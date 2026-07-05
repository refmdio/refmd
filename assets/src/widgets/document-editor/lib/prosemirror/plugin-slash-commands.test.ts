import { afterEach, describe, expect, it } from "vitest";
import { EditorState } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { buildCollabPlugins } from "./plugin-base";
import { type SlashMenuState, slashCommandsPlugin } from "./plugin-slash-commands";
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

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe("slash commands ProseMirror plugin", () => {
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

  it("keeps the menu active for an empty result set instead of leaking input to the editor", () => {
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
    expect(press(view, "Enter")).toBe(true);
    expect(slashState().active).toBe(true);
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
