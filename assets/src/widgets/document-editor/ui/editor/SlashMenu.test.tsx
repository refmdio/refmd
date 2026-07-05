import { render } from "solid-js/web";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EditorState } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { markdownSchema } from "../../lib/prosemirror/schema";
import type { SlashCommand, SlashMenuState } from "../../lib/prosemirror/plugin-slash-commands";
import { SlashMenu } from "./SlashMenu";

const cleanupFns: (() => void)[] = [];

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
  document.body.replaceChildren();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function createView(): EditorView {
  const container = document.createElement("div");
  document.body.append(container);
  const view = new EditorView(container, {
    state: EditorState.create({
      doc: markdownSchema.node("doc", null, [markdownSchema.nodes.paragraph.create()]),
    }),
  });
  vi.spyOn(view, "coordsAtPos").mockReturnValue({
    bottom: 0,
    left: 0,
    right: 0,
    top: 0,
  });
  cleanupFns.push(
    () => view.destroy(),
    () => container.remove(),
  );
  return view;
}

function command(label: string, shortcut: string): SlashCommand {
  return {
    category: "text",
    description: `${label} description`,
    execute: () => true,
    icon: "type",
    label,
    shortcut,
  };
}

function renderSlashMenu(state: SlashMenuState) {
  vi.stubGlobal("ResizeObserver", ResizeObserverMock);
  Element.prototype.scrollIntoView = vi.fn();
  const view = createView();
  const dispose = render(
    () => <SlashMenu view={view} slashState={state} onSelect={() => undefined} />,
    document.body,
  );
  cleanupFns.push(dispose);
}

describe("SlashMenu accessibility", () => {
  it("exposes listbox active option and result status semantics", async () => {
    renderSlashMenu({
      active: true,
      commands: [command("Heading 1", "h1"), command("Heading 2", "h2")],
      pos: 1,
      query: "h",
      selectedIndex: 1,
    });
    await flush();

    const listbox = document.querySelector<HTMLElement>('[role="listbox"]');
    expect(listbox).toBeInstanceOf(HTMLElement);
    expect(listbox?.getAttribute("aria-describedby")).toBeTruthy();
    const activeId = listbox?.getAttribute("aria-activedescendant");
    expect(activeId).toBeTruthy();

    const options = [...document.querySelectorAll<HTMLElement>('[role="option"]')];
    expect(options).toHaveLength(2);
    expect(options[1].id).toBe(activeId);
    expect(options[1].getAttribute("aria-selected")).toBe("true");
    expect(options[0].getAttribute("aria-selected")).toBe("false");

    const status = document.getElementById(listbox!.getAttribute("aria-describedby")!);
    expect(status?.textContent).toContain("2 block commands available for h");
    expect(status?.textContent).toContain("Heading 2 selected");
  });

  it("announces the no-results state", async () => {
    renderSlashMenu({
      active: true,
      commands: [],
      pos: 1,
      query: "zzz",
      selectedIndex: 0,
    });
    await flush();

    const listbox = document.querySelector<HTMLElement>('[role="listbox"]');
    const status = document.getElementById(listbox!.getAttribute("aria-describedby")!);

    expect(listbox?.hasAttribute("aria-activedescendant")).toBe(false);
    expect(status?.textContent).toContain("No block commands match zzz");
    expect(document.querySelectorAll('[role="option"]')).toHaveLength(0);
  });
});
