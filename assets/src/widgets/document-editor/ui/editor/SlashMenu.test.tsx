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

function renderSlashMenu(
  state: SlashMenuState,
  handlers: {
    onDismiss?: () => void;
    onSelect?: (command: SlashCommand) => void;
    prepareView?: (view: EditorView) => void;
  } = {},
) {
  vi.stubGlobal("ResizeObserver", ResizeObserverMock);
  Element.prototype.scrollIntoView = vi.fn();
  const view = createView();
  handlers.prepareView?.(view);
  const dispose = render(
    () => (
      <SlashMenu
        view={view}
        slashState={state}
        onDismiss={handlers.onDismiss ?? (() => undefined)}
        onSelect={handlers.onSelect ?? (() => undefined)}
      />
    ),
    document.body,
  );
  cleanupFns.push(dispose);
  return view;
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
    expect(options[0].getAttribute("data-slot")).toBe("command-item");
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

  it("dismisses when Escape is pressed from a focused option", async () => {
    const onDismiss = vi.fn();
    renderSlashMenu(
      {
        active: true,
        commands: [command("Heading 1", "h1")],
        pos: 1,
        query: "",
        selectedIndex: 0,
      },
      { onDismiss },
    );
    await flush();

    const option = document.querySelector<HTMLElement>('[role="option"]');
    option?.focus();
    option?.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "Escape" }));

    expect(onDismiss).toHaveBeenCalledOnce();
  });

  it("positions virtual block menus below the handled block", async () => {
    const block = document.createElement("p");
    block.getBoundingClientRect = vi.fn(
      () =>
        ({
          bottom: 260,
          height: 40,
          left: 120,
          right: 520,
          top: 220,
          width: 400,
          x: 120,
          y: 220,
          toJSON: () => ({}),
        }) as DOMRect,
    );

    renderSlashMenu(
      {
        active: true,
        commands: [command("Heading 1", "h1")],
        insertAfterBlockPos: 0,
        mode: "virtual",
        pos: 1,
        query: "",
        selectedIndex: 0,
      },
      {
        prepareView: (view) => {
          vi.spyOn(view, "nodeDOM").mockReturnValue(block);
          vi.spyOn(view, "coordsAtPos").mockImplementation(() => {
            throw new Error("stale ProseMirror position");
          });
        },
      },
    );
    await flush();

    const menu = document.querySelector<HTMLElement>(".refmd-slash-menu");
    expect(Number.parseFloat(menu?.style.left ?? "0")).toBe(120);
    expect(Number.parseFloat(menu?.style.top ?? "0")).toBe(264);
  });

  it("dismisses text slash menus when no caret or block anchor is available", async () => {
    const onDismiss = vi.fn();
    renderSlashMenu(
      {
        active: true,
        commands: [command("Heading 1", "h1")],
        mode: "text",
        pos: 1,
        query: "",
        selectedIndex: 0,
      },
      {
        onDismiss,
        prepareView: (view) => {
          vi.spyOn(view, "coordsAtPos").mockImplementation(() => {
            throw new Error("stale ProseMirror position");
          });
          vi.spyOn(view, "domAtPos").mockImplementation(() => {
            throw new Error("stale ProseMirror DOM position");
          });
        },
      },
    );
    await flush();
    await flush();

    const menu = document.querySelector<HTMLElement>(".refmd-slash-menu");
    expect(menu?.style.visibility).toBe("hidden");
    expect(onDismiss).toHaveBeenCalledOnce();
  });
});
