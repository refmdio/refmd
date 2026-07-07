import { createSignal } from "solid-js";
import { render } from "solid-js/web";
import { Mosaic } from "solid-mosaic-component";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { disposePanelWorkspace, workspaceManager, type usePanelWorkspace } from "@/features/panel";
import type { AuxiliaryPaneConfig } from "@/shared/lib/workspace/app";
import { PluginWorkspaceTile } from "../tile/PluginWorkspaceTile";
import { AuxiliaryPaneColumn } from "./AuxiliaryPaneColumn";

type Workspace = ReturnType<typeof usePanelWorkspace>;
type WorkspaceTileOpenGuard = () => boolean | Promise<boolean>;

describe("DocumentWorkspace auxiliary pane chrome", () => {
  afterEach(() => {
    workspaceManager.reset();
    disposePanelWorkspace();
    document.body.replaceChildren();
  });

  it("renders Host-owned focus, resize, and close controls around plugin pane content", async () => {
    const renderPane = vi.fn((container: HTMLElement) => {
      container.textContent = "plugin pane body";
    });
    const hidePane = vi.fn();
    const closePane = vi.fn(() => workspaceManager.removeAuxiliaryPane("plugin-comments"));
    const invokeAction = vi.fn();
    const pane = {
      id: "plugin-comments",
      title: "Comments",
      allowedLocations: ["document_right"],
      defaultWidth: 300,
      actions: [
        {
          id: "plugin-comments:send",
          title: "Send",
          invoke: invokeAction,
          isAvailable: () => true,
        },
      ],
      render: renderPane,
      hide: hidePane,
      close: closePane,
    } satisfies AuxiliaryPaneConfig;
    workspaceManager.addAuxiliaryPane(pane);

    const root = document.createElement("div");
    root.style.height = "600px";
    document.body.append(root);
    const dispose = render(() => {
      const [focusedPaneId, setFocusedPaneId] = createSignal<string | null>(null);
      const [width, setWidth] = createSignal<number | undefined>(undefined);
      return (
        <AuxiliaryPaneColumn
          panes={workspaceManager.getAuxiliaryPanes()}
          location="document_right"
          focusedPaneId={focusedPaneId()}
          setFocusedPaneId={setFocusedPaneId}
          width={width()}
          setWidth={setWidth}
        />
      );
    }, root);

    await Promise.resolve();

    const paneBody = root.querySelector<HTMLElement>("[data-auxiliary-pane-id='plugin-comments']");
    expect(paneBody?.textContent).toBe("plugin pane body");
    expect(renderPane).toHaveBeenCalledOnce();

    const section = paneBody?.closest<HTMLElement>("section");
    expect(section?.dataset.auxiliaryPaneFocused).toBe("false");
    section?.dispatchEvent(new FocusEvent("focusin", { bubbles: true }));
    expect(section?.dataset.auxiliaryPaneFocused).toBe("true");

    const column = root.querySelector<HTMLElement>(
      "[data-auxiliary-pane-location='document_right']",
    );
    expect(column?.style.width).toBe("300px");
    const actionButton = root.querySelector<HTMLElement>(
      "[data-auxiliary-pane-action='plugin-comments:send']",
    );
    expect(actionButton?.textContent?.trim()).toBe("Send");
    actionButton?.click();
    expect(invokeAction).toHaveBeenCalledOnce();

    const handle = root.querySelector<HTMLElement>(
      "[data-auxiliary-pane-resize-handle='document_right']",
    );
    handle?.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, clientX: 300 }));
    window.dispatchEvent(new MouseEvent("pointermove", { clientX: 250 }));
    window.dispatchEvent(new MouseEvent("pointerup"));
    expect(column?.style.width).toBe("350px");

    root.querySelector<HTMLElement>("[data-auxiliary-pane-close='plugin-comments']")?.click();
    expect(closePane).toHaveBeenCalledOnce();
    expect(workspaceManager.getAuxiliaryPanes()).toEqual([]);
    expect(root.querySelector("[data-auxiliary-pane-id='plugin-comments']")).toBeNull();
    expect(hidePane).toHaveBeenCalledOnce();

    dispose();
  });
});

describe("DocumentWorkspace plugin workspace tile chrome", () => {
  const deniedWorkspaceTileOpenGuards: Array<[string, WorkspaceTileOpenGuard]> = [
    ["denies", () => false],
    ["rejects", () => Promise.reject(new Error("audit denied"))],
  ];

  afterEach(() => {
    workspaceManager.reset();
    disposePanelWorkspace();
    document.body.replaceChildren();
  });

  it("renders workspace tile actions in their Host-owned placements", async () => {
    const panelId = "plugin:workspace:plugin.tile:document-one:instance-one:action-one";
    const openTile = vi.fn(() => true);
    const invokeWorkspaceTileAction = vi.fn();
    const workspace = {
      closePanel: vi.fn(),
      consumeWorkspaceTileAction: vi.fn(() => undefined),
      focusPanel: vi.fn(),
      invokeWorkspaceTileAction,
      splitPanel: vi.fn(),
    } as unknown as Workspace;
    workspaceManager.addWorkspaceTile({
      id: "plugin.tile",
      tileId: "plugin.tile",
      title: "Plugin Tile",
      scope: "document",
      preferredOpen: "document_menu",
      actions: () => [
        {
          id: "plugin.tile:menu",
          actionId: "menu-action",
          title: "Menu Action",
          placement: "tile_menu",
          order: 20,
        },
        {
          id: "plugin.tile:refresh",
          actionId: "refresh-action",
          title: "Refresh Action",
          placement: "refresh",
          order: 10,
        },
        {
          id: "plugin.tile:toolbar",
          actionId: "toolbar-action",
          title: "Toolbar Action",
          placement: "tile_toolbar",
          order: 5,
        },
      ],
      open: openTile,
      render(container) {
        container.textContent = "plugin tile body";
      },
    });

    const root = document.createElement("div");
    root.style.height = "600px";
    document.body.append(root);
    const dispose = render(
      () => (
        <Mosaic<string>
          value={panelId}
          onChange={() => undefined}
          renderTile={(tileId, path) => (
            <PluginWorkspaceTile panelId={tileId} path={path} workspace={workspace} />
          )}
        />
      ),
      root,
    );

    await Promise.resolve();

    const refreshButton = root.querySelector<HTMLElement>(
      "[data-workspace-tile-action='plugin.tile:refresh'][data-workspace-tile-action-placement='refresh']",
    );
    expect(refreshButton?.getAttribute("aria-label")).toBe("Refresh Action");
    const toolbarButton = root.querySelector<HTMLElement>(
      "[data-workspace-tile-action='plugin.tile:toolbar'][data-workspace-tile-action-placement='tile_toolbar']",
    );
    expect(toolbarButton?.textContent?.trim()).toBe("Toolbar Action");

    refreshButton?.click();
    await waitForMenuAction();
    expect(openTile).toHaveBeenNthCalledWith(1, {
      resourceKind: "document",
      workspaceId: undefined,
      documentId: "document-one",
      documentOpen: true,
      selectionPresent: false,
    });
    expect(invokeWorkspaceTileAction).toHaveBeenNthCalledWith(1, panelId, {
      tileActionId: "refresh-action",
    });

    toolbarButton?.click();
    await waitForMenuAction();
    expect(invokeWorkspaceTileAction).toHaveBeenNthCalledWith(2, panelId, {
      tileActionId: "toolbar-action",
    });

    const menuItems = await openPluginTileMenu(root);
    expect(menuItems.map((item) => item.textContent?.trim())).toEqual([
      "Menu Action",
      "Split Horizontal",
      "Split Vertical",
      "Close",
    ]);
    menuItems[0]?.click();
    await waitForMenuAction();
    expect(invokeWorkspaceTileAction).toHaveBeenNthCalledWith(3, panelId, {
      tileActionId: "menu-action",
    });

    dispose();
  });

  it("runs the workspace tile open guard before Host-owned split controls", async () => {
    const panelId = "plugin:workspace:plugin.tile:document-one:instance-one:action-one";
    const openTile = vi.fn(() => true);
    const splitPanel = vi.fn();
    const closePanel = vi.fn();
    const workspace = {
      closePanel,
      consumeWorkspaceTileAction: vi.fn(() => undefined),
      focusPanel: vi.fn(),
      splitPanel,
    } as unknown as Workspace;
    workspaceManager.addWorkspaceTile({
      id: "plugin.tile",
      tileId: "plugin.tile",
      title: "Plugin Tile",
      scope: "document",
      preferredOpen: "document_menu",
      open: openTile,
      render(container) {
        container.textContent = "plugin tile body";
      },
    });

    const root = document.createElement("div");
    root.style.height = "600px";
    document.body.append(root);
    const dispose = render(
      () => (
        <Mosaic<string>
          value={panelId}
          onChange={() => undefined}
          renderTile={(tileId, path) => (
            <PluginWorkspaceTile panelId={tileId} path={path} workspace={workspace} />
          )}
        />
      ),
      root,
    );

    await Promise.resolve();

    expect(root.querySelector("[data-panel-id^='plugin:workspace']")?.textContent).toContain(
      "plugin tile body",
    );
    let menuItems = await openPluginTileMenu(root);
    expect(menuItems.map((item) => item.textContent?.trim())).toEqual([
      "Split Horizontal",
      "Split Vertical",
      "Close",
    ]);

    menuItems[0]?.click();
    await waitForMenuAction();
    expect(openTile).toHaveBeenNthCalledWith(1, {
      resourceKind: "document",
      workspaceId: undefined,
      documentId: "document-one",
      documentOpen: true,
      selectionPresent: false,
    });
    expect(splitPanel).toHaveBeenCalledWith(panelId, "row");
    expect(openTile.mock.invocationCallOrder[0]).toBeLessThan(
      splitPanel.mock.invocationCallOrder[0],
    );
    menuItems = await openPluginTileMenu(root);
    menuItems[1]?.click();
    await waitForMenuAction();
    expect(splitPanel).toHaveBeenCalledWith(panelId, "column");
    menuItems = await openPluginTileMenu(root);
    menuItems[2]?.click();
    expect(closePanel).toHaveBeenCalledWith(panelId);

    dispose();
  });

  it.each(deniedWorkspaceTileOpenGuards)(
    "does not split when the workspace tile open guard %s",
    async (_, guard) => {
      const panelId = "plugin:workspace:plugin.tile:document-one:instance-one:action-one";
      const openTile = vi.fn(guard);
      const splitPanel = vi.fn();
      const workspace = {
        closePanel: vi.fn(),
        consumeWorkspaceTileAction: vi.fn(() => undefined),
        focusPanel: vi.fn(),
        splitPanel,
      } as unknown as Workspace;
      workspaceManager.addWorkspaceTile({
        id: "plugin.tile",
        tileId: "plugin.tile",
        title: "Plugin Tile",
        scope: "document",
        preferredOpen: "document_menu",
        open: openTile,
        render(container) {
          container.textContent = "plugin tile body";
        },
      });

      const root = document.createElement("div");
      root.style.height = "600px";
      document.body.append(root);
      const dispose = render(
        () => (
          <Mosaic<string>
            value={panelId}
            onChange={() => undefined}
            renderTile={(tileId, path) => (
              <PluginWorkspaceTile panelId={tileId} path={path} workspace={workspace} />
            )}
          />
        ),
        root,
      );

      await Promise.resolve();

      const menuItems = await openPluginTileMenu(root);
      menuItems[0]?.click();
      await waitForMenuAction();

      expect(openTile).toHaveBeenCalledOnce();
      expect(splitPanel).not.toHaveBeenCalled();

      dispose();
    },
  );
});

async function openPluginTileMenu(root: HTMLElement): Promise<HTMLElement[]> {
  const currentContent = openDropdownMenuContent();
  if (currentContent) {
    return Array.from(
      currentContent.querySelectorAll<HTMLElement>("[data-slot='dropdown-menu-item']"),
    );
  }

  const trigger = root.querySelector<HTMLElement>("[data-slot='dropdown-menu-trigger']");
  trigger?.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true }));
  trigger?.dispatchEvent(new PointerEvent("pointerup", { bubbles: true }));
  trigger?.click();
  const content = await waitForOpenDropdownMenuContent();
  return Array.from(content.querySelectorAll<HTMLElement>("[data-slot='dropdown-menu-item']"));
}

async function waitForMenuAction(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function waitForOpenDropdownMenuContent(): Promise<HTMLElement> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const content = openDropdownMenuContent();
    if (content) return content;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("Dropdown menu content did not open");
}

function openDropdownMenuContent(): HTMLElement | null {
  const contents = Array.from(
    document.body.querySelectorAll<HTMLElement>("[data-slot='dropdown-menu-content']"),
  );
  for (let index = contents.length - 1; index >= 0; index -= 1) {
    const content = contents[index];
    if (content?.hasAttribute("data-expanded")) return content;
  }
  return null;
}
