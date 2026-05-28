import { describe, expect, it } from "vitest";
import type { WorkspaceSurfaceOwner } from "@/shared/lib/workspace/app";
import { ShellState } from "./shell";

const owner: WorkspaceSurfaceOwner = {
  kind: "built_in",
  workspaceId: "workspace-alpha",
  ownerId: "shell-test",
  generation: 1,
};

describe("ShellState", () => {
  it("keeps sidebar panel accessors valid after reset", () => {
    const shell = new ShellState();
    const panels = shell.sidebarPanelsAccessor;
    const activePanelId = shell.activeSidebarPanelIdAccessor;

    shell.addSidebarPanel({ id: "document-tree", title: "Document Tree" });
    expect(panels()).toEqual([{ id: "document-tree", title: "Document Tree" }]);
    expect(activePanelId()).toBe("document-tree");

    shell.reset();
    expect(panels()).toEqual([]);
    expect(activePanelId()).toBeNull();

    shell.addSidebarPanel({ id: "document-tree", title: "Document Tree" });
    expect(panels()).toEqual([{ id: "document-tree", title: "Document Tree" }]);
    expect(activePanelId()).toBe("document-tree");
  });

  it("switches between registered sidebar panels and ignores unknown panel ids", () => {
    const shell = new ShellState();
    const activePanelId = shell.activeSidebarPanelIdAccessor;

    shell.addSidebarPanel({ id: "document-tree", title: "Document Tree" });
    shell.addSidebarPanel({ id: "plugin-panel", title: "Plugin Panel" });

    expect(activePanelId()).toBe("document-tree");
    shell.setActiveSidebarPanel("plugin-panel");
    expect(activePanelId()).toBe("plugin-panel");
    shell.setActiveSidebarPanel("missing-panel");
    expect(activePanelId()).toBe("plugin-panel");
  });

  it("replaces same-id setting tabs and hides the stale tab", () => {
    const shell = new ShellState();
    const hidden: string[] = [];
    const firstContainer = document.createElement("div");
    const secondContainer = document.createElement("div");

    shell.addSettingTab({
      id: "plugin-settings",
      name: "Plugin Settings",
      owner,
      containerEl: firstContainer,
      display: () => undefined,
      hide: () => hidden.push("first"),
    });
    shell.addSettingTab({
      id: "plugin-settings",
      name: "Plugin Settings V2",
      owner: { ...owner, generation: 2 },
      containerEl: secondContainer,
      display: () => undefined,
      hide: () => hidden.push("second"),
    });

    expect(hidden).toEqual(["first"]);
    expect(shell.settingTabsAccessor()).toHaveLength(1);
    expect(shell.settingTabsAccessor()[0]).toMatchObject({
      id: "plugin-settings",
      name: "Plugin Settings V2",
      owner: { generation: 2 },
    });
    expect(shell.settingTabsAccessor()[0]?.containerEl).toBe(secondContainer);
  });

  it("removes shell surfaces by owner predicate", () => {
    const shell = new ShellState();
    const statusContainer = document.createElement("div");
    shell.setStatusBarContainer(statusContainer);
    const hidden: string[] = [];

    shell.addSidebarPanel({ id: "plugin-panel", title: "Plugin Panel", owner });
    shell.addSidebarPanel({
      id: "other-panel",
      title: "Other Panel",
      owner: { ...owner, workspaceId: "workspace-beta" },
    });
    shell.addWorkspaceTile({
      id: "plugin-workspace-tile",
      tileId: "plugin-workspace-tile",
      title: "Plugin Workspace Tile",
      owner,
      scope: "document",
      preferredOpen: "document_menu",
      render: () => undefined,
      hide: () => hidden.push("plugin-workspace-tile"),
    });
    shell.addWorkspaceTile({
      id: "other-workspace-tile",
      tileId: "other-workspace-tile",
      title: "Other Workspace Tile",
      owner: { ...owner, workspaceId: "workspace-beta" },
      scope: "document",
      preferredOpen: "document_menu",
      render: () => undefined,
    });
    shell.addAuxiliaryPane({
      id: "plugin-auxiliary-pane",
      title: "Plugin Auxiliary Pane",
      owner,
      allowedLocations: ["right"],
      render: () => undefined,
      hide: () => hidden.push("plugin-auxiliary-pane"),
    });
    shell.addAuxiliaryPane({
      id: "other-auxiliary-pane",
      title: "Other Auxiliary Pane",
      owner: { ...owner, workspaceId: "workspace-beta" },
      allowedLocations: ["right"],
      render: () => undefined,
      hide: () => hidden.push("other-auxiliary-pane"),
    });
    shell.addSettingTab({
      id: "plugin-settings",
      name: "Plugin Settings",
      owner,
      containerEl: document.createElement("div"),
      display: () => undefined,
      hide: () => hidden.push("plugin-settings"),
    });
    shell.addSettingTab({
      id: "other-settings",
      name: "Other Settings",
      owner: { ...owner, workspaceId: "workspace-beta" },
      containerEl: document.createElement("div"),
      display: () => undefined,
      hide: () => hidden.push("other-settings"),
    });
    shell.addStatusBarItem({ owner, label: "Plugin status" }).textContent = "plugin";
    shell.addStatusBarItem({
      owner: { ...owner, workspaceId: "workspace-beta" },
      label: "Other status",
    }).textContent = "other";

    expect(
      shell.removeSurfacesByOwner((candidate) => candidate.workspaceId === "workspace-alpha"),
    ).toEqual({
      sidebarViewTypes: ["plugin-panel"],
      workspaceTileIds: ["plugin-workspace-tile"],
    });

    expect(shell.sidebarPanelsAccessor().map((panel) => panel.id)).toEqual(["other-panel"]);
    expect(shell.workspaceTilesAccessor().map((panel) => panel.id)).toEqual([
      "other-workspace-tile",
    ]);
    expect(shell.auxiliaryPanesAccessor().map((pane) => pane.id)).toEqual(["other-auxiliary-pane"]);
    expect(shell.settingTabsAccessor().map((tab) => tab.id)).toEqual(["other-settings"]);
    expect(hidden).toEqual(["plugin-workspace-tile", "plugin-auxiliary-pane", "plugin-settings"]);
    expect(statusContainer.textContent).toBe("other");
  });

  it("rehomes live status items when the status bar container changes", () => {
    const shell = new ShellState();
    const firstContainer = document.createElement("div");
    const secondContainer = document.createElement("div");
    shell.setStatusBarContainer(firstContainer);

    const item = shell.addStatusBarItem({ owner, label: "Plugin status" });
    item.textContent = "ready";
    const removed = shell.addStatusBarItem({ owner, label: "Removed status" });
    removed.textContent = "removed";
    removed.remove();

    shell.setStatusBarContainer(secondContainer);

    expect(firstContainer.contains(item)).toBe(false);
    expect(secondContainer.contains(item)).toBe(true);
    expect(secondContainer.textContent).toBe("ready");
    expect(secondContainer.querySelector('[aria-label="Removed status"]')).toBeNull();
  });
});
