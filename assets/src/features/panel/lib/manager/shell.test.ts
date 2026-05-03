import { describe, expect, it } from "vitest";
import { ShellState } from "./shell";

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
});
