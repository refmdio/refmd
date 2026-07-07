import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

async function loadSelection() {
  vi.resetModules();
  return import("./selection");
}

describe("workspace selection", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("prevents a discarded workspace from being reselected by stale async state", async () => {
    const { currentWorkspaceId, discardWorkspaceSelection, setCurrentWorkspaceId } =
      await loadSelection();

    setCurrentWorkspaceId("workspace-left");
    expect(currentWorkspaceId()).toBe("workspace-left");
    expect(localStorage.getItem("refmd_workspace_id")).toBe("workspace-left");

    discardWorkspaceSelection("workspace-left");
    expect(currentWorkspaceId()).toBeNull();
    expect(localStorage.getItem("refmd_workspace_id")).toBeNull();

    setCurrentWorkspaceId("workspace-left");
    expect(currentWorkspaceId()).toBeNull();
    expect(localStorage.getItem("refmd_workspace_id")).toBeNull();

    setCurrentWorkspaceId("workspace-other");
    expect(currentWorkspaceId()).toBe("workspace-other");
    expect(localStorage.getItem("refmd_workspace_id")).toBe("workspace-other");
  });
});
