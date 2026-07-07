import { render } from "solid-js/web";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { disposePanelWorkspace, workspaceManager } from "@/features/panel";
import { View, type WorkspaceLeaf } from "@/shared/lib/workspace/view";
import { Sidebar } from "./Sidebar";

class TestSidebarView extends View {
  constructor(leaf: WorkspaceLeaf) {
    super(leaf);
    this.containerEl.dataset.testid = "built-in-sidebar";
    this.containerEl.textContent = "built-in sidebar";
  }

  getViewType(): string {
    return "document-tree";
  }

  getDisplayText(): string {
    return "Document Tree";
  }
}

describe("Sidebar plugin panel cleanup", () => {
  afterEach(() => {
    workspaceManager.reset();
    disposePanelWorkspace();
    document.body.replaceChildren();
  });

  it("clears plugin-rendered sidebar content when switching to a built-in view panel", async () => {
    const renderPluginPanel = vi.fn((container: HTMLElement) => {
      const frame = document.createElement("iframe");
      frame.dataset.testid = "plugin-sidebar-frame";
      container.append(frame);
    });
    workspaceManager.addSidebarPanel({
      id: "plugin-sidebar",
      title: "Plugin Sidebar",
      render: renderPluginPanel,
    });
    workspaceManager.registerView("document-tree", (leaf) => new TestSidebarView(leaf));
    workspaceManager.addSidebarPanel({
      id: "document-tree",
      title: "Document Tree",
      viewType: "document-tree",
    });

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(
      () => (
        <Sidebar
          workspaces={[{ id: "workspace-one", name: "Workspace One" }]}
          currentWorkspaceId="workspace-one"
          onSelectWorkspace={() => undefined}
          onCreateWorkspace={async () => undefined}
          onSettingsClick={() => undefined}
        />
      ),
      root,
    );

    await flushMicrotasks();

    expect(renderPluginPanel).toHaveBeenCalled();
    expect(root.querySelectorAll("[data-testid='plugin-sidebar-frame']")).toHaveLength(1);

    workspaceManager.setActiveSidebarPanel("document-tree");
    await flushMicrotasks();

    expect(root.querySelector("[data-testid='plugin-sidebar-frame']")).toBeNull();
    expect(root.querySelector("[data-testid='built-in-sidebar']")?.textContent).toBe(
      "built-in sidebar",
    );

    workspaceManager.setActiveSidebarPanel("plugin-sidebar");
    await flushMicrotasks();

    expect(root.querySelector("[data-testid='built-in-sidebar']")).toBeNull();
    expect(root.querySelectorAll("[data-testid='plugin-sidebar-frame']")).toHaveLength(1);

    dispose();
  });
});

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}
