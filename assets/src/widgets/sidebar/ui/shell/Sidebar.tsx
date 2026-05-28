import { createEffect, For, getOwner, onCleanup, Show, type JSX } from "solid-js";
import { UserMenu } from "../user-menu/UserMenu";
import { workspaceManager } from "@/features/panel";
import { withPluginRenderOwner } from "@/features/plugin-runtime";
import { Button } from "@/shared/ui/button";

interface Workspace {
  id: string;
  name: string;
}

interface SidebarProps {
  workspaces: Workspace[];
  currentWorkspaceId: string | null;
  onSelectWorkspace: (workspaceId: string) => void;
  onCreateWorkspace: (data: { name: string; description?: string; icon?: string }) => Promise<void>;
  notificationSlot?: JSX.Element;
  onSettingsClick: () => void;
}

export function Sidebar(props: SidebarProps) {
  const pluginOwner = getOwner();
  const panels = workspaceManager.getSidebarPanels();
  const activePanelId = workspaceManager.getActiveSidebarPanelId();
  let containerRef: HTMLDivElement | undefined;
  let mountedNodes: Node[] = [];
  let mountedCleanup: (() => void) | undefined;
  let mountToken = 0;

  function clearMounted() {
    mountedCleanup?.();
    mountedCleanup = undefined;
    const container = containerRef;
    for (const node of mountedNodes) {
      if (container?.contains(node)) {
        container.removeChild(node);
      }
    }
    mountedNodes = [];
  }

  function mountPanel() {
    if (!containerRef) return;
    const container = containerRef;
    clearMounted();

    const panelId = activePanelId();
    const wsId = props.currentWorkspaceId;
    const activePanel = panels().find((p) => p.id === panelId) ?? null;
    if (!activePanel || !wsId) return;

    withPluginRenderOwner(pluginOwner, () => {
      if (activePanel.render) {
        const slot = document.createElement("div");
        slot.className = "flex-1 min-h-0 overflow-hidden flex flex-col";
        slot.dataset.sidebarPanelSlot = activePanel.id;
        container.appendChild(slot);
        mountedNodes = [slot];
        mountedCleanup = activePanel.hide;
        activePanel.render(slot);
      } else if (activePanel.viewType) {
        const leaf = workspaceManager.getSidebarLeaf(activePanel.viewType);
        if (leaf?.view?.containerEl) {
          container.appendChild(leaf.view.containerEl);
          mountedNodes = [leaf.view.containerEl];
        }
      }
    });
  }

  function scheduleMountPanel() {
    const token = ++mountToken;
    queueMicrotask(() => {
      if (token === mountToken) mountPanel();
    });
  }

  createEffect(() => {
    const mountInputs = [activePanelId(), panels(), props.currentWorkspaceId] as const;
    void mountInputs;
    scheduleMountPanel();
  });

  onCleanup(clearMounted);

  return (
    <aside class="w-64 border-r border-border h-full flex flex-col bg-sidebar">
      <Show when={panels().length > 1}>
        <div class="flex shrink-0 items-center gap-1 border-b border-sidebar-border px-2 py-1">
          <For each={panels()}>
            {(panel) => (
              <Button
                type="button"
                variant={activePanelId() === panel.id ? "secondary" : "ghost"}
                size="sm"
                class="h-7 min-w-0 flex-1 px-2 text-xs"
                title={panel.title ?? panel.id}
                aria-label={panel.title ?? panel.id}
                onClick={() => workspaceManager.setActiveSidebarPanel(panel.id)}
              >
                <span class="truncate">{panel.title ?? panel.id}</span>
              </Button>
            )}
          </For>
        </div>
      </Show>
      <div
        ref={(el) => {
          containerRef = el;
          mountPanel();
        }}
        onFocusIn={() => {
          const panelId = activePanelId();
          if (!panelId) return;
          const panel = panels().find((p) => p.id === panelId);
          if (!panel?.viewType) return;
          const leaf = workspaceManager.getSidebarLeaf(panel.viewType);
          if (leaf) workspaceManager.setActiveLeaf(leaf);
        }}
        class="flex-1 overflow-hidden flex flex-col"
      />

      <UserMenu
        workspaces={props.workspaces}
        currentWorkspaceId={props.currentWorkspaceId}
        onSelectWorkspace={props.onSelectWorkspace}
        onCreateWorkspace={props.onCreateWorkspace}
        notificationSlot={props.notificationSlot}
        onSettingsClick={props.onSettingsClick}
      />
    </aside>
  );
}
