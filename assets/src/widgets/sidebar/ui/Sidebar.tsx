import { createEffect, onCleanup, type JSX } from "solid-js";
import { UserMenu } from "./UserMenu";
import { workspaceManager } from "@/features/panel";

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
  const panels = workspaceManager.getSidebarPanels();
  const activePanelId = workspaceManager.getActiveSidebarPanelId();
  let containerRef: HTMLDivElement | undefined;
  let mountedEl: HTMLElement | null = null;

  function clearMounted() {
    if (mountedEl && containerRef?.contains(mountedEl)) {
      containerRef.removeChild(mountedEl);
    }
    mountedEl = null;
  }

  function mountPanel() {
    if (!containerRef) return;
    clearMounted();

    const panelId = activePanelId();
    const wsId = props.currentWorkspaceId;
    const activePanel = panels().find((p) => p.id === panelId) ?? null;
    if (!activePanel || !wsId) return;

    if (activePanel.render) {
      activePanel.render(containerRef);
    } else if (activePanel.viewType) {
      const leaf = workspaceManager.getSidebarLeaf(activePanel.viewType);
      if (leaf?.view?.containerEl) {
        containerRef.appendChild(leaf.view.containerEl);
        mountedEl = leaf.view.containerEl;
      }
    }
  }

  createEffect(mountPanel);

  onCleanup(clearMounted);

  return (
    <aside class="w-64 border-r border-border h-full flex flex-col bg-sidebar">
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
