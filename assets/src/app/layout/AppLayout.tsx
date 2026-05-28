import { Show, createSignal, type ParentProps } from "solid-js";
import { Sidebar } from "@/widgets/sidebar";
import { SettingsDialog } from "@/widgets/settings";
import { Toaster } from "@/shared/ui/sonner";
import { Button } from "@/shared/ui/button";
import { PluginUiModalHost } from "./PluginUiModalHost";
import { BellIcon } from "lucide-solid";

interface WorkspaceSummary {
  id: string;
  name: string;
}

interface CreateWorkspaceInput {
  name: string;
  description?: string;
  icon?: string;
}

interface AppLayoutProps extends ParentProps {
  workspaces: WorkspaceSummary[];
  currentWorkspaceId: string | null;
  securityNotificationCount: number;
  onSelectWorkspace: (workspaceId: string) => void;
  onCreateWorkspace: (data: CreateWorkspaceInput) => Promise<void>;
  beginPluginRuntimeApplicationRevocation?: (applicationId: string) => void;
  closePluginRuntimeByApplication?: (
    applicationId: string,
    reason?: string,
  ) => void | Promise<void>;
  releasePluginRuntimeApplicationRevocation?: (applicationId: string) => void;
  closePluginRuntimeByWorkspace?: (workspaceId: string, reason?: string) => void | Promise<void>;
  releasePluginRuntimeWorkspaceRevocation?: (workspaceId: string) => void;
}

export function AppLayout(props: AppLayoutProps) {
  const [settingsOpen, setSettingsOpen] = createSignal(false);
  const [settingsInitialTab, setSettingsInitialTab] = createSignal("about");

  const openSettings = (tab = "about") => {
    setSettingsInitialTab(tab);
    setSettingsOpen(true);
  };

  const notificationSlot = () => (
    <Show when={props.securityNotificationCount > 0}>
      <Button
        variant="ghost"
        size="icon"
        class="size-9 relative"
        onClick={() => openSettings("security")}
        aria-label="Action-required security notifications"
      >
        <BellIcon class="size-4" />
        <span class="absolute -top-0.5 -right-0.5 size-4 rounded-full bg-destructive text-destructive-foreground text-[10px] flex items-center justify-center">
          {props.securityNotificationCount}
        </span>
      </Button>
    </Show>
  );

  return (
    <div class="flex h-screen">
      <Toaster position="bottom-right" />
      <Sidebar
        workspaces={props.workspaces}
        currentWorkspaceId={props.currentWorkspaceId}
        onSelectWorkspace={props.onSelectWorkspace}
        onCreateWorkspace={props.onCreateWorkspace}
        notificationSlot={notificationSlot()}
        onSettingsClick={() => openSettings()}
      />
      <div class="flex-1 overflow-hidden">{props.children}</div>
      <PluginUiModalHost />
      <SettingsDialog
        open={settingsOpen()}
        onOpenChange={setSettingsOpen}
        initialTab={settingsInitialTab()}
        beginPluginRuntimeApplicationRevocation={props.beginPluginRuntimeApplicationRevocation}
        closePluginRuntimeByApplication={props.closePluginRuntimeByApplication}
        releasePluginRuntimeApplicationRevocation={props.releasePluginRuntimeApplicationRevocation}
        closePluginRuntimeByWorkspace={props.closePluginRuntimeByWorkspace}
        releasePluginRuntimeWorkspaceRevocation={props.releasePluginRuntimeWorkspaceRevocation}
      />
    </div>
  );
}
