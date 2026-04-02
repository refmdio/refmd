import { Show, createSignal, type ParentProps } from "solid-js";
import { Sidebar } from "@/widgets/sidebar";
import { SettingsDialog } from "@/widgets/settings";
import { Toaster } from "@/shared/ui/sonner";
import { Button } from "@/shared/ui/button";
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
  pendingDeviceCount: number;
  onSelectWorkspace: (workspaceId: string) => void;
  onCreateWorkspace: (data: CreateWorkspaceInput) => Promise<void>;
}

export function AppLayout(props: AppLayoutProps) {
  const [settingsOpen, setSettingsOpen] = createSignal(false);

  const notificationSlot = () => (
    <Show when={props.pendingDeviceCount > 0}>
      <Button
        variant="ghost"
        size="icon"
        class="size-9 relative"
        onClick={() => setSettingsOpen(true)}
        aria-label="Pending device approvals"
      >
        <BellIcon class="size-4" />
        <span class="absolute -top-0.5 -right-0.5 size-4 rounded-full bg-destructive text-destructive-foreground text-[10px] flex items-center justify-center">
          {props.pendingDeviceCount}
        </span>
      </Button>
    </Show>
  );

  return (
    <div class="flex h-screen">
      <Sidebar
        workspaces={props.workspaces}
        currentWorkspaceId={props.currentWorkspaceId}
        onSelectWorkspace={props.onSelectWorkspace}
        onCreateWorkspace={props.onCreateWorkspace}
        notificationSlot={notificationSlot()}
        onSettingsClick={() => setSettingsOpen(true)}
      />
      <div class="flex-1 overflow-hidden">{props.children}</div>
      <SettingsDialog open={settingsOpen()} onOpenChange={setSettingsOpen} />
      <Toaster position="bottom-right" />
    </div>
  );
}
