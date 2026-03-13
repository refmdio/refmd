import { Show } from "solid-js";
import { FilePlusIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { UserMenu } from "./UserMenu";

interface Workspace {
  id: string;
  name: string;
}

interface SidebarProps {
  workspaces: Workspace[];
  currentWorkspaceId: string | null;
  onSelectWorkspace: (workspaceId: string) => void;
  onCreateWorkspace: (data: { name: string; description?: string; icon?: string }) => Promise<void>;
  onCreateDocument?: () => void;
  notificationSlot?: any;
  onSettingsClick: () => void;
}

export function Sidebar(props: SidebarProps) {
  return (
    <aside class="w-64 border-r border-border h-full flex flex-col bg-sidebar">
      <Show when={props.currentWorkspaceId}>
        <div class="px-2 py-1 border-b border-border flex items-center justify-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            class="size-7"
            onClick={props.onCreateDocument}
          >
            <FilePlusIcon class="size-4" />
          </Button>
        </div>
      </Show>

      <div class="flex-1 overflow-hidden flex flex-col">
        <div class="flex-1 flex items-center justify-center">
          <p class="text-xs text-muted-foreground">No documents yet</p>
        </div>
      </div>

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
