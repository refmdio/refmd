import { createSignal, For, Show, type JSX } from "solid-js";
import { ChevronsUpDownIcon, CheckIcon, PlusIcon, SettingsIcon } from "lucide-solid";
import { Button } from "@/shared/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";

interface Workspace {
  id: string;
  name: string;
}

interface CreateWorkspaceData {
  name: string;
  description?: string;
  icon?: string;
}

interface UserMenuProps {
  workspaces: Workspace[];
  currentWorkspaceId: string | null;
  onSelectWorkspace: (workspaceId: string) => void;
  onCreateWorkspace: (data: CreateWorkspaceData) => Promise<void>;
  notificationSlot?: JSX.Element;
  onSettingsClick: () => void;
}

function formatWorkspaceName(name: string) {
  return name.replace(/'s workspace$/i, "");
}

export function UserMenu(props: UserMenuProps) {
  const [createOpen, setCreateOpen] = createSignal(false);
  const [createName, setCreateName] = createSignal("");
  const [createDescription, setCreateDescription] = createSignal("");
  const [createIcon, setCreateIcon] = createSignal("");
  const [creating, setCreating] = createSignal(false);

  const currentWorkspace = () => props.workspaces.find((w) => w.id === props.currentWorkspaceId);

  const displayName = () => {
    const ws = currentWorkspace();
    return ws ? formatWorkspaceName(ws.name) : "Select workspace";
  };

  const handleCreate = async () => {
    const name = createName().trim();
    if (!name) return;
    setCreating(true);
    try {
      const data: CreateWorkspaceData = { name };
      const desc = createDescription().trim();
      const icon = createIcon().trim();
      if (desc) data.description = desc;
      if (icon) data.icon = icon;
      await props.onCreateWorkspace(data);
      setCreateOpen(false);
      setCreateName("");
      setCreateDescription("");
      setCreateIcon("");
    } finally {
      setCreating(false);
    }
  };

  return (
    <div class="border-t border-border px-2 py-1">
      <div class="flex items-center gap-1">
        <DropdownMenu>
          <DropdownMenuTrigger
            as={(triggerProps: JSX.ButtonHTMLAttributes<HTMLButtonElement>) => (
              <Button
                variant="ghost"
                class="flex-1 justify-start px-3 py-2 h-auto font-sans normal-case tracking-normal text-xs"
                {...triggerProps}
              >
                <span class="flex items-center gap-2">
                  <ChevronsUpDownIcon class="size-4 shrink-0 opacity-50" />
                  <span class="truncate font-bold">{displayName()}</span>
                </span>
              </Button>
            )}
          />
          <DropdownMenuContent class="w-56">
            <For each={props.workspaces}>
              {(ws) => (
                <DropdownMenuItem
                  onSelect={() => props.onSelectWorkspace(ws.id)}
                  class="font-sans text-sm normal-case tracking-normal"
                >
                  <span class="flex-1 truncate">{formatWorkspaceName(ws.name)}</span>
                  <Show when={ws.id === props.currentWorkspaceId}>
                    <CheckIcon class="size-4 shrink-0" />
                  </Show>
                </DropdownMenuItem>
              )}
            </For>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onSelect={() => setCreateOpen(true)}
              class="font-sans text-sm normal-case tracking-normal"
            >
              <PlusIcon class="size-4 mr-2" />
              New workspace
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {props.notificationSlot}

        <Button
          variant="ghost"
          size="icon"
          class="size-9"
          onClick={props.onSettingsClick}
          aria-label="Settings"
        >
          <SettingsIcon class="size-4" />
        </Button>
      </div>

      <Dialog open={createOpen()} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Workspace</DialogTitle>
            <DialogDescription>
              Create a new workspace to collaborate with others.
            </DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel for="new-workspace-name">Name</FieldLabel>
            <Input
              id="new-workspace-name"
              placeholder="My Workspace"
              value={createName()}
              onInput={(e) => setCreateName(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handleCreate();
              }}
            />
          </Field>
          <Field>
            <FieldLabel for="new-workspace-description">Description</FieldLabel>
            <Input
              id="new-workspace-description"
              placeholder="Optional description"
              value={createDescription()}
              onInput={(e) => setCreateDescription(e.currentTarget.value)}
            />
          </Field>
          <Field>
            <FieldLabel for="new-workspace-icon">Icon</FieldLabel>
            <Input
              id="new-workspace-icon"
              placeholder="Optional icon (e.g. emoji)"
              value={createIcon()}
              onInput={(e) => setCreateIcon(e.currentTarget.value)}
            />
          </Field>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreate} disabled={creating() || !createName().trim()}>
              {creating() ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
