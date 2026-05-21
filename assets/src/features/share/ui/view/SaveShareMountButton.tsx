import { For, Show, createSignal } from "solid-js";
import { CheckIcon, PlusIcon } from "lucide-solid";
import type { ShareLinkMount } from "@/entities/mount";
import { authState } from "@/entities/session";
import { Notice } from "@/shared/lib/notice";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { useSaveShareMount } from "../../model/view/use-save-share-mount";

interface SaveShareMountButtonProps {
  shareSlug: string;
  targetKind: "document" | "folder";
  targetToken: string | null;
  targetDocumentId?: string | null;
  targetTitle?: string | null;
  existingMounts?: ShareLinkMount[];
  size?: "sm" | "default";
  iconOnly?: boolean;
  class?: string;
  sessionAvailable?: boolean;
  onSaved?: () => void;
}

export function SaveShareMountButton(props: SaveShareMountButtonProps) {
  const state = useSaveShareMount(props);
  const [workspaceDialogOpen, setWorkspaceDialogOpen] = createSignal(false);

  const handleSave = async (event: Event) => {
    event.stopPropagation();
    if (!state.hasDestinationWorkspace()) {
      new Notice("No destination workspace");
      return;
    }
    if (state.canChooseWorkspace()) {
      setWorkspaceDialogOpen(true);
      return;
    }
    await state.save();
  };

  const saveToWorkspace = async (workspaceId: string) => {
    if (await state.save(workspaceId)) {
      setWorkspaceDialogOpen(false);
    }
  };

  const dialog = () => (
    <Dialog open={workspaceDialogOpen()} onOpenChange={setWorkspaceDialogOpen}>
      <DialogContent class="max-w-sm">
        <DialogHeader>
          <DialogTitle>Save to Workspace</DialogTitle>
          <DialogDescription>Choose a workspace for this saved share.</DialogDescription>
        </DialogHeader>
        <div class="grid gap-2">
          <For each={state.workspaces()}>
            {(workspace) => (
              <Button
                type="button"
                variant="outline"
                class="h-10 justify-start px-3 text-left"
                disabled={state.saving()}
                onClick={() => void saveToWorkspace(workspace.id)}
              >
                <span class="truncate">{workspace.name}</span>
              </Button>
            )}
          </For>
        </div>
      </DialogContent>
    </Dialog>
  );

  if (props.iconOnly) {
    return (
      <Show when={props.sessionAvailable ?? !!authState()}>
        <span
          onClick={(event) => {
            if (!state.hasDestinationWorkspace()) void handleSave(event);
          }}
        >
          <Button
            size="icon-sm"
            variant={state.isSaved() ? "secondary" : "ghost"}
            class={props.class}
            disabled={(!state.canSave() && !state.canChooseWorkspace()) || state.saving()}
            onClick={(event) => void handleSave(event)}
            title={state.title()}
            aria-label={state.title()}
          >
            <Show when={state.isSaved()} fallback={<PlusIcon class="size-3.5" />}>
              <CheckIcon class="size-3.5" />
            </Show>
          </Button>
          {dialog()}
        </span>
      </Show>
    );
  }

  return (
    <Show when={props.sessionAvailable ?? !!authState()}>
      <span
        onClick={(event) => {
          if (!state.hasDestinationWorkspace()) void handleSave(event);
        }}
      >
        <Button
          size={props.size ?? "sm"}
          variant={state.isSaved() ? "secondary" : "outline"}
          class="h-7 gap-1.5 px-2 text-[11px]"
          disabled={(!state.canSave() && !state.canChooseWorkspace()) || state.saving()}
          onClick={(event) => void handleSave(event)}
          title={state.title()}
        >
          <Show when={state.isSaved()} fallback={<PlusIcon class="size-3" />}>
            <CheckIcon class="size-3" />
          </Show>
          <span>{state.isSaved() ? "Saved" : state.saving() ? "Saving" : "Save"}</span>
        </Button>
        {dialog()}
      </span>
    </Show>
  );
}
