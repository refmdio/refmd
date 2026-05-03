import { Show } from "solid-js";
import { CheckIcon, PlusIcon } from "lucide-solid";
import type { ShareMountLookupItem } from "@/entities/mount";
import { authState } from "@/entities/session";
import { Button } from "@/shared/ui/button";
import { useSaveShareMount } from "../model/useSaveShareMount";

interface SaveShareMountButtonProps {
  shareSlug: string;
  targetKind: "document" | "folder";
  targetToken: string | null;
  existingMounts?: ShareMountLookupItem[];
  size?: "sm" | "default";
  iconOnly?: boolean;
  class?: string;
  sessionAvailable?: boolean;
  onSaved?: () => void;
}

export function SaveShareMountButton(props: SaveShareMountButtonProps) {
  const state = useSaveShareMount(props);

  if (props.iconOnly) {
    return (
      <Show when={props.sessionAvailable ?? !!authState()}>
        <Button
          size="icon-sm"
          variant={state.isSaved() ? "secondary" : "ghost"}
          class={props.class}
          disabled={!state.canSave() || state.saving()}
          onClick={(event) => {
            event.stopPropagation();
            void state.save();
          }}
          title={state.title()}
          aria-label={state.title()}
        >
          <Show when={state.isSaved()} fallback={<PlusIcon class="size-3.5" />}>
            <CheckIcon class="size-3.5" />
          </Show>
        </Button>
      </Show>
    );
  }

  return (
    <Show when={props.sessionAvailable ?? !!authState()}>
      <Button
        size={props.size ?? "sm"}
        variant={state.isSaved() ? "secondary" : "outline"}
        class="h-7 gap-1.5 px-2 text-[11px]"
        disabled={!state.canSave() || state.saving()}
        onClick={(event) => {
          event.stopPropagation();
          void state.save();
        }}
        title={state.title()}
      >
        <Show when={state.isSaved()} fallback={<PlusIcon class="size-3" />}>
          <CheckIcon class="size-3" />
        </Show>
        <span>{state.isSaved() ? "Saved" : state.saving() ? "Saving" : "Save"}</span>
      </Button>
    </Show>
  );
}
