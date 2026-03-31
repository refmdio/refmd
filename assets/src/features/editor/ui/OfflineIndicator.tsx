import { Show } from "solid-js";
import { WifiOffIcon, RefreshCwIcon } from "lucide-solid";
import { offlineMode, offlineReason } from "@/shared/lib/offline/offline-state";

export function OfflineIndicator() {
  return (
    <Show when={offlineMode()}>
      <div class="flex items-center gap-1.5 text-yellow-600 dark:text-yellow-400">
        <Show
          when={offlineReason() === "network"}
          fallback={<RefreshCwIcon class="size-3 animate-spin" />}
        >
          <WifiOffIcon class="size-3" />
        </Show>
        <span>{offlineReason() === "network" ? "Offline" : "Reconnecting..."}</span>
      </div>
    </Show>
  );
}
