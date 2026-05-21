import { Show } from "solid-js";
import { WifiOffIcon } from "lucide-solid";
import { offlineMode } from "@/shared/lib/offline/offline-state";

export function OfflineIndicator() {
  return (
    <Show when={offlineMode()}>
      <div class="flex items-center gap-1.5 text-yellow-600 dark:text-yellow-400">
        <WifiOffIcon class="size-3" />
        <span>Offline</span>
      </div>
    </Show>
  );
}
