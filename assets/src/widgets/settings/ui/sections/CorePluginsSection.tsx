import { For, createSignal } from "solid-js";
import { Switch as ToggleSwitch } from "@/shared/ui/switch";
import { currentWorkspaceId } from "@/entities/workspace";
import {
  getCorePlugins,
  isCorePluginEnabled,
  setCorePluginEnabled,
} from "@/features/plugin-runtime";
import { getApp } from "@/shared/lib/workspace/app";

export function CorePluginsSection() {
  const [updateTracker, forceUpdate] = createSignal(0);

  const wsId = () => currentWorkspaceId();

  const handleToggle = (pluginId: string, enabled: boolean) => {
    const w = wsId();
    if (!w) return;
    const app = getApp();
    setCorePluginEnabled(pluginId, w, enabled, app);
    forceUpdate((v) => v + 1);
  };

  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold">Core Plugins</h3>
        <p class="text-sm text-muted-foreground mt-1">
          Manage built-in plugins. Changes take effect immediately.
        </p>
      </div>

      <div class="space-y-3">
        <For each={getCorePlugins()}>
          {(plugin) => {
            const enabled = () => {
              updateTracker();
              const w = wsId();
              return w ? isCorePluginEnabled(plugin.id, w) : plugin.defaultEnabled;
            };

            return (
              <div class="flex items-center justify-between py-3 border-b border-border last:border-0">
                <div>
                  <div class="text-sm font-medium">{plugin.name}</div>
                  <div class="text-xs text-muted-foreground">{plugin.description}</div>
                </div>
                <ToggleSwitch
                  checked={enabled()}
                  onChange={(checked: boolean) => handleToggle(plugin.id, checked)}
                />
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
}
