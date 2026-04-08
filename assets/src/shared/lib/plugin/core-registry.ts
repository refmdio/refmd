import type { App } from "@/shared/lib/workspace/app";

interface CorePluginEntry {
  id: string;
  name: string;
  description: string;
  defaultEnabled: boolean;
  load: (app: App) => void;
  unload: () => void;
}

interface CorePluginPreferenceState {
  disabled: Set<string>;
  enabled: Set<string>;
}

let registeredPlugins: CorePluginEntry[] = [];
const loadedPlugins = new Set<string>();

export function registerCorePlugins(plugins: CorePluginEntry[]): void {
  registeredPlugins = plugins;
}

export function getCorePlugins(): CorePluginEntry[] {
  return registeredPlugins;
}

function getStorageKey(workspaceId: string): string {
  return `refmd-core-plugins:${workspaceId}`;
}

function readPreferenceState(workspaceId: string): CorePluginPreferenceState {
  try {
    const raw = localStorage.getItem(getStorageKey(workspaceId));
    if (!raw) {
      return {
        disabled: new Set(),
        enabled: new Set(),
      };
    }

    const parsed = JSON.parse(raw) as {
      disabled?: string[];
      enabled?: string[];
    };

    return {
      disabled: new Set(parsed.disabled ?? []),
      enabled: new Set(parsed.enabled ?? []),
    };
  } catch {
    return {
      disabled: new Set(),
      enabled: new Set(),
    };
  }
}

function savePreferenceState(workspaceId: string, state: CorePluginPreferenceState): void {
  try {
    localStorage.setItem(
      getStorageKey(workspaceId),
      JSON.stringify({
        disabled: [...state.disabled],
        enabled: [...state.enabled],
      }),
    );
  } catch {
    // localStorage unavailable
  }
}

export function isCorePluginEnabled(id: string, workspaceId: string): boolean {
  const { disabled, enabled } = readPreferenceState(workspaceId);
  const plugin = registeredPlugins.find((p) => p.id === id);
  if (!plugin) return false;
  if (disabled.has(id)) return false;
  if (enabled.has(id)) return true;
  return plugin.defaultEnabled;
}

export function setCorePluginEnabled(
  id: string,
  workspaceId: string,
  enabled: boolean,
  app: App,
): void {
  const preferenceState = readPreferenceState(workspaceId);
  const plugin = registeredPlugins.find((p) => p.id === id);
  const isDefault = plugin?.defaultEnabled ?? true;
  if (enabled) {
    preferenceState.disabled.delete(id);
    if (!isDefault) {
      preferenceState.enabled.add(id);
    } else {
      preferenceState.enabled.delete(id);
    }
    if (plugin && !loadedPlugins.has(id)) {
      plugin.load(app);
      loadedPlugins.add(id);
    }
  } else {
    preferenceState.enabled.delete(id);
    if (isDefault) {
      preferenceState.disabled.add(id);
    } else {
      preferenceState.disabled.delete(id);
    }
    if (plugin && loadedPlugins.has(id)) {
      plugin.unload();
      loadedPlugins.delete(id);
    }
  }
  savePreferenceState(workspaceId, preferenceState);
}

export function loadCorePlugins(app: App, workspaceId: string): void {
  for (const plugin of registeredPlugins) {
    if (!isCorePluginEnabled(plugin.id, workspaceId)) continue;
    if (loadedPlugins.has(plugin.id)) continue;
    plugin.load(app);
    loadedPlugins.add(plugin.id);
  }
}

export function unloadCorePlugins(): void {
  for (const plugin of registeredPlugins) {
    if (!loadedPlugins.has(plugin.id)) continue;
    plugin.unload();
  }
  loadedPlugins.clear();
}
