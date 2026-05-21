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
const runtimePreferences = new Map<string, CorePluginPreferenceState>();

export function registerCorePlugins(plugins: CorePluginEntry[]): void {
  registeredPlugins = plugins;
}

export function getCorePlugins(): CorePluginEntry[] {
  return registeredPlugins;
}

function preferenceState(workspaceId: string): CorePluginPreferenceState {
  let state = runtimePreferences.get(workspaceId);
  if (!state) {
    state = {
      disabled: new Set(),
      enabled: new Set(),
    };
    runtimePreferences.set(workspaceId, state);
  }
  return state;
}

export function isCorePluginEnabled(id: string, workspaceId: string): boolean {
  const { disabled, enabled } = preferenceState(workspaceId);
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
  const state = preferenceState(workspaceId);
  const plugin = registeredPlugins.find((p) => p.id === id);
  const isDefault = plugin?.defaultEnabled ?? true;
  if (enabled) {
    state.disabled.delete(id);
    if (!isDefault) {
      state.enabled.add(id);
    } else {
      state.enabled.delete(id);
    }
    if (plugin && !loadedPlugins.has(id)) {
      plugin.load(app);
      loadedPlugins.add(id);
    }
  } else {
    state.enabled.delete(id);
    if (isDefault) {
      state.disabled.add(id);
    } else {
      state.disabled.delete(id);
    }
    if (plugin && loadedPlugins.has(id)) {
      plugin.unload();
      loadedPlugins.delete(id);
    }
  }
}

export function loadCorePlugins(app: App, workspaceId: string): void {
  for (const plugin of registeredPlugins) {
    if (!isCorePluginEnabled(plugin.id, workspaceId)) continue;
    if (loadedPlugins.has(plugin.id)) continue;
    plugin.load(app);
    loadedPlugins.add(plugin.id);
  }
}

export function syncCorePlugins(app: App, workspaceId: string): void {
  for (const plugin of registeredPlugins) {
    const enabled = isCorePluginEnabled(plugin.id, workspaceId);
    const loaded = loadedPlugins.has(plugin.id);

    if (enabled && !loaded) {
      plugin.load(app);
      loadedPlugins.add(plugin.id);
    } else if (!enabled && loaded) {
      plugin.unload();
      loadedPlugins.delete(plugin.id);
    }
  }
}

export function unloadCorePlugins(): void {
  for (const plugin of registeredPlugins) {
    if (!loadedPlugins.has(plugin.id)) continue;
    plugin.unload();
  }
  loadedPlugins.clear();
}
