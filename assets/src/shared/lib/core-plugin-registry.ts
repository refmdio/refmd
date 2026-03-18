import type { App } from "./app-context";

export interface CorePluginEntry {
  id: string;
  name: string;
  description: string;
  defaultEnabled: boolean;
  load: (app: App) => void;
  unload: () => void;
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

function getDisabledSet(workspaceId: string): Set<string> {
  try {
    const raw = localStorage.getItem(getStorageKey(workspaceId));
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as { disabled?: string[] };
    return new Set(parsed.disabled ?? []);
  } catch {
    return new Set();
  }
}

function saveState(workspaceId: string, disabled: Set<string>, enabled: Set<string>): void {
  try {
    localStorage.setItem(
      getStorageKey(workspaceId),
      JSON.stringify({ disabled: [...disabled], enabled: [...enabled] }),
    );
  } catch {
    // localStorage unavailable
  }
}

function getEnabledSet(workspaceId: string): Set<string> {
  try {
    const raw = localStorage.getItem(getStorageKey(workspaceId));
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as { enabled?: string[] };
    return new Set(parsed.enabled ?? []);
  } catch {
    return new Set();
  }
}

export function isCorePluginEnabled(id: string, workspaceId: string): boolean {
  const disabled = getDisabledSet(workspaceId);
  const enabled = getEnabledSet(workspaceId);
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
  const disabled = getDisabledSet(workspaceId);
  const enabledSet = getEnabledSet(workspaceId);

  const plugin = registeredPlugins.find((p) => p.id === id);
  const isDefault = plugin?.defaultEnabled ?? true;

  if (enabled) {
    disabled.delete(id);
    if (!isDefault) {
      enabledSet.add(id);
    } else {
      enabledSet.delete(id);
    }
    if (plugin && !loadedPlugins.has(id)) {
      plugin.load(app);
      loadedPlugins.add(id);
    }
  } else {
    enabledSet.delete(id);
    if (isDefault) {
      disabled.add(id);
    } else {
      disabled.delete(id);
    }
    if (plugin && loadedPlugins.has(id)) {
      plugin.unload();
      loadedPlugins.delete(id);
    }
  }

  saveState(workspaceId, disabled, enabledSet);
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
