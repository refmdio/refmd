import type { App, WorkspaceSurfaceOwner } from "@/shared/lib/workspace/app";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

export interface CorePluginLoadContext {
  workspaceId: string;
  ownerId: string;
  generation: number;
}

interface CorePluginEntry {
  id: string;
  name: string;
  description: string;
  defaultEnabled: boolean;
  load: (app: App, context: CorePluginLoadContext) => void;
  unload: () => void;
}

interface CorePluginPreferenceState {
  disabled: Set<string>;
  enabled: Set<string>;
}

interface StoredCorePluginPreferenceState {
  protocol: "refmd.core-plugin-preferences";
  version: 1;
  disabled: string[];
  enabled: string[];
}

let registeredPlugins: CorePluginEntry[] = [];
const loadedPluginsByWorkspace = new Map<string, Set<string>>();
const runtimePreferences = new Map<string, CorePluginPreferenceState>();
let loadGeneration = 0;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function corePluginSurfaceOwner(context: CorePluginLoadContext): WorkspaceSurfaceOwner {
  return {
    kind: "built_in",
    workspaceId: context.workspaceId,
    ownerId: context.ownerId,
    generation: context.generation,
  };
}

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

function preferenceStorageKey(workspaceId: string): string {
  return `refmd-core-plugins:${workspaceId}`;
}

function preferenceAadRecord(workspaceId: string): Record<string, unknown> {
  return {
    kind: "core_plugin_preferences",
    workspace_id: workspaceId,
  };
}

function storedPreferenceState(state: CorePluginPreferenceState): StoredCorePluginPreferenceState {
  return {
    protocol: "refmd.core-plugin-preferences",
    version: 1,
    disabled: [...state.disabled].sort(),
    enabled: [...state.enabled].sort(),
  };
}

function parseStoredPreferenceState(value: unknown): CorePluginPreferenceState | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (record.protocol !== "refmd.core-plugin-preferences" || record.version !== 1) return null;
  if (!Array.isArray(record.disabled) || !Array.isArray(record.enabled)) return null;
  return {
    disabled: new Set(record.disabled.filter((item): item is string => typeof item === "string")),
    enabled: new Set(record.enabled.filter((item): item is string => typeof item === "string")),
  };
}

async function savePreferenceState(workspaceId: string): Promise<void> {
  try {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) return;
    await worker.storeUiStateWithDsk({
      storageKey: preferenceStorageKey(workspaceId),
      aadRecord: preferenceAadRecord(workspaceId),
      plaintext: textEncoder.encode(
        JSON.stringify(storedPreferenceState(preferenceState(workspaceId))),
      ),
    });
  } catch {
    // The in-memory state remains authoritative for this tab if encrypted local storage is unavailable.
  }
}

export async function hydrateCorePluginPreferences(workspaceId: string): Promise<void> {
  try {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) return;
    const plaintext = await worker.loadUiStateWithDsk({
      storageKey: preferenceStorageKey(workspaceId),
      aadRecord: preferenceAadRecord(workspaceId),
    });
    if (!plaintext) return;
    const parsed = parseStoredPreferenceState(JSON.parse(textDecoder.decode(plaintext)));
    if (parsed) runtimePreferences.set(workspaceId, parsed);
  } catch {
    // Preference hydration is best effort; defaults still load fail-closed for unknown plugin ids.
  }
}

function loadedState(workspaceId: string): Set<string> {
  let state = loadedPluginsByWorkspace.get(workspaceId);
  if (!state) {
    state = new Set();
    loadedPluginsByWorkspace.set(workspaceId, state);
  }
  return state;
}

function unloadWorkspacePlugins(workspaceId: string): void {
  const loadedPlugins = loadedPluginsByWorkspace.get(workspaceId);
  if (!loadedPlugins) return;
  for (const plugin of registeredPlugins) {
    if (!loadedPlugins.has(plugin.id)) continue;
    plugin.unload();
  }
  loadedPluginsByWorkspace.delete(workspaceId);
}

function unloadOtherWorkspacePlugins(workspaceId: string): void {
  for (const loadedWorkspaceId of Array.from(loadedPluginsByWorkspace.keys())) {
    if (loadedWorkspaceId === workspaceId) continue;
    unloadWorkspacePlugins(loadedWorkspaceId);
  }
}

function loadPlugin(app: App, plugin: CorePluginEntry, workspaceId: string): void {
  plugin.load(app, {
    workspaceId,
    ownerId: plugin.id,
    generation: ++loadGeneration,
  });
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
  const loadedPlugins = loadedState(workspaceId);
  if (enabled) {
    state.disabled.delete(id);
    if (!isDefault) {
      state.enabled.add(id);
    } else {
      state.enabled.delete(id);
    }
    if (plugin && !loadedPlugins.has(id)) {
      unloadOtherWorkspacePlugins(workspaceId);
      loadPlugin(app, plugin, workspaceId);
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

  void savePreferenceState(workspaceId);
}

export function loadCorePlugins(app: App, workspaceId: string): void {
  unloadOtherWorkspacePlugins(workspaceId);
  const loadedPlugins = loadedState(workspaceId);
  for (const plugin of registeredPlugins) {
    if (!isCorePluginEnabled(plugin.id, workspaceId)) continue;
    if (loadedPlugins.has(plugin.id)) continue;
    loadPlugin(app, plugin, workspaceId);
    loadedPlugins.add(plugin.id);
  }
}

export function syncCorePlugins(app: App, workspaceId: string): void {
  unloadOtherWorkspacePlugins(workspaceId);
  const loadedPlugins = loadedState(workspaceId);
  for (const plugin of registeredPlugins) {
    const enabled = isCorePluginEnabled(plugin.id, workspaceId);
    const loaded = loadedPlugins.has(plugin.id);

    if (enabled && !loaded) {
      loadPlugin(app, plugin, workspaceId);
      loadedPlugins.add(plugin.id);
    } else if (!enabled && loaded) {
      plugin.unload();
      loadedPlugins.delete(plugin.id);
    }
  }
}

export function unloadCorePlugins(workspaceId?: string): void {
  if (workspaceId) {
    unloadWorkspacePlugins(workspaceId);
    return;
  }

  for (const loadedWorkspaceId of Array.from(loadedPluginsByWorkspace.keys())) {
    unloadWorkspacePlugins(loadedWorkspaceId);
  }
}
