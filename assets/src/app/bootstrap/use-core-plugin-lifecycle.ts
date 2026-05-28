import { createEffect, onCleanup } from "solid-js";
import { currentWorkspaceId } from "@/entities/workspace";
import { usePanelWorkspace, workspaceManager } from "@/features/panel";
import type { App, WorkspaceSurfaceOwner } from "@/shared/lib/workspace/app";
import {
  hydrateCorePluginPreferences,
  loadCorePlugins,
  registerCorePlugins,
  syncCorePlugins,
  unloadCorePlugins,
} from "@/features/plugin-runtime";
import { loadCommandPalette, unloadCommandPalette } from "@/app/core-plugins/command-palette/index";
import { loadDocumentTree, unloadDocumentTree } from "@/app/core-plugins/document-tree/index";
import { loadWordCount, unloadWordCount } from "@/app/core-plugins/word-count/index";

type DocumentWorkspace = ReturnType<typeof usePanelWorkspace>;

let lifecycleGeneration = 0;

const BUILTIN_EDITOR_COMMAND_IDS = [
  "editor:switch-mode",
  "editor:split-horizontal",
  "editor:split-vertical",
  "editor:close-panel",
  "editor:switch-to-split",
] as const;

function builtinEditorOwner(workspaceId: string, generation: number): WorkspaceSurfaceOwner {
  return {
    kind: "built_in",
    workspaceId,
    ownerId: "editor",
    generation,
  };
}

function unregisterBuiltinCommands(): void {
  for (const commandId of BUILTIN_EDITOR_COMMAND_IDS) {
    workspaceManager.removeCommand(commandId);
  }
}

function registerBuiltinCommands(
  documentWorkspace: DocumentWorkspace,
  workspaceId: string,
  generation: number,
): void {
  const owner = builtinEditorOwner(workspaceId, generation);
  unregisterBuiltinCommands();

  workspaceManager.addCommand({
    id: "editor:switch-mode",
    name: "Switch editor mode",
    owner,
    editorCallback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.switchPanelType(panelId);
    },
  });
  workspaceManager.addCommand({
    id: "editor:split-horizontal",
    name: "Split editor horizontally",
    owner,
    editorCallback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.splitPanel(panelId, "row");
    },
  });
  workspaceManager.addCommand({
    id: "editor:split-vertical",
    name: "Split editor vertically",
    owner,
    editorCallback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.splitPanel(panelId, "column");
    },
  });
  workspaceManager.addCommand({
    id: "editor:close-panel",
    name: "Close current panel",
    owner,
    callback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.closePanel(panelId);
    },
  });
  workspaceManager.addCommand({
    id: "editor:switch-to-split",
    name: "Switch to split view",
    owner,
    editorCallback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.switchToSplit(panelId);
    },
  });
}

function registerDefaultCorePlugins(): void {
  registerCorePlugins([
    {
      id: "document-tree",
      name: "Document Tree",
      description: "Browse documents and folders in the sidebar.",
      defaultEnabled: true,
      load: loadDocumentTree,
      unload: unloadDocumentTree,
    },
    {
      id: "command-palette",
      name: "Command Palette",
      description: "Quickly access commands from your keyboard.",
      defaultEnabled: true,
      load: loadCommandPalette,
      unload: unloadCommandPalette,
    },
    {
      id: "word-count",
      name: "Word Count",
      description: "Display the number of words and characters in the status bar.",
      defaultEnabled: true,
      load: loadWordCount,
      unload: unloadWordCount,
    },
  ]);
}

export function useCorePluginLifecycle(app: App, documentWorkspace: DocumentWorkspace): void {
  const lifecycleId = ++lifecycleGeneration;

  registerDefaultCorePlugins();

  let corePluginsLoaded = false;
  let loadedForWorkspaceId: string | null = null;
  let syncRun = 0;

  createEffect(() => {
    const workspaceId = currentWorkspaceId();
    const runId = ++syncRun;
    if (workspaceId === loadedForWorkspaceId && corePluginsLoaded) return;

    if (workspaceId) {
      registerBuiltinCommands(documentWorkspace, workspaceId, lifecycleId);
      void hydrateCorePluginPreferences(workspaceId).then(() => {
        if (syncRun !== runId) return;
        if (corePluginsLoaded) {
          syncCorePlugins(app, workspaceId);
        } else {
          loadCorePlugins(app, workspaceId);
        }
        corePluginsLoaded = true;
        loadedForWorkspaceId = workspaceId;
      });
    } else {
      unregisterBuiltinCommands();
      if (corePluginsLoaded) {
        unloadCorePlugins();
        corePluginsLoaded = false;
        loadedForWorkspaceId = null;
      }
    }
  });

  onCleanup(() => {
    syncRun++;
    if (lifecycleGeneration !== lifecycleId) return;
    unregisterBuiltinCommands();
    if (!corePluginsLoaded) return;
    unloadCorePlugins();
  });
}
