import { createEffect, onCleanup } from "solid-js";
import { currentWorkspaceId } from "@/entities/workspace";
import { usePanelWorkspace, workspaceManager } from "@/features/panel";
import type { App } from "@/shared/lib/workspace/app";
import {
  loadCorePlugins,
  registerCorePlugins,
  syncCorePlugins,
  unloadCorePlugins,
} from "@/shared/lib/plugin/core-registry";
import { loadCommandPalette, unloadCommandPalette } from "@/app/core-plugins/command-palette/index";
import { loadDocumentTree, unloadDocumentTree } from "@/app/core-plugins/document-tree/index";
import { loadWordCount, unloadWordCount } from "@/app/core-plugins/word-count/index";

type DocumentWorkspace = ReturnType<typeof usePanelWorkspace>;

let lifecycleGeneration = 0;

function registerBuiltinCommands(documentWorkspace: DocumentWorkspace): void {
  workspaceManager.addCommand({
    id: "editor:switch-mode",
    name: "Switch editor mode",
    editorCallback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.switchPanelType(panelId);
    },
  });
  workspaceManager.addCommand({
    id: "editor:split-horizontal",
    name: "Split editor horizontally",
    editorCallback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.splitPanel(panelId, "row");
    },
  });
  workspaceManager.addCommand({
    id: "editor:split-vertical",
    name: "Split editor vertically",
    editorCallback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.splitPanel(panelId, "column");
    },
  });
  workspaceManager.addCommand({
    id: "editor:close-panel",
    name: "Close current panel",
    callback: () => {
      const panelId = documentWorkspace.focusedPanelId();
      if (panelId) documentWorkspace.closePanel(panelId);
    },
  });
  workspaceManager.addCommand({
    id: "editor:switch-to-split",
    name: "Switch to split view",
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
  registerBuiltinCommands(documentWorkspace);

  const initialWorkspaceId = currentWorkspaceId();
  let corePluginsLoaded = false;
  if (initialWorkspaceId) {
    loadCorePlugins(app, initialWorkspaceId);
    corePluginsLoaded = true;
  }

  let loadedForWorkspaceId: string | null = initialWorkspaceId;
  createEffect(() => {
    const workspaceId = currentWorkspaceId();
    if (workspaceId === loadedForWorkspaceId && corePluginsLoaded) return;

    if (workspaceId) {
      syncCorePlugins(app, workspaceId);
      corePluginsLoaded = true;
      loadedForWorkspaceId = workspaceId;
    } else if (corePluginsLoaded) {
      unloadCorePlugins();
      corePluginsLoaded = false;
      loadedForWorkspaceId = null;
    }
  });

  onCleanup(() => {
    if (lifecycleGeneration !== lifecycleId) return;
    if (!corePluginsLoaded) return;
    unloadCorePlugins();
  });
}
