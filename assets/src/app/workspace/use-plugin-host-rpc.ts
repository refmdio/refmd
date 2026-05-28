import type { Accessor } from "solid-js";
import { getActiveEditor, getActiveEditorEntry, type EditorLike } from "@/features/editor";
import {
  usePluginHostRpc as usePluginHostRuntime,
  type PluginHostDocumentEditor,
  type PluginHostWorkspaceAdapter,
} from "@/features/plugin-runtime";
import type { PluginHostRpcHandlerOwnerDescriptor } from "@/features/plugin-runtime";
import { getDocumentEvents } from "@/shared/lib/document/manager";

export { createDurablePluginRuntimeAuditSink } from "@/features/plugin-runtime";

export interface PluginHostAppServices {
  workspace: PluginHostWorkspaceSurface;
  documents: PluginHostDocumentSurface;
}

interface PluginHostWorkspaceSurface {
  addCommand(command: PluginHostWorkspaceSurfaceCommand): unknown;
  removeCommand(commandId: string): void;
  addStatusBarItem(config?: PluginHostWorkspaceStatusConfig): HTMLElement;
  addSidebarPanel(config: PluginHostWorkspaceSidebarConfig): void;
  removeSidebarPanel(id: string): void;
  addWorkspaceTile(config: PluginHostWorkspaceTileConfig): void;
  openWorkspaceTile?(panelId: string, documentId?: string): void;
  removeWorkspaceTile(id: string): void;
  addAuxiliaryPane(config: PluginHostWorkspaceAuxiliaryPaneConfig): void;
  removeAuxiliaryPane(id: string): void;
  addSettingTab(settingTab: PluginHostWorkspaceSettingConfig): void;
  removeSettingTab(id: string): void;
  removeSurfacesByOwner?(predicate: (owner: PluginHostWorkspaceSurfaceOwner) => boolean): void;
}

interface PluginHostWorkspaceSurfaceCommand {
  id: string;
  name: string;
  owner?: PluginHostWorkspaceSurfaceOwner;
  icon?: string;
  callback?: (payload?: unknown) => void;
  checkCallback?: (checking: boolean) => boolean | void;
  editorCheckCallback?: (checking: boolean, editor: unknown, view: unknown) => boolean | void;
}

interface PluginHostWorkspaceStatusConfig {
  id?: string;
  owner?: PluginHostWorkspaceSurfaceOwner;
  label?: string;
}

interface PluginHostWorkspaceSidebarConfig {
  id: string;
  owner?: PluginHostWorkspaceSurfaceOwner;
  icon?: string;
  title?: string;
  render?: (containerEl: HTMLElement) => void;
  hide?: () => void;
}

interface PluginHostWorkspaceTileConfig {
  id: string;
  tileId: string;
  owner?: PluginHostWorkspaceSurfaceOwner;
  icon?: string;
  title: string;
  scope: "workspace" | "document";
  preferredOpen: "manual" | "document_menu" | "command";
  actions?: () => PluginHostWorkspaceTileAction[] | undefined;
  isAvailable?: (context: PluginHostWorkspaceTileAvailabilityContext) => boolean;
  open?: (context: PluginHostWorkspaceTileAvailabilityContext) => boolean | Promise<boolean>;
  render: (containerEl: HTMLElement, context?: PluginHostWorkspaceTileRenderContext) => void;
  hide?: (context?: PluginHostWorkspaceTileRenderContext) => void;
}

interface PluginHostWorkspaceTileAction {
  id: string;
  actionId: string;
  title: string;
  icon?: string;
  order?: number;
  placement: "tile_toolbar" | "tile_menu" | "refresh";
  documentQuery?: PluginHostWorkspaceDocumentQuery;
}

interface PluginHostWorkspaceDocumentQuery {
  scope: "workspace";
  max_documents: number;
  max_bytes: number;
  reason?: string;
}

interface PluginHostWorkspaceTileAvailabilityContext {
  resourceKind: "document" | "folder" | "workspace";
  workspaceId?: string;
  documentId?: string;
  folderId?: string;
  documentOpen?: boolean;
  selectionPresent?: boolean;
}

interface PluginHostWorkspaceTileRenderContext {
  tileInstanceId: string;
  documentId?: string;
  action?: PluginHostWorkspaceTileActionContext;
}

interface PluginHostWorkspaceTileActionContext {
  actionId: string;
  tileId: string;
  tileInstanceId: string;
  documentId?: string;
  kind?: "tile_action";
  tileActionId?: string;
  documentQuery?: PluginHostWorkspaceDocumentQuery;
  issuedAtMs: number;
}

interface PluginHostWorkspaceAuxiliaryPaneConfig {
  id: string;
  owner?: PluginHostWorkspaceSurfaceOwner;
  icon?: string;
  title: string;
  allowedLocations: ("left" | "right" | "document_left" | "document_right")[];
  defaultWidth?: number;
  actions?: PluginHostWorkspaceAuxiliaryPaneActionConfig[];
  render: (containerEl: HTMLElement) => void;
  hide?: () => void;
  close?: () => void;
}

interface PluginHostWorkspaceAuxiliaryPaneActionConfig {
  id: string;
  title: string;
  icon?: string;
  order?: number;
  invoke: () => void;
  isAvailable?: () => boolean;
}

interface PluginHostWorkspaceSettingConfig {
  id: string;
  name: string;
  owner?: PluginHostWorkspaceSurfaceOwner;
  containerEl: HTMLElement;
  display(): void;
  hide(): void;
}

type PluginHostWorkspaceSurfaceOwner =
  | {
      kind: "built_in";
      workspaceId: string;
      ownerId: string;
      generation: number;
    }
  | {
      kind: "third_party";
      pluginId: string;
      packageId: string;
      applicationId: string;
      activationId: string;
      ownerScopeKind: string;
      workspaceId: string;
      userId: string;
      deviceId: string;
      bundleHash: string;
      manifestHash: string;
      frameGeneration: number;
      consentEpoch: number;
      capabilityGrantId: string;
    };

interface PluginHostDocumentSurface {
  getActiveDocument(): { id: string; title: string; editor: unknown } | null;
  getSelectedDocuments?(): readonly { id: string; title: string; editor: unknown }[];
  getDocumentList(): readonly { id: string; docType: string; archivedAt?: unknown }[];
  getDocumentById(documentId: string): Promise<{
    id: string;
    title: string;
    text: string;
    release(): void;
  } | null>;
}

export function usePluginHostRpc(
  workspaceId: Accessor<string | null> | undefined,
  app: PluginHostAppServices,
) {
  return usePluginHostRuntime(workspaceId, {
    workspace: createPluginHostWorkspaceAdapter(app.workspace, app),
  });
}

function createPluginHostWorkspaceAdapter(
  workspace: PluginHostWorkspaceSurface,
  app: PluginHostAppServices,
): PluginHostWorkspaceAdapter {
  return {
    addCommand(command) {
      workspace.addCommand({
        id: command.id,
        name: command.name,
        owner: workspaceOwnerFromPluginOwner(command.owner, command.fallbackManifestHash),
        icon: command.icon,
        callback: command.callback,
        checkCallback: command.checkCallback,
        editorCheckCallback: command.editorCheckCallback,
      });
    },
    removeCommand(commandId) {
      workspace.removeCommand(commandId);
    },
    addStatusBarItem(item) {
      return workspace.addStatusBarItem({
        id: item.id,
        owner: workspaceOwnerFromPluginOwner(item.owner, item.fallbackManifestHash),
        label: item.label,
      });
    },
    addSidebarPanel(panel) {
      workspace.addSidebarPanel({
        id: panel.id,
        owner: workspaceOwnerFromPluginOwner(panel.owner, panel.fallbackManifestHash),
        title: panel.title,
        icon: panel.icon,
        render: panel.render,
        hide: panel.hide,
      });
    },
    removeSidebarPanel(panelId) {
      workspace.removeSidebarPanel(panelId);
    },
    addWorkspaceTile(panel) {
      workspace.addWorkspaceTile({
        id: panel.id,
        tileId: panel.tileId,
        owner: workspaceOwnerFromPluginOwner(panel.owner, panel.fallbackManifestHash),
        title: panel.title,
        icon: panel.icon,
        scope: panel.scope,
        preferredOpen: panel.preferredOpen,
        actions: panel.actions,
        isAvailable: panel.isAvailable,
        open: panel.open,
        render: panel.render,
        hide: panel.hide,
      });
    },
    removeWorkspaceTile(panelId) {
      workspace.removeWorkspaceTile(panelId);
    },
    openWorkspaceTile(panelId, documentId) {
      workspace.openWorkspaceTile?.(panelId, documentId);
    },
    addAuxiliaryPane(pane) {
      workspace.addAuxiliaryPane({
        id: pane.id,
        owner: workspaceOwnerFromPluginOwner(pane.owner, pane.fallbackManifestHash),
        title: pane.title,
        icon: pane.icon,
        allowedLocations: pane.allowedLocations,
        defaultWidth: pane.defaultWidth,
        actions: pane.actions,
        render: pane.render,
        hide: pane.hide,
        close: pane.close,
      });
    },
    removeAuxiliaryPane(paneId) {
      workspace.removeAuxiliaryPane(paneId);
    },
    addSettingTab(tab) {
      const containerEl = document.createElement("div");
      workspace.addSettingTab({
        id: tab.id,
        owner: workspaceOwnerFromPluginOwner(tab.owner, tab.fallbackManifestHash),
        name: tab.title,
        containerEl,
        display() {
          tab.render(containerEl);
        },
        hide() {
          tab.hide?.();
        },
      });
      return containerEl;
    },
    removeSettingTab(tabId) {
      workspace.removeSettingTab(tabId);
    },
    removeSurfacesByOwner(predicate) {
      workspace.removeSurfacesByOwner?.((owner) => {
        if (owner.kind !== "third_party") return false;
        return predicate(owner);
      });
    },
    activeDocument() {
      const active = app.documents.getActiveDocument();
      if (!active) return null;
      return {
        id: active.id,
        title: active.title,
        editor: active.editor as PluginHostDocumentEditor,
      };
    },
    selectedDocuments() {
      return (
        app.documents.getSelectedDocuments?.().map((document) => ({
          id: document.id,
          title: document.title,
          editor: document.editor as PluginHostDocumentEditor,
        })) ?? []
      );
    },
    activeEditor() {
      return getActiveEditor();
    },
    activeEditorEntry() {
      const entry = getActiveEditorEntry();
      if (!entry) return null;
      return { panelId: entry.panelId, editor: entry.editor as EditorLike };
    },
    documentList() {
      return app.documents.getDocumentList();
    },
    getDocumentById(documentId) {
      return app.documents.getDocumentById(documentId);
    },
    notifyDocumentChange(documentId, editor) {
      getDocumentEvents().notifyDocumentChangeFor(documentId, editor as EditorLike);
    },
  };
}

function workspaceOwnerFromPluginOwner(
  owner: PluginHostRpcHandlerOwnerDescriptor,
  fallbackManifestHash: string,
): PluginHostWorkspaceSurfaceOwner {
  return {
    kind: "third_party",
    pluginId: owner.pluginId,
    packageId: owner.packageId,
    applicationId: owner.applicationId,
    activationId: owner.activationId,
    ownerScopeKind: owner.ownerScopeKind,
    workspaceId: owner.workspaceId,
    userId: owner.userId,
    deviceId: owner.deviceId,
    bundleHash: owner.bundleHash,
    manifestHash: owner.manifestHash ?? fallbackManifestHash,
    frameGeneration: owner.frameGeneration,
    consentEpoch: owner.consentEpoch,
    capabilityGrantId: owner.capabilityGrantId,
  };
}
