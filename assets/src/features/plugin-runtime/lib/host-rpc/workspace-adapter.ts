import type { PluginHostRpcHandlerOwnerDescriptor } from "../host-rpc/host-rpc";

export interface PluginHostWorkspaceAdapter {
  addCommand(command: PluginHostWorkspaceCommand): void;
  removeCommand(commandId: string): void;
  addStatusBarItem(item: PluginHostWorkspaceStatusItem): HTMLElement;
  addSidebarPanel(panel: PluginHostWorkspaceSidebarPanel): void;
  removeSidebarPanel(panelId: string): void;
  addWorkspaceTile(panel: PluginHostWorkspaceTile): void;
  openWorkspaceTile?(panelId: string, documentId?: string): void;
  removeWorkspaceTile(panelId: string): void;
  addAuxiliaryPane?(pane: PluginHostWorkspaceAuxiliaryPane): void;
  removeAuxiliaryPane?(paneId: string): void;
  addSettingTab(tab: PluginHostWorkspaceSettingTab): HTMLElement;
  removeSettingTab(tabId: string): void;
  removeSurfacesByOwner?(predicate: (owner: PluginHostRpcHandlerOwnerDescriptor) => boolean): void;
  activeDocument(): PluginHostWorkspaceDocument | null;
  selectedDocuments?(): readonly PluginHostWorkspaceDocument[];
  activeEditor(): unknown;
  activeEditorEntry(): PluginHostWorkspaceEditorEntry | null;
  documentList(): readonly PluginHostWorkspaceDocumentListEntry[];
  getDocumentById(documentId: string): Promise<PluginHostWorkspaceReadableDocument | null>;
  notifyDocumentChange(documentId: string, editor: PluginHostDocumentEditor): void;
}

export interface PluginHostWorkspaceCommand {
  id: string;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  fallbackManifestHash: string;
  name: string;
  icon?: string;
  callback: (payload?: unknown) => void;
  checkCallback?: (checking: boolean) => boolean | void;
  editorCheckCallback?: (checking: boolean, editor: unknown, view: unknown) => boolean | void;
}

export interface PluginHostWorkspaceStatusItem {
  id: string;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  fallbackManifestHash: string;
  label?: string;
}

export interface PluginHostWorkspaceSidebarPanel {
  id: string;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  fallbackManifestHash: string;
  title: string;
  icon?: string;
  render: (container: HTMLElement) => void;
  hide?: () => void;
}

export interface PluginHostWorkspaceTile {
  id: string;
  tileId: string;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  fallbackManifestHash: string;
  title: string;
  icon?: string;
  scope: "workspace" | "document";
  preferredOpen: "manual" | "document_menu" | "command";
  actions?: () => PluginHostWorkspaceTileAction[] | undefined;
  isAvailable?: (context: PluginHostWorkspaceTileAvailabilityContext) => boolean;
  open?: (context: PluginHostWorkspaceTileAvailabilityContext) => boolean | Promise<boolean>;
  render: (container: HTMLElement, context?: PluginHostWorkspaceTileRenderContext) => void;
  hide?: (context?: PluginHostWorkspaceTileRenderContext) => void;
}

export interface PluginHostWorkspaceTileAction {
  id: string;
  actionId: string;
  title: string;
  icon?: string;
  order?: number;
  placement: "tile_toolbar" | "tile_menu" | "refresh";
  documentQuery?: PluginHostWorkspaceDocumentQuery;
}

export interface PluginHostWorkspaceDocumentQuery {
  scope: "workspace";
  max_documents: number;
  max_bytes: number;
  reason?: string;
}

export interface PluginHostWorkspaceTileAvailabilityContext {
  resourceKind: "document" | "folder" | "workspace";
  workspaceId?: string;
  documentId?: string;
  folderId?: string;
  documentOpen?: boolean;
  selectionPresent?: boolean;
}

export interface PluginHostWorkspaceTileRenderContext {
  tileInstanceId: string;
  documentId?: string;
  action?: PluginHostWorkspaceTileActionContext;
}

export interface PluginHostWorkspaceTileActionContext {
  actionId: string;
  tileId: string;
  tileInstanceId: string;
  documentId?: string;
  kind?: "tile_action";
  tileActionId?: string;
  documentQuery?: PluginHostWorkspaceDocumentQuery;
  issuedAtMs: number;
}

export interface PluginHostWorkspaceAuxiliaryPane {
  id: string;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  fallbackManifestHash: string;
  title: string;
  icon?: string;
  allowedLocations: ("left" | "right" | "document_left" | "document_right")[];
  defaultWidth?: number;
  actions?: PluginHostWorkspaceAuxiliaryPaneAction[];
  render: (container: HTMLElement) => void;
  hide?: () => void;
  close?: () => void;
}

export interface PluginHostWorkspaceAuxiliaryPaneAction {
  id: string;
  title: string;
  icon?: string;
  order?: number;
  invoke: () => void;
  isAvailable?: () => boolean;
}

export interface PluginHostWorkspaceSettingTab {
  id: string;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  fallbackManifestHash: string;
  title: string;
  render: (container: HTMLElement) => void;
  hide?: () => void;
}

export interface PluginHostWorkspaceDocument {
  id: string;
  title: string;
  editor: PluginHostDocumentEditor;
}

export interface PluginHostWorkspaceEditorEntry {
  panelId: string;
  editor: PluginHostCommandEditor;
}

export interface PluginHostWorkspaceDocumentListEntry {
  id: string;
  docType: string;
  archivedAt?: unknown;
}

export interface PluginHostWorkspaceReadableDocument {
  id: string;
  title: string;
  text: string;
  release(): void;
}

export interface PluginHostDocumentEditor {
  getValue(): string;
  setValue?: (value: string) => void;
  replaceSelection?: (text: string) => void;
}

export interface PluginHostCommandEditor extends PluginHostDocumentEditor {
  somethingSelected(): boolean;
  getCursor(which: "from" | "to" | "head"): unknown;
  posToOffset(position: unknown): number;
  getSelection(): string;
}
