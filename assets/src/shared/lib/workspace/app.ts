import type { AppDocuments } from "@/shared/lib/document/manager";
import type { EventRef } from "@/shared/lib/events";
import type { ViewCreator, WorkspaceLeaf, View } from "./view";

export type WorkspaceSurfaceOwner =
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

export type WorkspaceSurfaceOwnerPredicate = (owner: WorkspaceSurfaceOwner) => boolean;

export interface Command {
  id: string;
  name: string;
  owner: WorkspaceSurfaceOwner;
  icon?: string;
  hotkeys?: Hotkey[];
  callback?: (payload?: unknown) => void;
  checkCallback?: (checking: boolean) => boolean | void;
  editorCallback?: (editor: unknown, view: unknown) => void;
  editorCheckCallback?: (checking: boolean, editor: unknown, view: unknown) => boolean | void;
}

export interface Hotkey {
  modifiers: ("Mod" | "Ctrl" | "Meta" | "Shift" | "Alt")[];
  key: string;
}

export interface SettingTabConfig {
  id: string;
  name: string;
  owner?: WorkspaceSurfaceOwner;
  containerEl: HTMLElement;
  display(): void;
  hide(): void;
}

export interface SidebarPanelConfig {
  id: string;
  owner?: WorkspaceSurfaceOwner;
  viewType?: string;
  icon?: string;
  title?: string;
  render?: (containerEl: HTMLElement) => void;
  hide?: () => void;
}

export type AuxiliaryPaneLocation = "left" | "right" | "document_left" | "document_right";
export type WorkspaceTileScope = "workspace" | "document";
export type WorkspaceTilePreferredOpen = "manual" | "document_menu" | "command";

export interface WorkspaceDocumentQueryConfig {
  scope: "workspace";
  max_documents: number;
  max_bytes: number;
  reason?: string;
}

export interface AuxiliaryPaneConfig {
  id: string;
  owner?: WorkspaceSurfaceOwner;
  icon?: string;
  title: string;
  allowedLocations: AuxiliaryPaneLocation[];
  defaultWidth?: number;
  actions?: AuxiliaryPaneActionConfig[];
  render: (containerEl: HTMLElement) => void;
  hide?: () => void;
  close?: () => void;
}

export interface AuxiliaryPaneActionConfig {
  id: string;
  title: string;
  icon?: string;
  order?: number;
  invoke: () => void;
  isAvailable?: () => boolean;
}

export interface WorkspaceTileConfig {
  id: string;
  tileId: string;
  owner?: WorkspaceSurfaceOwner;
  icon?: string;
  title: string;
  scope: WorkspaceTileScope;
  preferredOpen: WorkspaceTilePreferredOpen;
  actions?: () => WorkspaceTileActionConfig[] | undefined;
  isAvailable?: (context: WorkspaceTileAvailabilityContext) => boolean;
  open?: (context: WorkspaceTileAvailabilityContext) => boolean | Promise<boolean>;
  render: (containerEl: HTMLElement, context?: WorkspaceTileRenderContext) => void;
  hide?: (context?: WorkspaceTileRenderContext) => void;
}

export interface WorkspaceTileActionConfig {
  id: string;
  actionId: string;
  title: string;
  icon?: string;
  order?: number;
  placement: "tile_toolbar" | "tile_menu" | "refresh";
  documentQuery?: WorkspaceDocumentQueryConfig;
}

export function workspaceTileCanOpenFromDocumentMenu(
  tile: Pick<WorkspaceTileConfig, "scope" | "preferredOpen">,
): boolean {
  return tile.scope === "document" && tile.preferredOpen === "document_menu";
}

export function auxiliaryPanePreferredLocation(pane: AuxiliaryPaneConfig): AuxiliaryPaneLocation {
  return pane.allowedLocations[0] ?? "right";
}

export interface WorkspaceTileAvailabilityContext {
  resourceKind: "document" | "folder" | "workspace";
  workspaceId?: string;
  documentId?: string;
  folderId?: string;
  documentOpen?: boolean;
  selectionPresent?: boolean;
}

export interface WorkspaceTileRenderContext {
  tileInstanceId: string;
  documentId?: string;
  action?: WorkspaceTileActionContext;
}

export interface WorkspaceTileActionContext {
  actionId: string;
  tileId: string;
  tileInstanceId: string;
  documentId?: string;
  kind?: "tile_action";
  tileActionId?: string;
  documentQuery?: WorkspaceDocumentQueryConfig;
  issuedAtMs: number;
}

export interface StatusBarItemConfig {
  id?: string;
  owner?: WorkspaceSurfaceOwner;
  label?: string;
}

export interface AppWorkspace {
  registerView(type: string, viewCreator: ViewCreator): void;
  unregisterView(type: string): void;
  getActiveViewOfType<T extends View>(type: abstract new (...args: unknown[]) => T): T | null;
  getLeavesOfType(viewType: string): WorkspaceLeaf[];
  getLeaf(newLeaf?: boolean | "split"): WorkspaceLeaf;
  getLeftLeaf(split: boolean): WorkspaceLeaf | null;
  getRightLeaf(split: boolean): WorkspaceLeaf | null;
  setActiveLeaf(leaf: WorkspaceLeaf, options?: { focus?: boolean }): void;
  revealLeaf(leaf: WorkspaceLeaf): void;
  getActiveDocumentView(): unknown;
  detachLeavesOfType(viewType: string): void;
  addCommand(command: Command): Command;
  removeCommand(commandId: string): void;
  listCommands(): Command[];
  addStatusBarItem(config?: StatusBarItemConfig): HTMLElement;
  addSidebarPanel(config: SidebarPanelConfig): void;
  removeSidebarPanel(id: string): void;
  addWorkspaceTile(config: WorkspaceTileConfig): void;
  openWorkspaceTile?(panelId: string, documentId?: string): void;
  removeWorkspaceTile(id: string): void;
  getWorkspaceTiles(): WorkspaceTileConfig[];
  addAuxiliaryPane(config: AuxiliaryPaneConfig): void;
  removeAuxiliaryPane(id: string): void;
  getAuxiliaryPanes(): AuxiliaryPaneConfig[];
  addSettingTab(settingTab: SettingTabConfig): void;
  removeSettingTab(id: string): void;
  removeSurfacesByOwner(predicate: WorkspaceSurfaceOwnerPredicate): void;
  on(event: string, cb: (...data: unknown[]) => unknown, ctx?: unknown): EventRef;
  offref(ref: EventRef): void;
  trigger(name: string, ...data: unknown[]): void;
}

export interface App {
  workspace: AppWorkspace;
  documents: AppDocuments;
  isDarkMode(): boolean;
}

export const APP_INSTANCE_KEY = "__REFMD_APP_INSTANCE__" as const;

export function getApp(): App {
  const appInstance = Reflect.get(globalThis, APP_INSTANCE_KEY) as App | null | undefined;
  if (!appInstance) throw new Error("App not initialized");
  return appInstance;
}
