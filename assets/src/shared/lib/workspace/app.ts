import type { AppDocuments } from "@/shared/lib/document/manager";
import type { EventRef } from "@/shared/lib/events";
import type { ViewCreator, WorkspaceLeaf, View } from "./view";

export interface Command {
  id: string;
  name: string;
  icon?: string;
  hotkeys?: Hotkey[];
  callback?: () => void;
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
  containerEl: HTMLElement;
  display(): void;
  hide(): void;
}

export interface SidebarPanelConfig {
  id: string;
  viewType?: string;
  icon?: string;
  title?: string;
  render?: (containerEl: HTMLElement) => void;
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
  addStatusBarItem(): HTMLElement;
  addSidebarPanel(config: SidebarPanelConfig): void;
  removeSidebarPanel(id: string): void;
  addSettingTab(settingTab: SettingTabConfig): void;
  removeSettingTab(id: string): void;
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
