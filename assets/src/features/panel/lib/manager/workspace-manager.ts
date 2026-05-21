import type { Accessor } from "solid-js";
import type { MosaicNode } from "solid-mosaic-component";
import { Events, type EventRef } from "@/shared/lib/events";
import type {
  App,
  AppWorkspace,
  Command,
  SettingTabConfig,
  SidebarPanelConfig,
} from "@/shared/lib/workspace/app";
import type { DocumentView } from "@/shared/lib/document/manager";
import type { ViewCreator, WorkspaceLeaf, View } from "@/shared/lib/workspace/view";
import { CommandsState } from "./commands";
import { LeafsState } from "./leafs";
import { ShellState } from "./shell";

type EditorContextResolver = () => { editor: unknown; doc: DocumentView } | null;
type ActiveDocumentResolver = () => DocumentView | null;

type MosaicOps = {
  focusPanel: (panelId: string) => void;
  setMosaicState: (state: MosaicNode<string> | null) => void;
  mosaicState: () => MosaicNode<string> | null;
};

class WorkspaceManagerImpl extends Events implements AppWorkspace {
  private readonly commands = new CommandsState(() => this.editorContextResolver?.() ?? null);
  private readonly shell = new ShellState();
  private readonly leafs = new LeafsState((leaf) => {
    const viewType = leaf.view?.getViewType();
    if (!viewType) return;
    this.shell.ensureSidebarPanel({
      id: viewType,
      viewType,
      title: leaf.getDisplayText(),
      icon: leaf.getIcon(),
    });
  });
  private editorContextResolver: EditorContextResolver | null = null;
  private activeDocumentResolver: ActiveDocumentResolver | null = null;
  appRef: App | null = null;

  constructor() {
    super();
  }

  init(): void {
    this.commands.init();
  }

  setAppRef(app: App): void {
    this.appRef = app;
    this.leafs.setAppRef(app);
  }

  setEditorContextResolver(resolver: EditorContextResolver): void {
    this.editorContextResolver = resolver;
  }

  setActiveDocumentResolver(resolver: ActiveDocumentResolver): void {
    this.activeDocumentResolver = resolver;
  }

  setMosaicOps(ops: MosaicOps): void {
    this.leafs.setMosaicOps(ops);
  }

  reset(): void {
    this.commands.reset();
    this.leafs.reset();
    this.shell.reset();
  }

  // --- View Registry ---

  registerView(type: string, viewCreator: ViewCreator): void {
    this.leafs.registerView(type, viewCreator);
  }

  unregisterView(type: string): void {
    this.leafs.unregisterView(type);
  }

  // --- Leaf operations ---

  getActiveViewOfType<T extends View>(viewType: abstract new (...args: unknown[]) => T): T | null {
    return this.leafs.getActiveViewOfType(viewType);
  }

  getActiveDocumentView(): DocumentView | null {
    return this.activeDocumentResolver?.() ?? null;
  }

  getLeavesOfType(viewType: string): WorkspaceLeaf[] {
    return this.leafs.getLeavesOfType(viewType);
  }

  getLeaf(newLeaf?: boolean | "split"): WorkspaceLeaf {
    return this.leafs.getLeaf(newLeaf);
  }

  getLeftLeaf(_split: boolean): WorkspaceLeaf | null {
    return this.leafs.getLeftLeaf(_split);
  }

  getRightLeaf(_split: boolean): WorkspaceLeaf | null {
    return this.leafs.getRightLeaf(_split);
  }

  getLeafById(id: string): WorkspaceLeaf | null {
    return this.leafs.getLeafById(id);
  }

  setActiveLeaf(leaf: WorkspaceLeaf, options?: { focus?: boolean }): void {
    this.leafs.setActiveLeaf(leaf, options);
    this.trigger("active-leaf-change", leaf);
  }

  syncMosaicLeaves(mosaicState: MosaicNode<string> | null): void {
    this.leafs.syncMosaicLeaves(mosaicState);
  }

  ensureLeaf(panelId: string): void {
    this.leafs.ensureLeaf(panelId);
  }

  setActiveLeafById(panelId: string): void {
    if (!panelId) {
      this.trigger("active-leaf-change", null);
      return;
    }
    const leaf = this.leafs.setActiveLeafById(panelId);
    this.trigger("active-leaf-change", leaf);
  }

  getActiveLeaf(): WorkspaceLeaf | null {
    return this.leafs.getActiveLeaf();
  }

  revealLeaf(leaf: WorkspaceLeaf): void {
    this.leafs.revealLeaf(leaf);
  }

  detachLeavesOfType(viewType: string): void {
    this.leafs.detachLeavesOfType(viewType);
  }

  // --- Setting Tabs ---

  addSettingTab(settingTab: SettingTabConfig): void {
    this.shell.addSettingTab(settingTab);
  }

  removeSettingTab(id: string): void {
    this.shell.removeSettingTab(id);
  }

  getSettingTabs(): Accessor<SettingTabConfig[]> {
    return this.shell.settingTabsAccessor;
  }

  // --- Command Registry ---

  addCommand(command: Command): Command {
    return this.commands.add(command);
  }

  removeCommand(commandId: string): void {
    this.commands.remove(commandId);
  }

  listCommands(): Command[] {
    return this.commands.list();
  }

  // --- Status Bar ---

  setStatusBarContainer(el: HTMLElement | null): void {
    this.shell.setStatusBarContainer(el);
  }

  addStatusBarItem(): HTMLElement {
    return this.shell.addStatusBarItem();
  }

  // --- Sidebar Panels ---

  addSidebarPanel(config: SidebarPanelConfig): void {
    this.shell.addSidebarPanel(config);
  }

  removeSidebarPanel(id: string): void {
    const viewType = this.shell.removeSidebarPanel(id);
    this.leafs.detachSidebarLeavesOfType(viewType);
  }

  getSidebarPanels(): Accessor<SidebarPanelConfig[]> {
    return this.shell.sidebarPanelsAccessor;
  }

  getActiveSidebarPanelId(): Accessor<string | null> {
    return this.shell.activeSidebarPanelIdAccessor;
  }

  getSidebarLeaf(viewType: string): WorkspaceLeaf | null {
    return this.leafs.getSidebarLeaf(viewType);
  }

  // --- Events (typed overloads) ---

  on(event: "active-leaf-change", cb: (leaf: WorkspaceLeaf | null) => void): EventRef;
  on(event: "layout-change", cb: () => void): EventRef;
  on(event: "editor-change", cb: (editor: unknown, view: unknown) => void): EventRef;
  on(event: "editor-menu", cb: (menu: unknown, editor: unknown, view: unknown) => void): EventRef;
  on(
    event: "editor-paste",
    cb: (evt: ClipboardEvent, editor: unknown, view: unknown) => void,
  ): EventRef;
  on(event: "editor-drop", cb: (evt: DragEvent, editor: unknown, view: unknown) => void): EventRef;
  on(event: "resize", cb: () => void): EventRef;
  on(event: "css-change", cb: () => void): EventRef;
  on(event: string, cb: (...data: never[]) => unknown, ctx?: unknown): EventRef {
    return super.on(event, cb as (...data: unknown[]) => unknown, ctx);
  }
}

export const workspaceManager = new WorkspaceManagerImpl();
