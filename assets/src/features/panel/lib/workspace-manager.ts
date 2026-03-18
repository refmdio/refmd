import { createSignal, type Accessor } from "solid-js";
import { Events, type EventRef } from "@/shared/lib/events";
import type {
  App,
  AppWorkspace,
  Command,
  Hotkey,
  SettingTabConfig,
  SidebarPanelConfig,
} from "@/shared/lib/app-context";
import type { DocumentView } from "@/shared/lib/document-manager";
import type { ViewCreator, WorkspaceLeaf, View } from "@/shared/lib/view";
import { WorkspaceLeaf as WorkspaceLeafImpl } from "@/shared/lib/view";

const isMac = typeof navigator !== "undefined" && /Mac/.test(navigator.userAgent);

function matchesHotkey(e: KeyboardEvent, hotkey: Hotkey): boolean {
  const modifiers = new Set(hotkey.modifiers);
  const needCtrl = modifiers.has("Ctrl") || (!isMac && modifiers.has("Mod"));
  const needMeta = modifiers.has("Meta") || (isMac && modifiers.has("Mod"));
  const needShift = modifiers.has("Shift");
  const needAlt = modifiers.has("Alt");

  if (e.ctrlKey !== needCtrl) return false;
  if (e.metaKey !== needMeta) return false;
  if (e.shiftKey !== needShift) return false;
  if (e.altKey !== needAlt) return false;

  return e.key.toLowerCase() === hotkey.key.toLowerCase();
}

const [sidebarPanels, setSidebarPanels] = createSignal<SidebarPanelConfig[]>([]);
const [activeSidebarPanelId, setActiveSidebarPanelId] = createSignal<string | null>(null);
const [settingTabs, setSettingTabs] = createSignal<SettingTabConfig[]>([]);

type EditorContextResolver = () => { editor: unknown; doc: DocumentView } | null;
type ActiveDocumentResolver = () => DocumentView | null;

type MosaicOps = {
  focusPanel: (panelId: string) => void;
  setMosaicState: (state: any) => void;
  mosaicState: () => any;
};

export class WorkspaceManagerImpl extends Events implements AppWorkspace {
  private viewRegistry = new Map<string, ViewCreator>();
  private commandRegistry = new Map<string, Command>();
  private hotkeyHandler: ((e: KeyboardEvent) => void) | null = null;
  private statusBarContainer: HTMLElement | null = null;
  private pendingStatusBarItems: HTMLElement[] = [];

  // Leaf management: single map for ALL leaves (sidebar + mosaic + custom)
  private leaves = new Map<string, WorkspaceLeaf>();
  private sidebarLeafIds = new Set<string>();
  private activeLeaf: WorkspaceLeaf | null = null;

  private editorContextResolver: EditorContextResolver | null = null;
  private activeDocumentResolver: ActiveDocumentResolver | null = null;
  private mosaicOps: MosaicOps | null = null;
  appRef: App | null = null;

  constructor() {
    super();
    this.hotkeyHandler = this.handleHotkey.bind(this);
    if (typeof window !== "undefined") {
      window.addEventListener("keydown", this.hotkeyHandler, true);
    }
  }

  destroy(): void {
    if (this.hotkeyHandler && typeof window !== "undefined") {
      window.removeEventListener("keydown", this.hotkeyHandler, true);
    }
    for (const leaf of this.leaves.values()) {
      leaf.detach();
    }
    this.leaves.clear();
    this.sidebarLeafIds.clear();
  }

  setAppRef(app: App): void {
    this.appRef = app;
  }

  setEditorContextResolver(resolver: EditorContextResolver): void {
    this.editorContextResolver = resolver;
  }

  setActiveDocumentResolver(resolver: ActiveDocumentResolver): void {
    this.activeDocumentResolver = resolver;
  }

  setMosaicOps(ops: MosaicOps): void {
    this.mosaicOps = ops;
  }

  reset(): void {
    for (const leaf of this.leaves.values()) {
      leaf.detach();
    }
    this.leaves.clear();
    this.sidebarLeafIds.clear();
    this.activeLeaf = null;
    this.viewRegistry.clear();
    this.commandRegistry.clear();
    setSidebarPanels([]);
    setActiveSidebarPanelId(null);
    setSettingTabs([]);
    if (this.statusBarContainer) {
      this.statusBarContainer.innerHTML = "";
    }
  }

  private handleHotkey(e: KeyboardEvent): void {
    if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
    for (const cmd of this.commandRegistry.values()) {
      if (!cmd.hotkeys) continue;
      for (const hotkey of cmd.hotkeys) {
        if (matchesHotkey(e, hotkey)) {
          e.preventDefault();
          e.stopPropagation();
          this.executeCommand(cmd);
          return;
        }
      }
    }
  }

  private executeCommand(cmd: Command): void {
    if (cmd.editorCheckCallback) {
      const ctx = this.editorContextResolver?.();
      if (ctx) {
        const canRun = cmd.editorCheckCallback(true, ctx.editor, ctx.doc);
        if (canRun) cmd.editorCheckCallback(false, ctx.editor, ctx.doc);
      }
    } else if (cmd.editorCallback) {
      const ctx = this.editorContextResolver?.();
      if (ctx) {
        cmd.editorCallback(ctx.editor, ctx.doc);
      }
    } else if (cmd.checkCallback) {
      const canRun = cmd.checkCallback(true);
      if (canRun) cmd.checkCallback(false);
    } else if (cmd.callback) {
      cmd.callback();
    }
  }

  // --- Leaf creation ---

  private createLeaf(): WorkspaceLeaf {
    const leaf = new WorkspaceLeafImpl();
    leaf.setViewResolver((type) => this.viewRegistry.get(type));
    if (this.appRef) leaf.setAppRef(this.appRef);
    leaf.setOnViewStateChange((l) => this.handleLeafViewStateChange(l));
    this.leaves.set(leaf.id, leaf);
    return leaf;
  }

  private handleLeafViewStateChange(leaf: WorkspaceLeaf): void {
    if (!this.sidebarLeafIds.has(leaf.id)) return;
    if (!leaf.view) return;
    const viewType = leaf.view.getViewType();
    const existing = sidebarPanels().find((p) => p.viewType === viewType);
    if (!existing) {
      this.addSidebarPanel({
        id: viewType,
        viewType,
        title: leaf.getDisplayText(),
        icon: leaf.getIcon(),
      });
    }
    setActiveSidebarPanelId(existing?.id ?? viewType);
  }

  // --- View Registry ---

  registerView(type: string, viewCreator: ViewCreator): void {
    this.viewRegistry.set(type, viewCreator);
  }

  unregisterView(type: string): void {
    this.viewRegistry.delete(type);
    const removedIds: string[] = [];
    for (const [id, leaf] of this.leaves) {
      if (!leaf.isDetached && leaf.view?.getViewType() === type) {
        leaf.detach();
        this.leaves.delete(id);
        this.sidebarLeafIds.delete(id);
        removedIds.push(id);
      }
    }
    if (removedIds.length > 0 && this.mosaicOps) {
      const state = this.mosaicOps.mosaicState();
      if (state) {
        const removedSet = new Set(removedIds);
        const pruned = pruneNodes(state, removedSet);
        this.mosaicOps.setMosaicState(pruned ?? null);
      }
    }
  }

  getViewCreator(type: string): ViewCreator | undefined {
    return this.viewRegistry.get(type);
  }

  // --- Leaf operations ---

  getActiveViewOfType<T extends View>(_type: { new (...args: any[]): T }): T | null {
    if (this.activeLeaf && !this.activeLeaf.isDetached && this.activeLeaf.view instanceof _type) {
      return this.activeLeaf.view as T;
    }
    for (const leaf of this.leaves.values()) {
      if (!leaf.isDetached && leaf.view instanceof _type) {
        return leaf.view as T;
      }
    }
    return null;
  }

  getActiveDocumentView(): DocumentView | null {
    return this.activeDocumentResolver?.() ?? null;
  }

  getLeavesOfType(viewType: string): WorkspaceLeaf[] {
    const result: WorkspaceLeaf[] = [];
    for (const leaf of this.leaves.values()) {
      if (!leaf.isDetached && leaf.view?.getViewType() === viewType) {
        result.push(leaf);
      }
    }
    return result;
  }

  getLeaf(newLeaf?: boolean | "split"): WorkspaceLeaf {
    if (!newLeaf) {
      if (this.activeLeaf && !this.activeLeaf.isDetached) {
        return this.activeLeaf;
      }
    }
    return this.createLeaf();
  }

  getLeftLeaf(_split: boolean): WorkspaceLeaf | null {
    const leaf = this.createLeaf();
    this.sidebarLeafIds.add(leaf.id);
    return leaf;
  }

  getRightLeaf(_split: boolean): WorkspaceLeaf | null {
    const leaf = this.createLeaf();
    this.sidebarLeafIds.add(leaf.id);
    return leaf;
  }

  getLeafById(id: string): WorkspaceLeaf | null {
    return this.leaves.get(id) ?? null;
  }

  setActiveLeaf(leaf: WorkspaceLeaf, _options?: { focus?: boolean }): void {
    this.activeLeaf = leaf;
    this.mosaicOps?.focusPanel(leaf.id);
    this.trigger("active-leaf-change", leaf);
  }

  syncMosaicLeaves(mosaicState: any): void {
    const activePanelIds = new Set<string>();
    const collect = (node: any) => {
      if (typeof node === "string") activePanelIds.add(node);
      else if (node) {
        collect(node.first);
        collect(node.second);
      }
    };
    collect(mosaicState);

    for (const pid of activePanelIds) {
      this.ensureLeaf(pid);
    }

    for (const [id, leaf] of this.leaves) {
      if (this.sidebarLeafIds.has(id)) continue;
      if (!activePanelIds.has(id)) {
        leaf.detach();
        this.leaves.delete(id);
      }
    }
  }

  ensureLeaf(panelId: string): void {
    if (!panelId || this.leaves.has(panelId)) return;
    const leaf = new WorkspaceLeafImpl(panelId);
    leaf.setViewResolver((type) => this.viewRegistry.get(type));
    if (this.appRef) leaf.setAppRef(this.appRef);
    const parts = panelId.split(":");
    if (parts.length >= 2) {
      const viewType = parts[1] === "markdown" || parts[1] === "wysiwyg" ? parts[1] : "document";
      leaf.view = {
        getViewType: () => viewType,
        getDisplayText: () => panelId,
        containerEl: document.createElement("div"),
        app: this.appRef,
        icon: "",
        navigation: true,
        leaf,
        onOpen: async () => {},
        onClose: async () => {},
        getState: () => ({}),
        setState: async () => {},
        getEphemeralState: () => ({}),
        setEphemeralState: () => {},
        getIcon: () => "",
        onResize: () => {},
        onPaneMenu: () => {},
      } as View;
    }
    this.leaves.set(panelId, leaf);
  }

  setActiveLeafById(panelId: string): void {
    if (!panelId) {
      this.activeLeaf = null;
      this.trigger("active-leaf-change", null);
      return;
    }
    this.ensureLeaf(panelId);
    const leaf = this.leaves.get(panelId)!;
    this.activeLeaf = leaf;
    this.trigger("active-leaf-change", leaf);
  }

  getActiveLeaf(): WorkspaceLeaf | null {
    return this.activeLeaf;
  }

  revealLeaf(leaf: WorkspaceLeaf): void {
    if (!leaf.view) return;
    if (!this.leaves.has(leaf.id)) {
      this.leaves.set(leaf.id, leaf);
    }
    if (this.mosaicOps) {
      const state = this.mosaicOps.mosaicState();
      if (!state) {
        this.mosaicOps.setMosaicState(leaf.id);
      } else {
        this.mosaicOps.setMosaicState({
          direction: "row",
          first: state,
          second: leaf.id,
          splitPercentage: 70,
        });
      }
    }
  }

  detachLeavesOfType(viewType: string): void {
    for (const [id, leaf] of this.leaves) {
      if (!leaf.isDetached && leaf.view?.getViewType() === viewType) {
        leaf.detach();
        this.leaves.delete(id);
        this.sidebarLeafIds.delete(id);
      }
    }
  }

  // --- Setting Tabs ---

  addSettingTab(settingTab: SettingTabConfig): void {
    const existing = settingTabs();
    if (existing.some((t) => t.id === settingTab.id)) return;
    setSettingTabs([...existing, settingTab]);
  }

  removeSettingTab(id: string): void {
    setSettingTabs(settingTabs().filter((t) => t.id !== id));
  }

  getSettingTabs(): Accessor<SettingTabConfig[]> {
    return settingTabs;
  }

  // --- Command Registry ---

  addCommand(command: Command): Command {
    this.commandRegistry.set(command.id, command);
    return command;
  }

  removeCommand(commandId: string): void {
    this.commandRegistry.delete(commandId);
  }

  listCommands(): Command[] {
    return [...this.commandRegistry.values()];
  }

  // --- Status Bar ---

  setStatusBarContainer(el: HTMLElement | null): void {
    this.statusBarContainer = el;
    if (el) {
      for (const item of this.pendingStatusBarItems) {
        el.appendChild(item);
      }
      this.pendingStatusBarItems = [];
    }
  }

  addStatusBarItem(): HTMLElement {
    const item = document.createElement("span");
    item.classList.add("status-bar-item");
    if (this.statusBarContainer) {
      this.statusBarContainer.appendChild(item);
    } else {
      this.pendingStatusBarItems.push(item);
    }
    return item;
  }

  // --- Sidebar Panels ---

  addSidebarPanel(config: SidebarPanelConfig): void {
    const existing = sidebarPanels();
    if (existing.some((p) => p.id === config.id)) return;
    setSidebarPanels([...existing, config]);
    if (!activeSidebarPanelId()) {
      setActiveSidebarPanelId(config.id);
    }
  }

  removeSidebarPanel(id: string): void {
    const panel = sidebarPanels().find((p) => p.id === id);
    const viewType = panel?.viewType ?? id;
    const remaining = sidebarPanels().filter((p) => p.id !== id);
    setSidebarPanels(remaining);
    if (activeSidebarPanelId() === id) {
      setActiveSidebarPanelId(remaining.length > 0 ? remaining[0].id : null);
    }
    for (const [leafId, leaf] of this.leaves) {
      if (this.sidebarLeafIds.has(leafId) && leaf.view?.getViewType() === viewType) {
        leaf.detach();
        this.leaves.delete(leafId);
        this.sidebarLeafIds.delete(leafId);
      }
    }
  }

  getSidebarPanels(): Accessor<SidebarPanelConfig[]> {
    return sidebarPanels;
  }

  getActiveSidebarPanelId(): Accessor<string | null> {
    return activeSidebarPanelId;
  }

  setActiveSidebarPanel(id: string): void {
    if (sidebarPanels().some((p) => p.id === id)) {
      setActiveSidebarPanelId(id);
    }
  }

  getSidebarLeaf(viewType: string): WorkspaceLeaf | null {
    for (const id of this.sidebarLeafIds) {
      const leaf = this.leaves.get(id);
      if (leaf && !leaf.isDetached && leaf.view?.getViewType() === viewType) {
        return leaf;
      }
    }

    const creator = this.viewRegistry.get(viewType);
    if (!creator) return null;

    const leaf = this.createLeaf();
    this.sidebarLeafIds.add(leaf.id);
    const view = creator(leaf);
    view.app = this.appRef;
    leaf.open(view);
    return leaf;
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
  on(event: string, cb: (...data: any[]) => any, ctx?: unknown): EventRef {
    return super.on(event, cb, ctx);
  }
}

function pruneNodes(node: any, removedIds: Set<string>): any {
  if (typeof node === "string") {
    return removedIds.has(node) ? null : node;
  }
  if (!node) return null;
  const first = pruneNodes(node.first, removedIds);
  const second = pruneNodes(node.second, removedIds);
  if (first == null && second == null) return null;
  if (first == null) return second;
  if (second == null) return first;
  return { ...node, first, second };
}

export const workspaceManager = new WorkspaceManagerImpl();
