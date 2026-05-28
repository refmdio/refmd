import { createSignal, type Accessor, type Setter } from "solid-js";
import type {
  AuxiliaryPaneConfig,
  SettingTabConfig,
  SidebarPanelConfig,
  StatusBarItemConfig,
  WorkspaceTileConfig,
  WorkspaceSurfaceOwnerPredicate,
} from "@/shared/lib/workspace/app";
import { StatusBarState } from "./status-bar";

export interface RemovedShellSurfaces {
  sidebarViewTypes: string[];
  workspaceTileIds: string[];
}

export class ShellState {
  private sidebarPanels!: Accessor<SidebarPanelConfig[]>;
  private setSidebarPanels!: Setter<SidebarPanelConfig[]>;
  private activeSidebarPanelId!: Accessor<string | null>;
  private setActiveSidebarPanelId!: Setter<string | null>;
  private workspaceTiles!: Accessor<WorkspaceTileConfig[]>;
  private setWorkspaceTiles!: Setter<WorkspaceTileConfig[]>;
  private auxiliaryPanes!: Accessor<AuxiliaryPaneConfig[]>;
  private setAuxiliaryPanes!: Setter<AuxiliaryPaneConfig[]>;
  private settingTabs!: Accessor<SettingTabConfig[]>;
  private setSettingTabs!: Setter<SettingTabConfig[]>;
  private readonly statusBar = new StatusBarState();

  readonly sidebarPanelsAccessor: Accessor<SidebarPanelConfig[]>;
  readonly activeSidebarPanelIdAccessor: Accessor<string | null>;
  readonly workspaceTilesAccessor: Accessor<WorkspaceTileConfig[]>;
  readonly auxiliaryPanesAccessor: Accessor<AuxiliaryPaneConfig[]>;
  readonly settingTabsAccessor: Accessor<SettingTabConfig[]>;

  constructor() {
    [this.sidebarPanels, this.setSidebarPanels] = createSignal<SidebarPanelConfig[]>([]);
    [this.activeSidebarPanelId, this.setActiveSidebarPanelId] = createSignal<string | null>(null);
    [this.workspaceTiles, this.setWorkspaceTiles] = createSignal<WorkspaceTileConfig[]>([]);
    [this.auxiliaryPanes, this.setAuxiliaryPanes] = createSignal<AuxiliaryPaneConfig[]>([]);
    [this.settingTabs, this.setSettingTabs] = createSignal<SettingTabConfig[]>([]);
    this.sidebarPanelsAccessor = () => this.sidebarPanels();
    this.activeSidebarPanelIdAccessor = () => this.activeSidebarPanelId();
    this.workspaceTilesAccessor = () => this.workspaceTiles();
    this.auxiliaryPanesAccessor = () => this.auxiliaryPanes();
    this.settingTabsAccessor = () => this.settingTabs();
    this.reset();
  }

  reset(): void {
    this.setSidebarPanels([]);
    this.setActiveSidebarPanelId(null);
    this.setWorkspaceTiles([]);
    this.setAuxiliaryPanes([]);
    this.setSettingTabs([]);
    this.statusBar.reset();
  }

  ensureSidebarPanel(config: SidebarPanelConfig): string {
    const existing = this.sidebarPanels().find((panel) => panel.id === config.id);
    if (!existing) {
      this.setSidebarPanels([...this.sidebarPanels(), config]);
    }
    const activeId = existing?.id ?? config.id;
    this.setActiveSidebarPanelId(activeId);
    return activeId;
  }

  addSidebarPanel(config: SidebarPanelConfig): void {
    if (this.sidebarPanels().some((panel) => panel.id === config.id)) return;
    this.setSidebarPanels([...this.sidebarPanels(), config]);
    if (!this.activeSidebarPanelId()) {
      this.setActiveSidebarPanelId(config.id);
    }
  }

  removeSidebarPanel(id: string): string {
    const panel = this.sidebarPanels().find((item) => item.id === id);
    const viewType = panel?.viewType ?? id;
    const remaining = this.sidebarPanels().filter((item) => item.id !== id);
    this.setSidebarPanels(remaining);
    if (this.activeSidebarPanelId() === id) {
      this.setActiveSidebarPanelId(remaining.length > 0 ? remaining[0].id : null);
    }
    return viewType;
  }

  setActiveSidebarPanel(id: string): void {
    if (!this.sidebarPanels().some((panel) => panel.id === id)) return;
    this.setActiveSidebarPanelId(id);
  }

  addWorkspaceTile(config: WorkspaceTileConfig): void {
    if (this.workspaceTiles().some((panel) => panel.id === config.id)) return;
    this.setWorkspaceTiles([...this.workspaceTiles(), config]);
  }

  removeWorkspaceTile(id: string): void {
    this.setWorkspaceTiles(this.workspaceTiles().filter((panel) => panel.id !== id));
  }

  addAuxiliaryPane(config: AuxiliaryPaneConfig): void {
    if (this.auxiliaryPanes().some((pane) => pane.id === config.id)) return;
    this.setAuxiliaryPanes([...this.auxiliaryPanes(), config]);
  }

  removeAuxiliaryPane(id: string): void {
    this.setAuxiliaryPanes(this.auxiliaryPanes().filter((pane) => pane.id !== id));
  }

  addSettingTab(settingTab: SettingTabConfig): void {
    const tabs = this.settingTabs();
    const existingIndex = tabs.findIndex((tab) => tab.id === settingTab.id);
    if (existingIndex < 0) {
      this.setSettingTabs([...tabs, settingTab]);
      return;
    }
    const existing = tabs[existingIndex];
    if (existing === settingTab) return;
    existing.hide();
    this.setSettingTabs([
      ...tabs.slice(0, existingIndex),
      settingTab,
      ...tabs.slice(existingIndex + 1),
    ]);
  }

  removeSettingTab(id: string): void {
    this.setSettingTabs(this.settingTabs().filter((tab) => tab.id !== id));
  }

  removeSurfacesByOwner(predicate: WorkspaceSurfaceOwnerPredicate): RemovedShellSurfaces {
    const removedSidebarViewTypes: string[] = [];
    const remainingSidebarPanels: SidebarPanelConfig[] = [];
    for (const panel of this.sidebarPanels()) {
      if (panel.owner && predicate(panel.owner)) {
        removedSidebarViewTypes.push(panel.viewType ?? panel.id);
      } else {
        remainingSidebarPanels.push(panel);
      }
    }
    if (removedSidebarViewTypes.length > 0) {
      this.setSidebarPanels(remainingSidebarPanels);
      if (
        this.activeSidebarPanelId() &&
        !remainingSidebarPanels.some((panel) => panel.id === this.activeSidebarPanelId())
      ) {
        this.setActiveSidebarPanelId(
          remainingSidebarPanels.length > 0 ? remainingSidebarPanels[0].id : null,
        );
      }
    }

    const removedWorkspaceTileIds: string[] = [];
    const remainingWorkspaceTiles: WorkspaceTileConfig[] = [];
    for (const panel of this.workspaceTiles()) {
      if (panel.owner && predicate(panel.owner)) {
        removedWorkspaceTileIds.push(panel.id);
        panel.hide?.();
      } else {
        remainingWorkspaceTiles.push(panel);
      }
    }
    this.setWorkspaceTiles(remainingWorkspaceTiles);
    const remainingAuxiliaryPanes: AuxiliaryPaneConfig[] = [];
    for (const pane of this.auxiliaryPanes()) {
      if (pane.owner && predicate(pane.owner)) {
        pane.hide?.();
      } else {
        remainingAuxiliaryPanes.push(pane);
      }
    }
    this.setAuxiliaryPanes(remainingAuxiliaryPanes);

    const remainingSettingTabs: SettingTabConfig[] = [];
    for (const tab of this.settingTabs()) {
      if (tab.owner && predicate(tab.owner)) {
        tab.hide();
      } else {
        remainingSettingTabs.push(tab);
      }
    }
    this.setSettingTabs(remainingSettingTabs);
    this.statusBar.removeByOwner(predicate);
    return {
      sidebarViewTypes: removedSidebarViewTypes,
      workspaceTileIds: removedWorkspaceTileIds,
    };
  }

  setStatusBarContainer(element: HTMLElement | null): void {
    this.statusBar.setContainer(element);
  }

  addStatusBarItem(config?: StatusBarItemConfig): HTMLElement {
    return this.statusBar.addItem(config);
  }
}
