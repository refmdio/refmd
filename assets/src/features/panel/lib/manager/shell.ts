import { createSignal, type Accessor, type Setter } from "solid-js";
import type { SettingTabConfig, SidebarPanelConfig } from "@/shared/lib/workspace/app";
import { StatusBarState } from "./status-bar";

export class ShellState {
  private sidebarPanels!: Accessor<SidebarPanelConfig[]>;
  private setSidebarPanels!: Setter<SidebarPanelConfig[]>;
  private activeSidebarPanelId!: Accessor<string | null>;
  private setActiveSidebarPanelId!: Setter<string | null>;
  private settingTabs!: Accessor<SettingTabConfig[]>;
  private setSettingTabs!: Setter<SettingTabConfig[]>;
  private readonly statusBar = new StatusBarState();

  readonly sidebarPanelsAccessor: Accessor<SidebarPanelConfig[]>;
  readonly activeSidebarPanelIdAccessor: Accessor<string | null>;
  readonly settingTabsAccessor: Accessor<SettingTabConfig[]>;

  constructor() {
    this.sidebarPanelsAccessor = () => this.sidebarPanels();
    this.activeSidebarPanelIdAccessor = () => this.activeSidebarPanelId();
    this.settingTabsAccessor = () => this.settingTabs();
    this.reset();
  }

  reset(): void {
    [this.sidebarPanels, this.setSidebarPanels] = createSignal<SidebarPanelConfig[]>([]);
    [this.activeSidebarPanelId, this.setActiveSidebarPanelId] = createSignal<string | null>(null);
    [this.settingTabs, this.setSettingTabs] = createSignal<SettingTabConfig[]>([]);
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

  addSettingTab(settingTab: SettingTabConfig): void {
    if (this.settingTabs().some((tab) => tab.id === settingTab.id)) return;
    this.setSettingTabs([...this.settingTabs(), settingTab]);
  }

  removeSettingTab(id: string): void {
    this.setSettingTabs(this.settingTabs().filter((tab) => tab.id !== id));
  }

  setStatusBarContainer(element: HTMLElement | null): void {
    this.statusBar.setContainer(element);
  }

  addStatusBarItem(): HTMLElement {
    return this.statusBar.addItem();
  }
}
