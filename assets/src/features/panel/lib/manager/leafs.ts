import type { MosaicNode } from "solid-mosaic-component";
import type { App } from "@/shared/lib/workspace/app";
import type { ViewCreator, WorkspaceLeaf, View } from "@/shared/lib/workspace/view";
import { WorkspaceLeaf as WorkspaceLeafImpl } from "@/shared/lib/workspace/view";
import { pruneNodes } from "./mosaic-tree";

type SidebarLeafChange = (leaf: WorkspaceLeaf) => void;

type MosaicOps = {
  focusPanel: (panelId: string) => void;
  setMosaicState: (state: MosaicNode<string> | null) => void;
  mosaicState: () => MosaicNode<string> | null;
  openWorkspaceTile: (panelId: string, documentId?: string) => void;
  closeWorkspaceTiles: (tileIds: readonly string[]) => void;
};

export class LeafsState {
  private readonly viewRegistry = new Map<string, ViewCreator>();
  private readonly leaves = new Map<string, WorkspaceLeaf>();
  private readonly sidebarLeafIds = new Set<string>();
  private activeLeaf: WorkspaceLeaf | null = null;
  private appRef: App | null = null;
  private mosaicOps: MosaicOps | null = null;
  private readonly onSidebarLeafChange: SidebarLeafChange;

  constructor(onSidebarLeafChange: SidebarLeafChange) {
    this.onSidebarLeafChange = onSidebarLeafChange;
  }

  setAppRef(app: App): void {
    this.appRef = app;
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
  }

  registerView(type: string, creator: ViewCreator): void {
    this.viewRegistry.set(type, creator);
  }

  unregisterView(type: string): void {
    this.viewRegistry.delete(type);
    const removedIds: string[] = [];
    for (const [id, leaf] of this.leaves) {
      if (leaf.isDetached || leaf.view?.getViewType() !== type) continue;
      leaf.detach();
      this.leaves.delete(id);
      this.sidebarLeafIds.delete(id);
      removedIds.push(id);
    }
    if (removedIds.length === 0 || !this.mosaicOps) return;
    const state = this.mosaicOps.mosaicState();
    if (!state) return;
    const pruned = pruneNodes(state, new Set(removedIds));
    this.mosaicOps.setMosaicState(pruned ?? null);
  }

  getActiveViewOfType<T extends View>(viewType: abstract new (...args: unknown[]) => T): T | null {
    if (
      this.activeLeaf &&
      !this.activeLeaf.isDetached &&
      this.activeLeaf.view instanceof viewType
    ) {
      return this.activeLeaf.view as T;
    }
    for (const leaf of this.leaves.values()) {
      if (!leaf.isDetached && leaf.view instanceof viewType) {
        return leaf.view as T;
      }
    }
    return null;
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
    if (!newLeaf && this.activeLeaf && !this.activeLeaf.isDetached) {
      return this.activeLeaf;
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

  setActiveLeaf(leaf: WorkspaceLeaf, options?: { focus?: boolean }): void {
    this.activeLeaf = leaf;
    if (options?.focus !== false) {
      this.mosaicOps?.focusPanel(leaf.id);
    }
  }

  syncMosaicLeaves(mosaicState: MosaicNode<string> | null): void {
    const activePanelIds = new Set<string>();
    const collect = (node: MosaicNode<string> | null) => {
      if (typeof node === "string") {
        activePanelIds.add(node);
      } else if (node) {
        collect(node.first);
        collect(node.second);
      }
    };
    collect(mosaicState);

    for (const panelId of activePanelIds) {
      this.ensureLeaf(panelId);
    }

    for (const [id, leaf] of this.leaves) {
      if (this.sidebarLeafIds.has(id) || activePanelIds.has(id)) continue;
      leaf.detach();
      this.leaves.delete(id);
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
      const creator = this.viewRegistry.get(viewType);
      if (creator) {
        const view = creator(leaf);
        view.app = this.appRef;
        leaf.open(view);
      }
    }
    this.leaves.set(panelId, leaf);
  }

  setActiveLeafById(panelId: string): WorkspaceLeaf | null {
    if (!panelId) {
      this.activeLeaf = null;
      return null;
    }
    this.ensureLeaf(panelId);
    const leaf = this.leaves.get(panelId)!;
    this.activeLeaf = leaf;
    return leaf;
  }

  getActiveLeaf(): WorkspaceLeaf | null {
    return this.activeLeaf;
  }

  revealLeaf(leaf: WorkspaceLeaf): void {
    if (!leaf.view) return;
    if (!this.leaves.has(leaf.id)) {
      this.leaves.set(leaf.id, leaf);
    }
    const state = this.mosaicOps?.mosaicState();
    if (!this.mosaicOps) return;
    if (!state) {
      this.mosaicOps.setMosaicState(leaf.id);
      return;
    }
    this.mosaicOps.setMosaicState({
      direction: "row",
      first: state,
      second: leaf.id,
      splitPercentage: 70,
    });
  }

  openWorkspaceTile(panelId: string, documentId?: string): void {
    this.mosaicOps?.openWorkspaceTile(panelId, documentId);
  }

  closeWorkspaceTiles(tileIds: readonly string[]): void {
    this.mosaicOps?.closeWorkspaceTiles(tileIds);
  }

  detachLeavesOfType(viewType: string): void {
    for (const [id, leaf] of this.leaves) {
      if (leaf.isDetached || leaf.view?.getViewType() !== viewType) continue;
      leaf.detach();
      this.leaves.delete(id);
      this.sidebarLeafIds.delete(id);
    }
  }

  detachSidebarLeavesOfType(viewType: string): void {
    for (const [leafId, leaf] of this.leaves) {
      if (!this.sidebarLeafIds.has(leafId) || leaf.view?.getViewType() !== viewType) continue;
      leaf.detach();
      this.leaves.delete(leafId);
      this.sidebarLeafIds.delete(leafId);
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

  private createLeaf(): WorkspaceLeaf {
    const leaf = new WorkspaceLeafImpl();
    leaf.setViewResolver((type) => this.viewRegistry.get(type));
    if (this.appRef) leaf.setAppRef(this.appRef);
    leaf.setOnViewStateChange((currentLeaf) => this.handleLeafViewStateChange(currentLeaf));
    this.leaves.set(leaf.id, leaf);
    return leaf;
  }

  private handleLeafViewStateChange(leaf: WorkspaceLeaf): void {
    if (!this.sidebarLeafIds.has(leaf.id) || !leaf.view) return;
    this.onSidebarLeafChange(leaf);
  }
}
