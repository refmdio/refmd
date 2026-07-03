import { createRoot, createSignal } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import type { MosaicNode } from "solid-mosaic-component";
import { createBalancedTreeFromLeaves } from "solid-mosaic-component";
import { authState } from "@/entities/session";
import type { SettingsResponse } from "@/shared/api";
import type { WorkspaceDocumentQueryConfig } from "@/shared/lib/workspace/app";
import {
  createWorkspaceTileTarget,
  decodePanelId,
  decodeWorkspacePluginTileId,
  encodePanelIdForTarget,
  encodeWorkspacePluginTileId,
  extractDocumentSubtrees,
  findFirstDocumentId,
  findFirstPanelId,
  findFirstPanelIdByTargetKey,
  findScrollGroupPeerId,
  hasTargetPanels,
  normalizePanelTarget,
  removeFromMosaic,
  replacePanelIdInMosaic,
  replacePanelInMosaic,
  type OpenPanelTargetInput,
  type PanelTarget,
  type PanelType,
} from "../../lib/workspace/panel-utils";

type EditorMode = "markdown" | "wysiwyg" | "split";
type QueryClient = ReturnType<typeof useQueryClient>;
export interface WorkspaceTileActionRecord {
  actionId: string;
  tileId: string;
  tileInstanceId: string;
  documentId?: string;
  kind?: "tile_action";
  tileActionId?: string;
  documentQuery?: WorkspaceDocumentQueryConfig;
  issuedAtMs: number;
}
function getPrimaryPanelId(node: MosaicNode<string>): string {
  return typeof node === "string" ? node : getPrimaryPanelId(node.first);
}
function createPanelWorkspaceContext(queryClient: QueryClient, disposeRoot: () => void) {
  const [openDocuments, setOpenDocuments] = createSignal<Map<string, PanelTarget>>(new Map());
  const [mosaicState, setMosaicState] = createSignal<MosaicNode<string> | null>(null);
  const [focusedPanelIdSignal, setFocusedPanelIdSignal] = createSignal<string | null>(null);
  const workspaceTileActions = new Map<string, WorkspaceTileActionRecord>();
  let scrollGroupCounter = 0;
  function generateScrollGroupId(): string {
    return `sg-${Date.now()}-${++scrollGroupCounter}`;
  }
  function resetWorkspace() {
    setOpenDocuments(new Map());
    setMosaicState(null);
    setFocusedPanelIdSignal(null);
    workspaceTileActions.clear();
  }
  function dispose() {
    resetWorkspace();
    disposeRoot();
  }
  function getDefaultEditorMode(): EditorMode {
    const userId = authState()?.user?.id;
    const settings = queryClient.getQueryData<SettingsResponse>(["settings", userId ?? "anon"]);
    const mode = settings?.editor_default_mode;
    if (mode === "markdown" || mode === "wysiwyg" || mode === "split") return mode;
    return "split";
  }
  function getLayoutMode(): "tiling" | "horizontal" | "vertical" {
    const userId = authState()?.user?.id;
    const settings = queryClient.getQueryData<SettingsResponse>(["settings", userId ?? "anon"]);
    const mode = settings?.editor_layout_mode;
    if (mode === "horizontal" || mode === "vertical") return mode;
    return "tiling";
  }
  function createSplitNode(target: PanelTarget): MosaicNode<string> {
    const mode = getDefaultEditorMode();
    const scrollGroupId = generateScrollGroupId();
    if (mode === "markdown") {
      return encodePanelIdForTarget(target, "markdown", undefined, scrollGroupId);
    }
    if (mode === "wysiwyg") {
      return encodePanelIdForTarget(target, "wysiwyg", undefined, scrollGroupId);
    }
    return createMarkdownPreviewSplit(target, scrollGroupId, "row").node;
  }
  function createMarkdownPreviewSplit(
    target: PanelTarget,
    scrollGroupId: string,
    direction: "row" | "column",
  ): { node: MosaicNode<string>; markdownPanelId: string; previewPanelId: string } {
    const markdownPanelId = encodePanelIdForTarget(target, "markdown", undefined, scrollGroupId);
    const previewPanelId = encodePanelIdForTarget(target, "preview", undefined, scrollGroupId);
    return {
      node: {
        direction,
        first: markdownPanelId,
        second: previewPanelId,
        splitPercentage: 50,
      },
      markdownPanelId,
      previewPanelId,
    };
  }
  const focusedDocumentId = () => {
    const panelId = focusedPanelIdSignal();
    if (!panelId) return null;
    return (
      decodePanelId(panelId)?.documentId ?? decodeWorkspacePluginTileId(panelId)?.documentId ?? null
    );
  };
  const focusedPanelType = (): PanelType => {
    const panelId = focusedPanelIdSignal();
    if (!panelId) return "markdown";
    return decodePanelId(panelId)?.type ?? "markdown";
  };
  function openDocument(input: OpenPanelTargetInput) {
    const target = normalizePanelTarget(input);
    const state = mosaicState();
    if (state && hasTargetPanels(state, target.targetKey)) {
      setOpenDocuments((previous) => {
        const next = new Map(previous);
        next.set(target.targetKey, { ...next.get(target.targetKey), ...target });
        return next;
      });
      const panelId = findFirstPanelIdByTargetKey(state, target.targetKey);
      if (panelId) setFocusedPanelIdSignal(panelId);
      return;
    }
    const splitNode = createSplitNode(target);
    const docs = new Map<string, PanelTarget>();
    docs.set(target.targetKey, target);
    setOpenDocuments(docs);
    setMosaicState(splitNode);
    setFocusedPanelIdSignal(getPrimaryPanelId(splitNode));
  }
  function refreshDocument(input: OpenPanelTargetInput) {
    const target = normalizePanelTarget(input);
    const state = mosaicState();
    if (!state || !hasTargetPanels(state, target.targetKey)) {
      openDocument(target);
      return;
    }

    const remountedPanelIds: string[] = [];
    const remountTargetPanels = (node: MosaicNode<string>): MosaicNode<string> => {
      if (typeof node === "string") {
        const panel = decodePanelId(node);
        if (!panel || panel.targetKey !== target.targetKey) return node;

        const nextId = encodePanelIdForTarget(target, panel.type, undefined, panel.scrollGroupId);
        remountedPanelIds.push(nextId);
        return nextId;
      }
      return {
        ...node,
        first: remountTargetPanels(node.first),
        second: remountTargetPanels(node.second),
      };
    };

    setOpenDocuments((previous) => {
      const next = new Map(previous);
      next.set(target.targetKey, { ...next.get(target.targetKey), ...target });
      return next;
    });
    setMosaicState(remountTargetPanels(state));
    const previousFocusedPanel = focusedPanelIdSignal();
    if (previousFocusedPanel) {
      const previousPanel = decodePanelId(previousFocusedPanel);
      if (previousPanel?.targetKey === target.targetKey) {
        setFocusedPanelIdSignal(remountedPanelIds[0] ?? null);
        return;
      }
    }
    if (remountedPanelIds[0]) setFocusedPanelIdSignal(remountedPanelIds[0]);
  }
  function addToTile(input: OpenPanelTargetInput) {
    const target = normalizePanelTarget(input);
    setOpenDocuments((previous) => {
      const next = new Map(previous);
      next.set(target.targetKey, { ...next.get(target.targetKey), ...target });
      return next;
    });
    const splitNode = createSplitNode(target);
    const state = mosaicState();
    if (!state) {
      setMosaicState(splitNode);
    } else {
      const layout = getLayoutMode();
      if (layout === "horizontal" || layout === "vertical") {
        const existingCount = extractDocumentSubtrees(state).length;
        const totalCount = existingCount + 1;
        setMosaicState({
          direction: layout === "horizontal" ? "row" : "column",
          first: state,
          second: splitNode,
          splitPercentage: (existingCount / totalCount) * 100,
        });
      } else {
        const existingUnits = extractDocumentSubtrees(state);
        const allUnits: MosaicNode<string>[] = [...existingUnits, splitNode];
        setMosaicState(createBalancedTreeFromLeaves(allUnits));
      }
    }
    setFocusedPanelIdSignal(getPrimaryPanelId(splitNode));
  }
  function openWorkspaceTile(tileId: string, documentId?: string) {
    const state = mosaicState();
    const existingPanelId = state ? findWorkspacePluginTileId(state, tileId, documentId) : null;
    if (existingPanelId) {
      const existingPanel = decodeWorkspacePluginTileId(existingPanelId);
      if (!existingPanel) {
        setFocusedPanelIdSignal(existingPanelId);
        return;
      }
      discardWorkspaceTileAction(existingPanelId, workspaceTileActions);
      const workspaceTileId = createWorkspaceTileActionPanelId(
        tileId,
        documentId,
        existingPanel.instanceId,
      );
      setMosaicState(replacePanelIdInMosaic(state!, existingPanelId, workspaceTileId));
      setFocusedPanelIdSignal(workspaceTileId);
      return;
    }

    const workspaceTileId = createWorkspaceTileActionPanelId(tileId, documentId);
    if (!state) {
      setMosaicState(workspaceTileId);
      setFocusedPanelIdSignal(workspaceTileId);
      return;
    }
    setMosaicState({
      direction: "row",
      first: state,
      second: workspaceTileId,
      splitPercentage: 70,
    });
    setFocusedPanelIdSignal(workspaceTileId);
  }
  function createWorkspaceTileActionPanelId(
    tileId: string,
    documentId?: string,
    instanceId?: string,
    options: {
      kind?: "tile_action";
      tileActionId?: string;
      documentQuery?: WorkspaceDocumentQueryConfig;
    } = {},
  ): string {
    const actionId = generateWorkspaceTileActionId();
    const workspaceTileId = encodeWorkspacePluginTileId(tileId, documentId, instanceId, actionId);
    workspaceTileActions.set(actionId, {
      actionId,
      tileId,
      tileInstanceId: workspaceTileId,
      documentId,
      ...(options.kind ? { kind: options.kind } : {}),
      ...(options.tileActionId ? { tileActionId: options.tileActionId } : {}),
      ...(options.documentQuery ? { documentQuery: options.documentQuery } : {}),
      issuedAtMs: Date.now(),
    });
    return workspaceTileId;
  }
  function invokeWorkspaceTileAction(
    panelId: string,
    options: { tileActionId?: string; documentQuery?: WorkspaceDocumentQueryConfig } = {},
  ) {
    const state = mosaicState();
    if (!state) return;
    const decoded = decodeWorkspacePluginTileId(panelId);
    if (!decoded) return;
    discardWorkspaceTileAction(panelId, workspaceTileActions);
    const workspaceTileId = createWorkspaceTileActionPanelId(
      decoded.tileId,
      decoded.documentId,
      decoded.instanceId,
      {
        kind: "tile_action",
        tileActionId: options.tileActionId,
        documentQuery: options.documentQuery,
      },
    );
    setMosaicState(replacePanelIdInMosaic(state, panelId, workspaceTileId));
    setFocusedPanelIdSignal(workspaceTileId);
  }
  function closePanel(panelId: string) {
    const state = mosaicState();
    if (!state) return;
    const newState = removeFromMosaic(state, panelId);
    discardWorkspaceTileAction(panelId, workspaceTileActions);
    setMosaicState(newState);
    if (!newState) {
      setOpenDocuments(new Map());
      setFocusedPanelIdSignal(null);
      return;
    }
    setOpenDocuments((targets) => {
      const next = new Map(targets);
      for (const targetKey of next.keys()) {
        if (!hasTargetPanels(newState, targetKey)) next.delete(targetKey);
      }
      return next;
    });
    if (focusedPanelIdSignal() === panelId) {
      const firstDocumentId = findFirstDocumentId(newState);
      if (firstDocumentId) {
        setFocusedPanelIdSignal(findFirstPanelId(newState, firstDocumentId));
      } else {
        setFocusedPanelIdSignal(null);
      }
    }
  }
  function closeWorkspaceTiles(tileIds: readonly string[]) {
    if (tileIds.length === 0) return;
    const state = mosaicState();
    if (!state) return;

    const targetTileIds = new Set(tileIds);
    const panelIds: string[] = [];
    collectWorkspacePluginTilePanelIds(state, targetTileIds, panelIds);
    if (panelIds.length === 0) return;

    let newState: MosaicNode<string> | null = state;
    for (const panelId of panelIds) {
      if (!newState) break;
      newState = removeFromMosaic(newState, panelId);
    }
    for (const [actionId, action] of workspaceTileActions) {
      if (targetTileIds.has(action.tileId)) workspaceTileActions.delete(actionId);
    }
    setMosaicState(newState);
    if (!newState) {
      setOpenDocuments(new Map());
      setFocusedPanelIdSignal(null);
      return;
    }
    setOpenDocuments((targets) => {
      const next = new Map(targets);
      for (const targetKey of next.keys()) {
        if (!hasTargetPanels(newState!, targetKey)) next.delete(targetKey);
      }
      return next;
    });
    const focusedPanelId = focusedPanelIdSignal();
    if (focusedPanelId && panelIds.includes(focusedPanelId)) {
      setFocusedPanelIdSignal(getPrimaryPanelId(newState));
    }
  }
  function splitPanel(panelId: string, direction: "row" | "column") {
    const workspaceTile = decodeWorkspacePluginTileId(panelId);
    if (workspaceTile) {
      splitWorkspaceTilePanel(panelId, workspaceTile, direction);
      return;
    }
    const panel = decodePanelId(panelId);
    if (!panel) return;
    const pairGroupId = generateScrollGroupId();
    const target =
      openDocuments().get(panel.targetKey) ?? createWorkspaceTileTarget(panel.documentId);
    const state = mosaicState();
    if (!state) return;
    const split = createMarkdownPreviewSplit(target, pairGroupId, direction);
    setMosaicState(replacePanelInMosaic(state, panelId, split.node));
    if (focusedPanelIdSignal() === panelId) {
      setFocusedPanelIdSignal(split.markdownPanelId);
    }
  }
  function splitWorkspaceTilePanel(
    panelId: string,
    panel: NonNullable<ReturnType<typeof decodeWorkspacePluginTileId>>,
    direction: "row" | "column",
  ) {
    const state = mosaicState();
    if (!state) return;
    discardWorkspaceTileAction(panelId, workspaceTileActions);
    const updatedPanelId = createWorkspaceTileActionPanelId(
      panel.tileId,
      panel.documentId,
      panel.instanceId,
    );
    const newPanelId = createWorkspaceTileActionPanelId(panel.tileId, panel.documentId);
    setMosaicState(
      replacePanelInMosaic(state, panelId, {
        direction,
        first: updatedPanelId,
        second: newPanelId,
        splitPercentage: 50,
      }),
    );
    if (focusedPanelIdSignal() === panelId) {
      setFocusedPanelIdSignal(updatedPanelId);
    }
  }
  function switchToSplit(panelId: string) {
    const panel = decodePanelId(panelId);
    if (!panel) return;
    const pairGroupId = generateScrollGroupId();
    const target =
      openDocuments().get(panel.targetKey) ?? createWorkspaceTileTarget(panel.documentId);
    const state = mosaicState();
    if (!state) return;
    const split = createMarkdownPreviewSplit(target, pairGroupId, "row");
    setMosaicState(replacePanelInMosaic(state, panelId, split.node));
    if (focusedPanelIdSignal() === panelId) {
      setFocusedPanelIdSignal(split.markdownPanelId);
    }
  }
  function switchPanelType(panelId: string) {
    const panel = decodePanelId(panelId);
    if (!panel) return;
    const newType: PanelType = panel.type === "markdown" ? "wysiwyg" : "markdown";
    const target =
      openDocuments().get(panel.targetKey) ?? createWorkspaceTileTarget(panel.documentId);
    const newPanelId = encodePanelIdForTarget(
      target,
      newType,
      panel.instanceId,
      panel.scrollGroupId,
    );
    const state = mosaicState();
    if (!state) return;
    setMosaicState(replacePanelIdInMosaic(state, panelId, newPanelId));
    if (focusedPanelIdSignal() === panelId) {
      setFocusedPanelIdSignal(newPanelId);
    }
  }
  function collapseSplitTo(panelId: string, targetType: PanelType) {
    const panel = decodePanelId(panelId);
    if (!panel) return;
    const state = mosaicState();
    if (!state) return;
    const peerId = findScrollGroupPeerId(state, panel.scrollGroupId, panelId);
    if (!peerId) return;
    const peer = decodePanelId(peerId);
    const keepExistingId =
      panel.type === targetType ? panelId : peer?.type === targetType ? peerId : null;
    const target =
      openDocuments().get(panel.targetKey) ?? createWorkspaceTileTarget(panel.documentId);
    const removeId = keepExistingId === panelId ? peerId : panelId;
    let newState = removeFromMosaic(state, removeId);
    let nextFocusId = keepExistingId;
    if (!keepExistingId && newState) {
      const replacementId = encodePanelIdForTarget(target, targetType);
      const remainingId = removeId === panelId ? peerId : panelId;
      newState = replacePanelIdInMosaic(newState, remainingId, replacementId);
      nextFocusId = replacementId;
    }
    setMosaicState(newState);
    if (
      focusedPanelIdSignal() === removeId ||
      focusedPanelIdSignal() === panelId ||
      focusedPanelIdSignal() === peerId
    ) {
      setFocusedPanelIdSignal(newState ? nextFocusId : null);
    }
  }
  function focusPanel(panelId: string) {
    setFocusedPanelIdSignal(panelId);
  }
  function consumeWorkspaceTileAction(
    actionId: string | undefined,
    tileId: string,
    tileInstanceId: string,
    documentId?: string,
  ): WorkspaceTileActionRecord | undefined {
    if (!actionId) return undefined;
    const action = workspaceTileActions.get(actionId);
    workspaceTileActions.delete(actionId);
    if (!action) return undefined;
    if (
      action.tileId !== tileId ||
      action.tileInstanceId !== tileInstanceId ||
      action.documentId !== documentId
    ) {
      return undefined;
    }
    return action;
  }
  function handleMosaicChange(newState: MosaicNode<string> | null) {
    setMosaicState(newState);
  }
  return {
    addToTile,
    closePanel,
    collapseSplitTo,
    dispose,
    focusPanel,
    focusedDocumentId,
    focusedPanelId: focusedPanelIdSignal,
    focusedPanelType,
    getLayoutMode,
    handleMosaicChange,
    mosaicState,
    openDocument,
    openDocuments,
    refreshDocument,
    resetWorkspace,
    setMosaicState,
    splitPanel,
    invokeWorkspaceTileAction,
    switchPanelType,
    switchToSplit,
    closeWorkspaceTiles,
    openWorkspaceTile,
    consumeWorkspaceTileAction,
  };
}

function collectWorkspacePluginTilePanelIds(
  node: MosaicNode<string>,
  tileIds: ReadonlySet<string>,
  panelIds: string[],
): void {
  if (typeof node === "string") {
    const panel = decodeWorkspacePluginTileId(node);
    if (panel && tileIds.has(panel.tileId)) panelIds.push(node);
    return;
  }
  collectWorkspacePluginTilePanelIds(node.first, tileIds, panelIds);
  collectWorkspacePluginTilePanelIds(node.second, tileIds, panelIds);
}

function findWorkspacePluginTileId(
  node: MosaicNode<string>,
  tileId: string,
  documentId?: string,
): string | null {
  if (typeof node === "string") {
    const panel = decodeWorkspacePluginTileId(node);
    if (panel?.tileId === tileId && panel.documentId === documentId) return node;
    return null;
  }

  return (
    findWorkspacePluginTileId(node.first, tileId, documentId) ??
    findWorkspacePluginTileId(node.second, tileId, documentId)
  );
}

function discardWorkspaceTileAction(
  panelId: string,
  actions: Map<string, WorkspaceTileActionRecord>,
): void {
  const panel = decodeWorkspacePluginTileId(panelId);
  if (!panel) return;
  if (panel.actionId) {
    actions.delete(panel.actionId);
    return;
  }
  for (const [actionId, action] of actions) {
    if (action.tileInstanceId === panelId) actions.delete(actionId);
  }
}

type PanelWorkspaceContext = ReturnType<typeof createPanelWorkspaceContext>;
let panelWorkspaceContext: PanelWorkspaceContext | null = null;
let panelWorkspaceRetainCount = 0;
let panelWorkspaceDisposeTimer: ReturnType<typeof setTimeout> | null = null;
export function disposePanelWorkspace(): void {
  if (panelWorkspaceDisposeTimer) {
    clearTimeout(panelWorkspaceDisposeTimer);
    panelWorkspaceDisposeTimer = null;
  }
  panelWorkspaceContext?.dispose();
  panelWorkspaceContext = null;
  panelWorkspaceRetainCount = 0;
}
export function usePanelWorkspace() {
  const queryClient = useQueryClient();
  if (!panelWorkspaceContext) {
    panelWorkspaceContext = createRoot((disposeRoot) =>
      createPanelWorkspaceContext(queryClient, () => {
        panelWorkspaceContext = null;
        disposeRoot();
      }),
    );
  }
  return panelWorkspaceContext;
}

export function retainPanelWorkspace(): {
  workspace: PanelWorkspaceContext;
  release: () => void;
} {
  const workspace = usePanelWorkspace();
  if (panelWorkspaceDisposeTimer) {
    clearTimeout(panelWorkspaceDisposeTimer);
    panelWorkspaceDisposeTimer = null;
  }
  let released = false;
  panelWorkspaceRetainCount += 1;

  return {
    workspace,
    release() {
      if (released) return;
      released = true;
      panelWorkspaceRetainCount = Math.max(0, panelWorkspaceRetainCount - 1);
      if (panelWorkspaceRetainCount === 0 && panelWorkspaceContext === workspace) {
        panelWorkspaceDisposeTimer = setTimeout(() => {
          panelWorkspaceDisposeTimer = null;
          if (panelWorkspaceRetainCount === 0 && panelWorkspaceContext === workspace) {
            disposePanelWorkspace();
          }
        }, 0);
      }
    },
  };
}

function generateWorkspaceTileActionId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `wpa-${crypto.randomUUID()}`;
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `wpa-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
