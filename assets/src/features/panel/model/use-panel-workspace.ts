import { createRoot, createSignal } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import type { MosaicNode } from "solid-mosaic-component";
import { createBalancedTreeFromLeaves } from "solid-mosaic-component";
import { readFromLocalStorage } from "@/entities/settings";
import { authState } from "@/entities/session";
import type { SettingsResponse } from "@/shared/api";
import {
  decodePanelId,
  encodePanelId,
  extractDocumentSubtrees,
  findFirstDocumentId,
  findFirstPanelId,
  findScrollGroupPeerId,
  hasDocumentPanels,
  removeFromMosaic,
  replacePanelIdInMosaic,
  replacePanelInMosaic,
  type PanelType,
} from "../lib/panel-utils";
interface OpenDocument {
  id: string;
  title?: string;
}
type EditorMode = "markdown" | "wysiwyg" | "split";
type QueryClient = ReturnType<typeof useQueryClient>;
function getCachedSettings(): SettingsResponse | null {
  return readFromLocalStorage()?.data ?? null;
}
function getPrimaryPanelId(node: MosaicNode<string>): string {
  return typeof node === "string" ? node : getPrimaryPanelId(node.first);
}
function createPanelWorkspaceContext(queryClient: QueryClient, disposeRoot: () => void) {
  const [openDocuments, setOpenDocuments] = createSignal<Map<string, OpenDocument>>(new Map());
  const [mosaicState, setMosaicState] = createSignal<MosaicNode<string> | null>(null);
  const [focusedPanelIdSignal, setFocusedPanelIdSignal] = createSignal<string | null>(null);
  let scrollGroupCounter = 0;
  function generateScrollGroupId(): string {
    return `sg-${Date.now()}-${++scrollGroupCounter}`;
  }
  function resetWorkspace() {
    setOpenDocuments(new Map());
    setMosaicState(null);
    setFocusedPanelIdSignal(null);
  }
  function dispose() {
    resetWorkspace();
    disposeRoot();
  }
  function getDefaultEditorMode(): EditorMode {
    const userId = authState()?.user?.id;
    const settings = queryClient.getQueryData<SettingsResponse>(["settings", userId ?? "anon"]);
    const mode = settings?.editor_default_mode ?? getCachedSettings()?.editor_default_mode;
    if (mode === "markdown" || mode === "wysiwyg" || mode === "split") return mode;
    return "split";
  }
  function getLayoutMode(): "tiling" | "horizontal" | "vertical" {
    const userId = authState()?.user?.id;
    const settings = queryClient.getQueryData<SettingsResponse>(["settings", userId ?? "anon"]);
    const mode = settings?.editor_layout_mode ?? getCachedSettings()?.editor_layout_mode;
    if (mode === "horizontal" || mode === "vertical") return mode;
    return "tiling";
  }
  function createSplitNode(documentId: string): MosaicNode<string> {
    const mode = getDefaultEditorMode();
    const scrollGroupId = generateScrollGroupId();
    if (mode === "markdown") {
      return encodePanelId(documentId, "markdown", undefined, scrollGroupId);
    }
    if (mode === "wysiwyg") {
      return encodePanelId(documentId, "wysiwyg", undefined, scrollGroupId);
    }
    return {
      direction: "row" as const,
      first: encodePanelId(documentId, "markdown", undefined, scrollGroupId),
      second: encodePanelId(documentId, "wysiwyg", undefined, scrollGroupId),
      splitPercentage: 50,
    };
  }
  const focusedDocumentId = () => {
    const panelId = focusedPanelIdSignal();
    if (!panelId) return null;
    return decodePanelId(panelId)?.documentId ?? null;
  };
  const focusedPanelType = (): PanelType => {
    const panelId = focusedPanelIdSignal();
    if (!panelId) return "markdown";
    return decodePanelId(panelId)?.type ?? "markdown";
  };
  function openDocument(doc: OpenDocument) {
    const state = mosaicState();
    if (state && hasDocumentPanels(state, doc.id)) {
      const panelId = findFirstPanelId(state, doc.id);
      if (panelId) setFocusedPanelIdSignal(panelId);
      return;
    }
    const splitNode = createSplitNode(doc.id);
    const docs = new Map<string, OpenDocument>();
    docs.set(doc.id, doc);
    setOpenDocuments(docs);
    setMosaicState(splitNode);
    setFocusedPanelIdSignal(getPrimaryPanelId(splitNode));
  }
  function addToTile(doc: OpenDocument) {
    setOpenDocuments((previous) => {
      const next = new Map(previous);
      next.set(doc.id, { ...next.get(doc.id), ...doc });
      return next;
    });
    const splitNode = createSplitNode(doc.id);
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
  function closePanel(panelId: string) {
    const state = mosaicState();
    if (!state) return;
    const newState = removeFromMosaic(state, panelId);
    setMosaicState(newState);
    if (!newState) {
      setOpenDocuments(new Map());
      setFocusedPanelIdSignal(null);
      return;
    }
    setOpenDocuments((docs) => {
      const next = new Map(docs);
      for (const documentId of next.keys()) {
        if (!hasDocumentPanels(newState, documentId)) next.delete(documentId);
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
  function splitPanel(panelId: string, direction: "row" | "column") {
    const panel = decodePanelId(panelId);
    if (!panel) return;
    const newType: PanelType = panel.type === "markdown" ? "wysiwyg" : "markdown";
    const pairGroupId = generateScrollGroupId();
    const updatedPanelId = encodePanelId(panel.documentId, panel.type, undefined, pairGroupId);
    const newPanelId = encodePanelId(panel.documentId, newType, undefined, pairGroupId);
    const state = mosaicState();
    if (!state) return;
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
    const markdownPanelId = encodePanelId(panel.documentId, "markdown", undefined, pairGroupId);
    const wysiwygPanelId = encodePanelId(panel.documentId, "wysiwyg", undefined, pairGroupId);
    const state = mosaicState();
    if (!state) return;
    setMosaicState(
      replacePanelInMosaic(state, panelId, {
        direction: "row" as const,
        first: markdownPanelId,
        second: wysiwygPanelId,
        splitPercentage: 50,
      }),
    );
    if (focusedPanelIdSignal() === panelId) {
      setFocusedPanelIdSignal(markdownPanelId);
    }
  }
  function switchPanelType(panelId: string) {
    const panel = decodePanelId(panelId);
    if (!panel) return;
    const newType: PanelType = panel.type === "markdown" ? "wysiwyg" : "markdown";
    const newPanelId = encodePanelId(
      panel.documentId,
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
    const keepId = panel.type === targetType ? panelId : peerId;
    const removeId = panel.type === targetType ? peerId : panelId;
    const newState = removeFromMosaic(state, removeId);
    setMosaicState(newState);
    if (focusedPanelIdSignal() === removeId && newState) {
      setFocusedPanelIdSignal(keepId);
    }
  }
  function focusPanel(panelId: string) {
    setFocusedPanelIdSignal(panelId);
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
    resetWorkspace,
    setMosaicState,
    splitPanel,
    switchPanelType,
    switchToSplit,
  };
}
type PanelWorkspaceContext = ReturnType<typeof createPanelWorkspaceContext>;
let panelWorkspaceContext: PanelWorkspaceContext | null = null;
export function disposePanelWorkspace(): void {
  panelWorkspaceContext?.dispose();
  panelWorkspaceContext = null;
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
