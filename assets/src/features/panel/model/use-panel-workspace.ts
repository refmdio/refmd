import { createSignal } from "solid-js";
import { useQueryClient } from "@tanstack/solid-query";
import type { MosaicNode } from "solid-mosaic-component";
import { getLeaves, createBalancedTreeFromLeaves } from "solid-mosaic-component";
import {
  encodePanelId,
  decodePanelId,
  findFirstDocumentId,
  findFirstPanelId,
  findScrollGroupPeerId,
  hasDocumentPanels,
  removeFromMosaic,
  replacePanelInMosaic,
  replacePanelIdInMosaic,
  type PanelType,
} from "../lib/panel-utils";
import type { SettingsResponse } from "@/shared/api";
import { authState } from "@/shared/lib/auth-state";

export interface OpenDocument {
  id: string;
  title?: string;
}

const [openDocuments, setOpenDocuments] = createSignal<Map<string, OpenDocument>>(new Map());
const [mosaicState, setMosaicState] = createSignal<MosaicNode<string> | null>(null);
const [focusedPanelIdSignal, setFocusedPanelIdSignal] = createSignal<string | null>(null);

type EditorMode = "markdown" | "wysiwyg" | "split";

let scrollGroupCounter = 0;
function generateScrollGroupId(): string {
  return `sg-${Date.now()}-${++scrollGroupCounter}`;
}

function resetWorkspace() {
  setOpenDocuments(new Map());
  setMosaicState(null);
  setFocusedPanelIdSignal(null);
}

export function usePanelWorkspace() {
  const queryClient = useQueryClient();

  function getDefaultEditorMode(): EditorMode {
    const userId = authState()?.user?.id;
    const settings = queryClient.getQueryData<SettingsResponse>(["settings", userId ?? "anon"]);
    let mode = settings?.editor_default_mode;
    if (!mode && userId) {
      try {
        const cached = localStorage.getItem(`refmd_settings:${userId}`);
        if (cached) {
          const parsed = JSON.parse(cached) as SettingsResponse;
          mode = parsed.editor_default_mode;
        }
      } catch {
        // localStorage unavailable
      }
    }
    if (mode === "markdown" || mode === "wysiwyg" || mode === "split") return mode;
    return "split";
  }

  function getLayoutMode(): "tiling" | "horizontal" | "vertical" {
    const userId = authState()?.user?.id;
    const settings = queryClient.getQueryData<SettingsResponse>(["settings", userId ?? "anon"]);
    let mode = settings?.editor_layout_mode;
    if (!mode && userId) {
      try {
        const cached = localStorage.getItem(`refmd_settings:${userId}`);
        if (cached) {
          const parsed = JSON.parse(cached) as SettingsResponse;
          mode = parsed.editor_layout_mode;
        }
      } catch {
        // localStorage unavailable
      }
    }
    if (mode === "horizontal" || mode === "vertical") return mode;
    return "tiling";
  }

  function createSplitNode(documentId: string): MosaicNode<string> {
    const mode = getDefaultEditorMode();
    const scrollGroupId = generateScrollGroupId();
    if (mode === "markdown") return encodePanelId(documentId, "markdown", undefined, scrollGroupId);
    if (mode === "wysiwyg") return encodePanelId(documentId, "wysiwyg", undefined, scrollGroupId);
    return {
      direction: "row" as const,
      first: encodePanelId(documentId, "markdown", undefined, scrollGroupId),
      second: encodePanelId(documentId, "wysiwyg", undefined, scrollGroupId),
      splitPercentage: 50,
    };
  }
  const focusedDocumentId = () => {
    const pid = focusedPanelIdSignal();
    if (!pid) return null;
    return decodePanelId(pid)?.documentId ?? null;
  };

  const focusedPanelType = (): PanelType => {
    const pid = focusedPanelIdSignal();
    if (!pid) return "markdown";
    return decodePanelId(pid)?.type ?? "markdown";
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
    const mdPanelId = typeof splitNode === "string" ? splitNode : (splitNode.first as string);
    setFocusedPanelIdSignal(mdPanelId);
  }

  function addToTile(doc: OpenDocument) {
    setOpenDocuments((prev) => {
      const next = new Map(prev);
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
        const docCount = openDocuments().size;
        setMosaicState({
          direction: layout === "horizontal" ? "row" : "column",
          first: state,
          second: splitNode,
          splitPercentage: ((docCount - 1) / docCount) * 100,
        });
      } else {
        const existingLeaves = getLeaves(state);
        const allLeaves: MosaicNode<string>[] = [
          ...existingLeaves,
          ...(typeof splitNode === "string" ? [splitNode] : getLeaves(splitNode)),
        ];
        setMosaicState(createBalancedTreeFromLeaves(allLeaves));
      }
    }
    const mdPanelId = typeof splitNode === "string" ? splitNode : (splitNode.first as string);
    setFocusedPanelIdSignal(mdPanelId);
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
      for (const docId of next.keys()) {
        if (!hasDocumentPanels(newState, docId)) next.delete(docId);
      }
      return next;
    });

    if (focusedPanelIdSignal() === panelId) {
      const firstDocId = findFirstDocumentId(newState);
      if (firstDocId) {
        const firstPid = findFirstPanelId(newState, firstDocId);
        setFocusedPanelIdSignal(firstPid);
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
    const mdPanelId = encodePanelId(panel.documentId, "markdown", undefined, pairGroupId);
    const pmPanelId = encodePanelId(panel.documentId, "wysiwyg", undefined, pairGroupId);
    const state = mosaicState();
    if (!state) return;
    setMosaicState(
      replacePanelInMosaic(state, panelId, {
        direction: "row" as const,
        first: mdPanelId,
        second: pmPanelId,
        splitPercentage: 50,
      }),
    );
    if (focusedPanelIdSignal() === panelId) {
      setFocusedPanelIdSignal(mdPanelId);
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
    openDocuments,
    mosaicState,
    focusedDocumentId,
    focusedPanelType,
    focusedPanelId: focusedPanelIdSignal,
    openDocument,
    addToTile,
    closePanel,
    splitPanel,
    switchToSplit,
    switchPanelType,
    collapseSplitTo,
    getLayoutMode,
    focusPanel,
    handleMosaicChange,
    resetWorkspace,
    setMosaicState,
  };
}
