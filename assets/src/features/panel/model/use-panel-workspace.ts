import { createSignal } from "solid-js";
import type { MosaicNode } from "solid-mosaic-component";
import {
  encodePanelId,
  decodePanelId,
  findFirstDocumentId,
  findFirstPanelId,
  hasDocumentPanels,
  removeFromMosaic,
  replacePanelInMosaic,
  replacePanelIdInMosaic,
  type PanelType,
} from "../lib/panel-utils";

export interface OpenDocument {
  id: string;
  title?: string;
}

const [openDocuments, setOpenDocuments] = createSignal<Map<string, OpenDocument>>(new Map());
const [mosaicState, setMosaicState] = createSignal<MosaicNode<string> | null>(null);
const [focusedPanelIdSignal, setFocusedPanelIdSignal] = createSignal<string | null>(null);

type EditorMode = "markdown" | "wysiwyg" | "split";

function getDefaultEditorMode(): EditorMode {
  try {
    const stored = localStorage.getItem("editor-mode");
    if (stored === "markdown" || stored === "wysiwyg" || stored === "split") return stored;
  } catch {
    // localStorage unavailable
  }
  return "split";
}

let scrollGroupCounter = 0;
function generateScrollGroupId(): string {
  return `sg-${Date.now()}-${++scrollGroupCounter}`;
}

function createSplitNode(documentId: string): MosaicNode<string> {
  const mode = getDefaultEditorMode();
  const scrollGroupId = generateScrollGroupId();
  if (mode === "markdown") return encodePanelId(documentId, "markdown", undefined, scrollGroupId);
  if (mode === "wysiwyg") return encodePanelId(documentId, "wysiwyg", undefined, scrollGroupId);
  return {
    direction: "row",
    first: encodePanelId(documentId, "markdown", undefined, scrollGroupId),
    second: encodePanelId(documentId, "wysiwyg", undefined, scrollGroupId),
    splitPercentage: 50,
  };
}

function resetWorkspace() {
  setOpenDocuments(new Map());
  setMosaicState(null);
  setFocusedPanelIdSignal(null);
}

export function usePanelWorkspace() {
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
      const docCount = openDocuments().size;
      setMosaicState({
        direction: "column",
        first: state,
        second: splitNode,
        splitPercentage: ((docCount - 1) / docCount) * 100,
      });
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

  function switchPanelType(panelId: string) {
    const panel = decodePanelId(panelId);
    if (!panel) return;
    const newType: PanelType = panel.type === "markdown" ? "wysiwyg" : "markdown";
    const newPanelId = encodePanelId(panel.documentId, newType, panel.instanceId);
    const state = mosaicState();
    if (!state) return;
    setMosaicState(replacePanelIdInMosaic(state, panelId, newPanelId));

    if (focusedPanelIdSignal() === panelId) {
      setFocusedPanelIdSignal(newPanelId);
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
    switchPanelType,
    focusPanel,
    handleMosaicChange,
    resetWorkspace,
    setMosaicState,
  };
}
