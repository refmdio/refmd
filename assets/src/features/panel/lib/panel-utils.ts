import type { MosaicNode } from "solid-mosaic-component";

export type PanelType = "markdown" | "wysiwyg";

export interface PanelId {
  documentId: string;
  type: PanelType;
  instanceId: string;
  scrollGroupId: string;
}

let instanceCounter = 0;
function generateInstanceId(): string {
  return `${Date.now()}-${++instanceCounter}`;
}

export function encodePanelId(
  documentId: string,
  type: PanelType,
  instanceId?: string,
  scrollGroupId?: string,
): string {
  const id = instanceId ?? generateInstanceId();
  const sg = scrollGroupId ?? generateInstanceId();
  return `${documentId}:${type}:${id}:${sg}`;
}

export function decodePanelId(panelId: string): PanelId | null {
  const parts = panelId.split(":");
  if (parts.length < 4) return null;
  const [documentId, type, instanceId, scrollGroupId] = parts;
  if (!documentId || (type !== "markdown" && type !== "wysiwyg") || !instanceId || !scrollGroupId)
    return null;
  return { documentId, type: type as PanelType, instanceId, scrollGroupId };
}

export function findFirstDocumentId(node: MosaicNode<string> | null): string | null {
  if (!node) return null;
  if (typeof node === "string") return decodePanelId(node)?.documentId ?? null;
  return findFirstDocumentId(node.first) ?? findFirstDocumentId(node.second);
}

export function findFirstPanelId(
  node: MosaicNode<string> | null,
  documentId: string,
): string | null {
  if (!node) return null;
  if (typeof node === "string") {
    const panel = decodePanelId(node);
    return panel?.documentId === documentId ? node : null;
  }
  return findFirstPanelId(node.first, documentId) ?? findFirstPanelId(node.second, documentId);
}

export function findFirstPanelType(node: MosaicNode<string>, documentId: string): PanelType | null {
  if (typeof node === "string") {
    const panel = decodePanelId(node);
    return panel?.documentId === documentId ? panel.type : null;
  }
  return findFirstPanelType(node.first, documentId) ?? findFirstPanelType(node.second, documentId);
}

export function hasDocumentPanels(node: MosaicNode<string>, documentId: string): boolean {
  if (typeof node === "string") return decodePanelId(node)?.documentId === documentId;
  return hasDocumentPanels(node.first, documentId) || hasDocumentPanels(node.second, documentId);
}

export function hasScrollGroupPeer(
  node: MosaicNode<string>,
  scrollGroupId: string,
  excludePanelId: string,
): boolean {
  if (typeof node === "string") {
    if (node === excludePanelId) return false;
    const panel = decodePanelId(node);
    return panel?.scrollGroupId === scrollGroupId;
  }
  return (
    hasScrollGroupPeer(node.first, scrollGroupId, excludePanelId) ||
    hasScrollGroupPeer(node.second, scrollGroupId, excludePanelId)
  );
}

export function findScrollGroupPeerId(
  node: MosaicNode<string>,
  scrollGroupId: string,
  excludePanelId: string,
): string | null {
  if (typeof node === "string") {
    if (node === excludePanelId) return null;
    const panel = decodePanelId(node);
    return panel?.scrollGroupId === scrollGroupId ? node : null;
  }
  return (
    findScrollGroupPeerId(node.first, scrollGroupId, excludePanelId) ??
    findScrollGroupPeerId(node.second, scrollGroupId, excludePanelId)
  );
}

export function hasDocumentPanelOfType(
  node: MosaicNode<string>,
  documentId: string,
  type: PanelType,
): boolean {
  if (typeof node === "string") {
    const panel = decodePanelId(node);
    return panel?.documentId === documentId && panel.type === type;
  }
  return (
    hasDocumentPanelOfType(node.first, documentId, type) ||
    hasDocumentPanelOfType(node.second, documentId, type)
  );
}

export function removeFromMosaic(
  node: MosaicNode<string>,
  idToRemove: string,
): MosaicNode<string> | null {
  if (typeof node === "string") return node === idToRemove ? null : node;
  const first = removeFromMosaic(node.first, idToRemove);
  const second = removeFromMosaic(node.second, idToRemove);
  if (!first && !second) return null;
  if (!first) return second;
  if (!second) return first;
  return { ...node, first, second };
}

export function replacePanelInMosaic(
  node: MosaicNode<string>,
  panelId: string,
  newNode: MosaicNode<string>,
): MosaicNode<string> {
  if (typeof node === "string") return node === panelId ? newNode : node;
  return {
    ...node,
    first: replacePanelInMosaic(node.first, panelId, newNode),
    second: replacePanelInMosaic(node.second, panelId, newNode),
  };
}

export function extractDocumentSubtrees(node: MosaicNode<string>): MosaicNode<string>[] {
  if (typeof node === "string") return [node];
  const leftGroupIds = new Set(getLeafScrollGroupIds(node.first));
  const rightGroupIds = new Set(getLeafScrollGroupIds(node.second));
  if ([...leftGroupIds].some((id) => rightGroupIds.has(id))) return [node];
  return [...extractDocumentSubtrees(node.first), ...extractDocumentSubtrees(node.second)];
}

function getLeafScrollGroupIds(node: MosaicNode<string>): string[] {
  if (typeof node === "string") {
    const panel = decodePanelId(node);
    return panel ? [panel.scrollGroupId] : [];
  }
  return [...getLeafScrollGroupIds(node.first), ...getLeafScrollGroupIds(node.second)];
}

export function replacePanelIdInMosaic(
  node: MosaicNode<string>,
  oldId: string,
  newId: string,
): MosaicNode<string> {
  if (typeof node === "string") return node === oldId ? newId : node;
  return {
    ...node,
    first: replacePanelIdInMosaic(node.first, oldId, newId),
    second: replacePanelIdInMosaic(node.second, oldId, newId),
  };
}
