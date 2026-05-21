import type { MosaicNode } from "solid-mosaic-component";

export type PanelType = "markdown" | "wysiwyg";

export interface DocumentPanelTarget {
  source: "document";
  targetKey: string;
  documentId: string;
  routePath: string;
  title?: string;
  workspaceId?: string | null;
}

export interface ShareLinkDocumentPanelTarget {
  source: "share-link-document";
  targetKey: string;
  documentId: string;
  documentToken: string;
  routePath: string;
  title?: string;
  workspaceId?: string | null;
}

export interface MountedShareDocumentPanelTarget {
  source: "mounted-share-document";
  targetKey: string;
  mountId: string;
  shareId: string;
  documentId: string;
  routePath: string;
  title?: string;
  workspaceId?: string | null;
}

export type PanelTarget =
  | DocumentPanelTarget
  | ShareLinkDocumentPanelTarget
  | MountedShareDocumentPanelTarget;

export type OpenPanelTargetInput =
  | {
      id: string;
      title?: string;
    }
  | PanelTarget;

export interface PanelId {
  source: PanelTarget["source"];
  targetKey: string;
  documentId: string;
  type: PanelType;
  instanceId: string;
  scrollGroupId: string;
}
let instanceCounter = 0;
function generateInstanceId(): string {
  return `${Date.now()}-${++instanceCounter}`;
}

export function createDocumentPanelTarget(documentId: string, title?: string): DocumentPanelTarget {
  return {
    source: "document",
    targetKey: documentId,
    documentId,
    routePath: `/document/${documentId}`,
    title,
  };
}

export function createShareLinkDocumentPanelTarget(args: {
  documentToken: string;
  documentId: string;
  routePath?: string;
  title?: string;
  workspaceId?: string | null;
}): ShareLinkDocumentPanelTarget {
  return {
    source: "share-link-document",
    targetKey: `share:d:${args.documentToken}`,
    documentId: args.documentId,
    documentToken: args.documentToken,
    routePath: args.routePath ?? `/share/d/${args.documentToken}`,
    title: args.title,
    workspaceId: args.workspaceId ?? null,
  };
}

export function createMountedShareDocumentPanelTarget(args: {
  mountId: string;
  shareId: string;
  documentId: string;
  routePath?: string;
  title?: string;
  workspaceId?: string | null;
}): MountedShareDocumentPanelTarget {
  return {
    source: "mounted-share-document",
    targetKey: `mount:${args.mountId}:${args.shareId}`,
    mountId: args.mountId,
    shareId: args.shareId,
    documentId: args.documentId,
    routePath: args.routePath ?? `/mounts/${args.mountId}`,
    title: args.title,
    workspaceId: args.workspaceId ?? null,
  };
}

export function normalizePanelTarget(input: OpenPanelTargetInput): PanelTarget {
  if ("targetKey" in input) {
    return input;
  }
  return createDocumentPanelTarget(input.id, input.title);
}

export function encodePanelId(
  documentId: string,
  type: PanelType,
  instanceId?: string,
  scrollGroupId?: string,
): string {
  return encodePanelIdForTarget(
    createDocumentPanelTarget(documentId),
    type,
    instanceId,
    scrollGroupId,
  );
}

export function encodePanelIdForTarget(
  target: PanelTarget,
  type: PanelType,
  instanceId?: string,
  scrollGroupId?: string,
): string {
  const id = instanceId ?? generateInstanceId();
  const sg = scrollGroupId ?? generateInstanceId();
  if (target.source === "share-link-document") {
    return `share:d:${target.documentToken}:${target.documentId}:${type}:${id}:${sg}`;
  }
  if (target.source === "mounted-share-document") {
    return `mount:${target.mountId}:${target.shareId}:${target.documentId}:${type}:${id}:${sg}`;
  }
  return `${target.documentId}:${type}:${id}:${sg}`;
}

export function decodePanelId(panelId: string): PanelId | null {
  const parts = panelId.split(":");
  if (parts.length === 4) {
    const [documentId, type, instanceId, scrollGroupId] = parts;
    if (
      !documentId ||
      (type !== "markdown" && type !== "wysiwyg") ||
      !instanceId ||
      !scrollGroupId
    ) {
      return null;
    }
    return {
      source: "document",
      targetKey: documentId,
      documentId,
      type: type as PanelType,
      instanceId,
      scrollGroupId,
    };
  }

  if (parts[0] === "share" && parts[1] === "d" && parts.length === 7) {
    const [, , documentToken, documentId, type, instanceId, scrollGroupId] = parts;
    if (
      !documentToken ||
      !documentId ||
      (type !== "markdown" && type !== "wysiwyg") ||
      !instanceId ||
      !scrollGroupId
    ) {
      return null;
    }
    return {
      source: "share-link-document",
      targetKey: `share:d:${documentToken}`,
      documentId,
      type: type as PanelType,
      instanceId,
      scrollGroupId,
    };
  }

  if (parts[0] === "mount" && parts.length === 7) {
    const [, mountId, shareId, documentId, type, instanceId, scrollGroupId] = parts;
    if (
      !mountId ||
      !shareId ||
      !documentId ||
      (type !== "markdown" && type !== "wysiwyg") ||
      !instanceId ||
      !scrollGroupId
    ) {
      return null;
    }
    return {
      source: "mounted-share-document",
      targetKey: `mount:${mountId}:${shareId}`,
      documentId,
      type: type as PanelType,
      instanceId,
      scrollGroupId,
    };
  }

  return null;
}

export function findFirstPanelIdByTargetKey(
  node: MosaicNode<string> | null,
  targetKey: string,
): string | null {
  if (!node) return null;
  if (typeof node === "string") {
    const panel = decodePanelId(node);
    return panel?.targetKey === targetKey ? node : null;
  }
  return (
    findFirstPanelIdByTargetKey(node.first, targetKey) ??
    findFirstPanelIdByTargetKey(node.second, targetKey)
  );
}

export function hasTargetPanels(node: MosaicNode<string>, targetKey: string): boolean {
  if (typeof node === "string") return decodePanelId(node)?.targetKey === targetKey;
  return hasTargetPanels(node.first, targetKey) || hasTargetPanels(node.second, targetKey);
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
