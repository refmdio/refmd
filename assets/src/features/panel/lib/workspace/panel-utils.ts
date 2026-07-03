import type { MosaicNode } from "solid-mosaic-component";

export type PanelType = "markdown" | "wysiwyg" | "preview";

export interface WorkspaceTileTarget {
  source: "document";
  targetKey: string;
  documentId: string;
  routePath: string;
  title?: string;
  workspaceId?: string | null;
}

export interface ShareLinkWorkspaceTileTarget {
  source: "share-link-document";
  targetKey: string;
  documentId: string;
  documentToken: string;
  routePath: string;
  title?: string;
  workspaceId?: string | null;
}

export interface MountedShareWorkspaceTileTarget {
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
  | WorkspaceTileTarget
  | ShareLinkWorkspaceTileTarget
  | MountedShareWorkspaceTileTarget;

export type OpenPanelTargetInput =
  | {
      id: string;
      title?: string;
      workspaceId?: string | null;
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

export interface WorkspacePluginTileId {
  source: "plugin-workspace-tile";
  tileId: string;
  documentId?: string;
  instanceId: string;
  actionId?: string;
}

let instanceCounter = 0;
function generateInstanceId(): string {
  return `${Date.now()}-${++instanceCounter}`;
}

export function createWorkspaceTileTarget(
  documentId: string,
  title?: string,
  workspaceId?: string | null,
): WorkspaceTileTarget {
  return {
    source: "document",
    targetKey: documentId,
    documentId,
    routePath: `/document/${documentId}`,
    title,
    workspaceId: workspaceId ?? null,
  };
}

export function createShareLinkWorkspaceTileTarget(args: {
  documentToken: string;
  documentId: string;
  routePath?: string;
  title?: string;
  workspaceId?: string | null;
}): ShareLinkWorkspaceTileTarget {
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

export function createMountedShareWorkspaceTileTarget(args: {
  mountId: string;
  shareId: string;
  documentId: string;
  routePath?: string;
  title?: string;
  workspaceId?: string | null;
}): MountedShareWorkspaceTileTarget {
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
  return createWorkspaceTileTarget(input.id, input.title, input.workspaceId);
}

export function encodePanelId(
  documentId: string,
  type: PanelType,
  instanceId?: string,
  scrollGroupId?: string,
): string {
  return encodePanelIdForTarget(
    createWorkspaceTileTarget(documentId),
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

export function encodeWorkspacePluginTileId(
  tileId: string,
  documentId?: string,
  instanceId?: string,
  actionId?: string,
): string {
  const id = instanceId ?? generateInstanceId();
  const encodedTileId = encodeURIComponent(tileId);
  const encodedDocumentId = documentId ? encodeURIComponent(documentId) : "_";
  const encodedActionId = actionId ? encodeURIComponent(actionId) : "_";
  return `plugin:workspace:${encodedTileId}:${encodedDocumentId}:${id}:${encodedActionId}`;
}

export function decodeWorkspacePluginTileId(panelId: string): WorkspacePluginTileId | null {
  const parts = panelId.split(":");
  if (
    parts[0] !== "plugin" ||
    parts[1] !== "workspace" ||
    (parts.length !== 5 && parts.length !== 6)
  ) {
    return null;
  }
  const [, , encodedTileId, encodedDocumentId, instanceId, encodedActionId] = parts;
  if (!encodedTileId || !encodedDocumentId || !instanceId) return null;
  try {
    return {
      source: "plugin-workspace-tile",
      tileId: decodeURIComponent(encodedTileId),
      documentId: encodedDocumentId === "_" ? undefined : decodeURIComponent(encodedDocumentId),
      instanceId,
      actionId:
        encodedActionId && encodedActionId !== "_"
          ? decodeURIComponent(encodedActionId)
          : undefined,
    };
  } catch {
    return null;
  }
}

export function decodePanelId(panelId: string): PanelId | null {
  const isPanelType = (value: string | undefined): value is PanelType =>
    value === "markdown" || value === "wysiwyg" || value === "preview";
  const parts = panelId.split(":");
  if (parts.length === 4) {
    const [documentId, type, instanceId, scrollGroupId] = parts;
    if (!documentId || !isPanelType(type) || !instanceId || !scrollGroupId) {
      return null;
    }
    return {
      source: "document",
      targetKey: documentId,
      documentId,
      type,
      instanceId,
      scrollGroupId,
    };
  }

  if (parts[0] === "share" && parts[1] === "d" && parts.length === 7) {
    const [, , documentToken, documentId, type, instanceId, scrollGroupId] = parts;
    if (!documentToken || !documentId || !isPanelType(type) || !instanceId || !scrollGroupId) {
      return null;
    }
    return {
      source: "share-link-document",
      targetKey: `share:d:${documentToken}`,
      documentId,
      type,
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
      !isPanelType(type) ||
      !instanceId ||
      !scrollGroupId
    ) {
      return null;
    }
    return {
      source: "mounted-share-document",
      targetKey: `mount:${mountId}:${shareId}`,
      documentId,
      type,
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

export function hasWorkspaceTiles(node: MosaicNode<string>, documentId: string): boolean {
  if (typeof node === "string") return decodePanelId(node)?.documentId === documentId;
  return hasWorkspaceTiles(node.first, documentId) || hasWorkspaceTiles(node.second, documentId);
}

export function findFirstDocumentResourcePanelId(
  node: MosaicNode<string> | null,
  documentId: string,
): string | null {
  if (!node) return null;
  if (typeof node === "string") {
    const panel = decodePanelId(node);
    if (panel?.documentId === documentId) return node;
    const pluginTile = decodeWorkspacePluginTileId(node);
    return pluginTile?.documentId === documentId ? node : null;
  }
  return (
    findFirstDocumentResourcePanelId(node.first, documentId) ??
    findFirstDocumentResourcePanelId(node.second, documentId)
  );
}

export function hasDocumentResourcePanels(node: MosaicNode<string>, documentId: string): boolean {
  if (typeof node === "string") {
    const panel = decodePanelId(node);
    if (panel?.documentId === documentId) return true;
    return decodeWorkspacePluginTileId(node)?.documentId === documentId;
  }
  return (
    hasDocumentResourcePanels(node.first, documentId) ||
    hasDocumentResourcePanels(node.second, documentId)
  );
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
