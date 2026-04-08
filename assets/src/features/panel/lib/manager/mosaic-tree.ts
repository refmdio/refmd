import type { MosaicNode } from "solid-mosaic-component";

export function pruneNodes(
  node: MosaicNode<string> | null,
  removedIds: Set<string>,
): MosaicNode<string> | null {
  if (typeof node === "string") {
    return removedIds.has(node) ? null : node;
  }
  if (!node) return null;

  const first = pruneNodes(node.first, removedIds);
  const second = pruneNodes(node.second, removedIds);

  if (first == null && second == null) return null;
  if (first == null) return second;
  if (second == null) return first;

  return { ...node, first, second };
}
