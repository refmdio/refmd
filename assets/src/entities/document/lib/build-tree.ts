import type { DocumentResponse, DocumentTreeNode } from "../model/types";

export function buildDocumentTree(documents: DocumentResponse[]): DocumentTreeNode[] {
  const childrenMap = new Map<string | null, DocumentResponse[]>();

  for (const doc of documents) {
    const parentId = doc.parent_id ?? null;
    const key = parentId;
    const existing = childrenMap.get(key);
    if (existing) {
      existing.push(doc);
    } else {
      childrenMap.set(key, [doc]);
    }
  }

  for (const children of childrenMap.values()) {
    children.sort((a, b) => a.position - b.position);
  }

  function buildNodes(parentId: string | null, depth: number): DocumentTreeNode[] {
    const children = childrenMap.get(parentId) ?? [];
    return children.map((doc) => ({
      document: doc,
      children: buildNodes(doc.id, depth + 1),
      depth,
    }));
  }

  return buildNodes(null, 0);
}
