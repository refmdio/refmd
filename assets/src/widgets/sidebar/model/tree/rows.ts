import type { DocumentResponse } from "@/entities/document";
import type { MountedShareTreeEntry, ShareMount } from "@/entities/mount";

export type SidebarTreeNode =
  | {
      kind: "document";
      document: DocumentResponse;
      depth: number;
    }
  | {
      kind: "folder";
      document: DocumentResponse;
      children: SidebarTreeNode[];
      depth: number;
    }
  | {
      kind: "mount";
      mount: ShareMount;
      depth: number;
    }
  | {
      kind: "mount-child-document";
      mount: ShareMount;
      entry: MountedShareTreeEntry;
      depth: number;
    }
  | {
      kind: "mount-child-folder";
      mount: ShareMount;
      entry: MountedShareTreeEntry;
      depth: number;
    };

type Sibling =
  | { kind: "document"; id: string; position: number; document: DocumentResponse }
  | { kind: "mount"; id: string; position: number; mount: ShareMount };

function compareSibling(a: Sibling, b: Sibling): number {
  const positionDiff = a.position - b.position;
  if (positionDiff !== 0) return positionDiff;
  return a.id.localeCompare(b.id);
}

export function buildSidebarRows(
  documents: DocumentResponse[],
  mounts: ShareMount[],
): SidebarTreeNode[] {
  const documentsByParent = new Map<string | null, DocumentResponse[]>();
  const mountsByParent = new Map<string | null, ShareMount[]>();

  for (const document of documents) {
    const key = document.parent_id ?? null;
    documentsByParent.set(key, [...(documentsByParent.get(key) ?? []), document]);
  }

  for (const mount of mounts) {
    const key = mount.parent_id ?? null;
    mountsByParent.set(key, [...(mountsByParent.get(key) ?? []), mount]);
  }

  function build(parentId: string | null, depth: number): SidebarTreeNode[] {
    const siblings: Sibling[] = [
      ...(documentsByParent.get(parentId) ?? []).map((document) => ({
        kind: "document" as const,
        id: document.id,
        position: document.position,
        document,
      })),
      ...(mountsByParent.get(parentId) ?? []).map((mount) => ({
        kind: "mount" as const,
        id: mount.id,
        position: mount.position,
        mount,
      })),
    ].sort(compareSibling);

    return siblings.map((sibling) => {
      if (sibling.kind === "mount") {
        return {
          kind: "mount",
          mount: sibling.mount,
          depth,
        };
      }

      if (sibling.document.doc_type === "folder") {
        return {
          kind: "folder",
          document: sibling.document,
          children: build(sibling.document.id, depth + 1),
          depth,
        };
      }

      return {
        kind: "document",
        document: sibling.document,
        depth,
      };
    });
  }

  return build(null, 0);
}

export function buildMountChildRows(
  mount: ShareMount,
  entries: MountedShareTreeEntry[],
  depth: number,
): SidebarTreeNode[] {
  return entries.map((entry) => ({
    kind: entry.doc_type === "folder" ? "mount-child-folder" : "mount-child-document",
    mount,
    entry,
    depth,
  }));
}
