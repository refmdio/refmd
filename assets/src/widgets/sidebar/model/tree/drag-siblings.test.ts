import { describe, expect, it } from "vite-plus/test";
import type { DocumentResponse } from "@/entities/document";
import type { ShareMount } from "@/entities/mount";
import { buildSidebarDragSiblings } from "./drag-siblings";

function documentFixture(
  id: string,
  position: number,
  attrs: Partial<DocumentResponse> = {},
): DocumentResponse {
  return {
    active_snapshot_id: null,
    archived_at: null,
    created_at: "2026-01-01T00:00:00Z",
    created_by: "user-1",
    can_sync_publication: true,
    doc_type: "document",
    id,
    is_encrypted: false,
    is_published: false,
    min_dek_version: 1,
    needs_dek_rotation: false,
    parent_id: null,
    position,
    slug: id,
    title: id,
    updated_at: "2026-01-01T00:00:00Z",
    write_state: attrs.archived_at ? "archived" : "writable",
    workspace_id: "workspace-1",
    ...attrs,
  };
}

function mountFixture(id: string, position: number, parentId: string | null = null): ShareMount {
  return {
    id,
    parent_id: parentId,
    position,
  } as unknown as ShareMount;
}

describe("buildSidebarDragSiblings", () => {
  it("includes archived documents and mounted shares in persisted sibling order", () => {
    const siblings = buildSidebarDragSiblings(
      [
        documentFixture("dragged", 0),
        documentFixture("archived", 1, { archived_at: "2026-01-01T00:00:00Z" }),
        documentFixture("target", 3),
      ],
      [mountFixture("mount", 2)],
      null,
      "dragged",
    );

    expect(siblings).toEqual([
      { key: "archived", documentId: "archived", position: 1 },
      { key: "mount", mountId: "mount", position: 2 },
      { key: "target", documentId: "target", position: 3 },
    ]);
  });

  it("matches backend tie-break order for duplicate positions", () => {
    const siblings = buildSidebarDragSiblings(
      [documentFixture("b-document", 1)],
      [mountFixture("a-mount", 1)],
      null,
      "dragged",
    );

    expect(siblings.map((sibling) => sibling.key)).toEqual(["a-mount", "b-document"]);
  });

  it("filters by parent without excluding mounts from the same folder", () => {
    const siblings = buildSidebarDragSiblings(
      [documentFixture("root-doc", 0), documentFixture("folder-doc", 0, { parent_id: "folder-1" })],
      [mountFixture("folder-mount", 1, "folder-1"), mountFixture("root-mount", 1)],
      "folder-1",
      "dragged",
    );

    expect(siblings.map((sibling) => sibling.key)).toEqual(["folder-doc", "folder-mount"]);
  });
});
