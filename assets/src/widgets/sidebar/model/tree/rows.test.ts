import { describe, expect, it } from "vite-plus/test";
import type { DocumentResponse } from "@/entities/document";
import type { MountedShareTreeEntry, ShareMount } from "@/entities/mount";
import { buildMountChildRows, buildSidebarRows } from "./rows";

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
    dek_rotation_reason: null,
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

function mountFixture(id: string, position: number): ShareMount {
  return {
    id,
    parent_id: null,
    position,
  } as unknown as ShareMount;
}

function shareEntryFixture(id: string, docType: "document" | "folder"): MountedShareTreeEntry {
  return {
    id,
    doc_type: docType,
    label: id,
  } as unknown as MountedShareTreeEntry;
}

describe("buildSidebarRows", () => {
  it("splits regular documents and folders into separate row kinds", () => {
    const rows = buildSidebarRows(
      [
        documentFixture("folder", 0, { doc_type: "folder" }),
        documentFixture("document", 0, { parent_id: "folder" }),
      ],
      [mountFixture("mount", 1)],
    );

    expect(rows).toHaveLength(2);
    expect(rows[0].kind).toBe("folder");
    expect(rows[1].kind).toBe("mount");

    const folder = rows[0];
    expect(folder.kind).toBe("folder");
    if (folder.kind === "folder") {
      expect(folder.children.map((child) => child.kind)).toEqual(["document"]);
    }
  });
});

describe("buildMountChildRows", () => {
  it("splits mounted share children into document and folder row kinds", () => {
    const mount = mountFixture("mount", 0);
    const rows = buildMountChildRows(
      mount,
      [
        shareEntryFixture("shared-document", "document"),
        shareEntryFixture("shared-folder", "folder"),
      ],
      1,
    );

    expect(rows.map((row) => row.kind)).toEqual(["mount-child-document", "mount-child-folder"]);
  });
});
