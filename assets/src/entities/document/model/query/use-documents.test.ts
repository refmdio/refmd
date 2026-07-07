import { describe, expect, it } from "vite-plus/test";
import { documentWriteStateForOfflineIndex, offlineDocumentWriteState } from "./use-documents";

describe("offline document index write state", () => {
  it("preserves non-writable document states in the offline index", () => {
    expect(
      documentWriteStateForOfflineIndex({
        archived_at: null,
        write_state: "read_only",
      }),
    ).toBe("read_only");

    expect(
      documentWriteStateForOfflineIndex({
        archived_at: null,
        write_state: "write_disabled",
      }),
    ).toBe("write_disabled");

    expect(
      documentWriteStateForOfflineIndex({
        archived_at: "2026-06-02T00:00:00Z",
        write_state: "archived",
      }),
    ).toBe("archived");
  });

  it("restores cached write state before legacy archived fallback", () => {
    expect(
      offlineDocumentWriteState({
        archivedAt: null,
        writeState: "read_only",
      }),
    ).toBe("read_only");

    expect(
      offlineDocumentWriteState({
        archivedAt: null,
        writeState: "write_disabled",
      }),
    ).toBe("write_disabled");

    expect(
      offlineDocumentWriteState({
        archivedAt: "2026-06-02T00:00:00Z",
      }),
    ).toBe("archived");

    expect(
      offlineDocumentWriteState({
        archivedAt: null,
      }),
    ).toBe("writable");
  });
});
