import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  flushDocumentCache: vi.fn(),
  getAllActiveDocumentStates: vi.fn(),
  onOfflineModeChange: vi.fn(() => vi.fn()),
}));

vi.mock("../../model/document-state/store", () => ({
  getAllActiveDocumentStates: mocks.getAllActiveDocumentStates,
}));

vi.mock("@/shared/lib/offline/cache/manager/write", () => ({
  flushDocumentCache: mocks.flushDocumentCache,
}));

vi.mock("@/shared/lib/offline/offline-state", () => ({
  onOfflineModeChange: mocks.onOfflineModeChange,
}));

import { runBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { setupFlushHooks } from "./flush-hooks";

describe("editor logout flush hook", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reports an auto-sync rejection after attempting every active document", async () => {
    const failedFlush = vi.fn().mockRejectedValue(new Error("flush failed"));
    const laterFlush = vi.fn().mockResolvedValue(undefined);
    mocks.getAllActiveDocumentStates.mockReturnValue(
      new Map([
        ["failed", documentState(failedFlush)],
        ["later", documentState(laterFlush)],
      ]),
    );
    const cleanup = setupFlushHooks();

    try {
      const result = await runBeforeSessionCleanup({ secure: true });

      expect(failedFlush).toHaveBeenCalledTimes(1);
      expect(laterFlush).toHaveBeenCalledTimes(1);
      expect(result.failures).toEqual([
        expect.objectContaining({ callbackId: expect.any(Number), reason: "rejected" }),
      ]);
    } finally {
      cleanup();
    }
  });
});

function documentState(flushNow: () => Promise<void>) {
  return {
    access: { kind: "user" },
    autoSync: { flushNow },
    pendingSnapshot: null,
    pendingSnapshotEnvelope: null,
    pendingUpdateEnvelope: null,
    sending: false,
    workspaceId: "workspace-id",
  };
}
