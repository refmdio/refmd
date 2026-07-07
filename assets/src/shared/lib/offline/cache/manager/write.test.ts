import * as Y from "yjs";
import { beforeEach, describe, expect, test, vi } from "vite-plus/test";
import {
  canonicalMarkdownText,
  encodeCanonicalDiffAsUpdate,
  encodeCanonicalSyncedStateAsUpdate,
} from "@/shared/lib/yjs/canonical-document";
import type { DocumentCacheEntry, PendingChangesEntry } from "@/shared/lib/offline/storage/store";
import type { CacheableDocumentState } from "./types";
import {
  cacheDocumentStateAndPendingChanges,
  cachePendingChanges,
  resolveOfflineCacheStateKind,
} from "./write";

const mocks = vi.hoisted(() => {
  let nonceCounter = 1;
  const documentCache = new Map<string, DocumentCacheEntry>();
  const meta = new Map<
    string,
    {
      documentId: string;
      workspaceId: string;
      encryptedTitle: Uint8Array;
      encryptedTitleNonce: Uint8Array;
      lastAccessedAt: number;
      cacheSize: number;
    }
  >();
  const pending = new Map<string, PendingChangesEntry>();
  return {
    documentCache,
    meta,
    pending,
    nextNonce: () => new Uint8Array([nonceCounter++]),
    reset: () => {
      nonceCounter = 1;
      documentCache.clear();
      meta.clear();
      pending.clear();
    },
    deletePendingChanges: vi.fn(async (documentId: string) => {
      pending.delete(documentId);
    }),
    getDocumentCache: vi.fn(async (documentId: string) => documentCache.get(documentId) ?? null),
    getOfflineDocumentMeta: vi.fn(async (documentId: string) => meta.get(documentId) ?? null),
    getPendingChanges: vi.fn(async (documentId: string) => pending.get(documentId) ?? null),
    putDocumentCache: vi.fn(async (entry: DocumentCacheEntry) => {
      documentCache.set(entry.documentId, entry);
    }),
    putOfflineDocumentMeta: vi.fn(
      async (entry: {
        documentId: string;
        workspaceId: string;
        encryptedTitle: Uint8Array;
        encryptedTitleNonce: Uint8Array;
        lastAccessedAt: number;
        cacheSize: number;
      }) => {
        meta.set(entry.documentId, entry);
      },
    ),
    putPendingChanges: vi.fn(async (entry: PendingChangesEntry) => {
      pending.set(entry.documentId, entry);
    }),
  };
});

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    encryptOfflineCache: vi.fn(async ({ plaintext }: { plaintext: Uint8Array }) => ({
      ciphertext: new Uint8Array(plaintext),
      nonce: mocks.nextNonce(),
    })),
    encryptOfflinePending: vi.fn(async ({ plaintext }: { plaintext: Uint8Array }) => ({
      ciphertext: new Uint8Array(plaintext),
      nonce: mocks.nextNonce(),
    })),
  }),
}));

vi.mock("@/shared/lib/logger", () => ({
  clientWarn: vi.fn(),
}));

vi.mock("@/shared/lib/offline/storage/store", () => ({
  deletePendingChanges: mocks.deletePendingChanges,
  getDocumentCache: mocks.getDocumentCache,
  getOfflineDocumentMeta: mocks.getOfflineDocumentMeta,
  getPendingChanges: mocks.getPendingChanges,
  putDocumentCache: mocks.putDocumentCache,
  putOfflineDocumentMeta: mocks.putOfflineDocumentMeta,
  putPendingChanges: mocks.putPendingChanges,
}));

function docWithText(text: string): Y.Doc {
  const doc = new Y.Doc();
  if (text.length > 0) doc.getText("content").insert(0, text);
  return doc;
}

function stateFor(doc: Y.Doc, lastSavedState: Uint8Array | null): CacheableDocumentState {
  return {
    yDoc: doc,
    keyVersion: 1,
    activeSnapshotId: "snapshot-1",
    snapshotProofHash: "proof-1",
    snapshotCiphertextHash: "ciphertext-1",
    latestVersion: 1,
    confirmedClocks: {},
    lastSavedState,
    initialized: true,
  };
}

function textFromUpdate(update: Uint8Array | null | undefined): string {
  const doc = new Y.Doc();
  try {
    if (update) Y.applyUpdate(doc, update, "remote");
    return canonicalMarkdownText(doc);
  } finally {
    doc.destroy();
  }
}

describe("offline cache writes", () => {
  beforeEach(() => {
    mocks.reset();
    vi.clearAllMocks();
  });

  test("uses confirmed primary cache when local changes are structurally replayable", async () => {
    const baselineDoc = docWithText("alpha\nbeta\n");
    const baseline = encodeCanonicalSyncedStateAsUpdate(baselineDoc);
    const liveDoc = new Y.Doc();
    Y.applyUpdate(liveDoc, baseline, "remote");
    liveDoc.getText("content").insert("alpha\n".length, "local\n");

    expect(resolveOfflineCacheStateKind(stateFor(liveDoc, baseline))).toBe("confirmed");

    await cacheDocumentStateAndPendingChanges("doc-1", "workspace-1", stateFor(liveDoc, baseline));

    const cacheEntry = mocks.documentCache.get("doc-1");
    const pendingEntry = mocks.pending.get("doc-1");
    if (!cacheEntry) throw new Error("expected document cache entry");
    if (!pendingEntry) throw new Error("expected pending changes entry");
    expect(cacheEntry.encryptedStateKind).toBe("confirmed");

    const recovered = new Y.Doc();
    try {
      Y.applyUpdate(recovered, cacheEntry.encryptedState, "remote");
      Y.applyUpdate(recovered, pendingEntry.encryptedDiff, "remote");
      expect(canonicalMarkdownText(recovered)).toBe("alpha\nlocal\nbeta\n");
    } finally {
      recovered.destroy();
      baselineDoc.destroy();
      liveDoc.destroy();
    }
  });

  test("uses live primary cache and drops stale pending only after structural diff is unavailable", async () => {
    const baselineDoc = docWithText("alpha\nbeta\n");
    const baseline = encodeCanonicalSyncedStateAsUpdate(baselineDoc);
    const liveDoc = docWithText("alpha\nlocal\nbeta\n");
    mocks.pending.set("doc-2", {
      documentId: "doc-2",
      encryptedDiff: new Uint8Array([1, 2, 3]),
      diffNonce: new Uint8Array([4]),
      keyVersion: 1,
      createdAt: 1,
      updatedAt: 1,
    });

    expect(encodeCanonicalDiffAsUpdate(liveDoc, baseline)).toBeNull();
    expect(resolveOfflineCacheStateKind(stateFor(liveDoc, baseline))).toBe("live");

    await cacheDocumentStateAndPendingChanges("doc-2", "workspace-1", stateFor(liveDoc, baseline));

    const cacheEntry = mocks.documentCache.get("doc-2");
    if (!cacheEntry) throw new Error("expected document cache entry");
    expect(cacheEntry.encryptedStateKind).toBe("live");
    expect(textFromUpdate(cacheEntry.encryptedState)).toBe("alpha\nlocal\nbeta\n");
    expect(textFromUpdate(cacheEntry.encryptedConfirmedState)).toBe("alpha\nbeta\n");
    expect(mocks.deletePendingChanges).toHaveBeenCalledWith("doc-2");
    expect(mocks.pending.has("doc-2")).toBe(false);

    baselineDoc.destroy();
    liveDoc.destroy();
  });

  test("does not delete existing pending changes when blocked diff has no live cache", async () => {
    const baselineDoc = docWithText("alpha\nbeta\n");
    const baseline = encodeCanonicalSyncedStateAsUpdate(baselineDoc);
    const liveDoc = docWithText("alpha\nlocal\nbeta\n");
    const existingPending = {
      documentId: "doc-3",
      encryptedDiff: new Uint8Array([9]),
      diffNonce: new Uint8Array([8]),
      keyVersion: 1,
      createdAt: 1,
      updatedAt: 1,
    };
    mocks.pending.set("doc-3", existingPending);

    await cachePendingChanges("doc-3", stateFor(liveDoc, baseline));

    expect(mocks.deletePendingChanges).not.toHaveBeenCalled();
    expect(mocks.pending.get("doc-3")).toBe(existingPending);

    baselineDoc.destroy();
    liveDoc.destroy();
  });
});
