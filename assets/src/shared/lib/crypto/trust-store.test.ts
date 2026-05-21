import { beforeEach, describe, expect, it, vi } from "vitest";
import { importTofuEntries, saveTofuEntry, type TofuEntry } from "./trust-store";
import type { HybridSigningPublicKeyMaterial } from "./signature-types";

const tofuStore = new Map<string, StoredTofuEntry>();

vi.mock("@/shared/lib/storage/idb", () => ({
  toArrayBuffer(bytes: Uint8Array) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  },
  openIdb: vi.fn(async () => ({
    transaction() {
      const tx = {
        oncomplete: null as (() => void) | null,
        onerror: null as (() => void) | null,
        onabort: null as (() => void) | null,
        abort() {
          queueMicrotask(() => tx.onabort?.());
        },
        objectStore() {
          return {
            get(key: [string, string]) {
              const request = {
                result: undefined as StoredTofuEntry | undefined,
                onerror: null as (() => void) | null,
                onsuccess: null as (() => void) | null,
              };
              queueMicrotask(() => {
                request.result = tofuStore.get(key.join("\u0000"));
                request.onsuccess?.();
              });
              return request;
            },
            put(value: StoredTofuEntry) {
              const request = {
                onerror: null as (() => void) | null,
              };
              queueMicrotask(() => {
                tofuStore.set(`${value.userId}\u0000${value.deviceId}`, value);
                maybeComplete(tx);
              });
              return request;
            },
          };
        },
      };
      return tx;
    },
    close: vi.fn(),
  })),
  idbConditionalPut: vi.fn(
    async (
      _db: unknown,
      _storeName: string,
      key: [string, string],
      value: StoredTofuEntry,
      predicate: (existing: StoredTofuEntry | undefined) => boolean,
    ) => {
      const storeKey = key.join("\u0000");
      const existing = tofuStore.get(storeKey);
      if (!predicate(existing)) return false;
      tofuStore.set(storeKey, value);
      return true;
    },
  ),
}));

describe("TOFU trust store", () => {
  beforeEach(() => {
    tofuStore.clear();
  });

  it("does not overwrite an existing TOFU entry with different keys", async () => {
    await saveTofuEntry(tofuEntry({ signing: 1, ecdh: 2 }));

    await expect(saveTofuEntry(tofuEntry({ signing: 9, ecdh: 2 }))).rejects.toThrow(
      "tofu_entry_conflict",
    );

    expect(
      tofuStore.get("user-1\u0000device-1")!.hybridSigningPublicKeyMaterial.ed25519_public,
    ).toBe("ed-1");
  });

  it("does not import a conflicting TOFU entry over an existing trust anchor", async () => {
    await saveTofuEntry(tofuEntry({ signing: 1, ecdh: 2 }));

    await expect(importTofuEntries([tofuEntry({ signing: 1, ecdh: 3 })])).rejects.toThrow(
      "tofu_entry_conflict",
    );

    expect(new Uint8Array(tofuStore.get("user-1\u0000device-1")!.ecdhPublicKey)[0]).toBe(2);
  });

  it("does not import conflicting duplicate entries from the same batch", async () => {
    await expect(
      importTofuEntries([tofuEntry({ signing: 1, ecdh: 2 }), tofuEntry({ signing: 1, ecdh: 3 })]),
    ).rejects.toThrow("tofu_entry_conflict");

    expect(tofuStore.size).toBe(0);
  });
});

function maybeComplete(tx: { oncomplete?: (() => void) | null }): void {
  queueMicrotask(() => tx.oncomplete?.());
}

function tofuEntry({ signing, ecdh }: { signing: number; ecdh: number }): TofuEntry {
  return {
    userId: "user-1",
    deviceId: "device-1",
    hybridSigningPublicKeyMaterial: hybridSigningPublicKeyMaterial(signing),
    ecdhPublicKey: new Uint8Array([ecdh]),
    firstSeenAt: 1,
    lastSeenAt: 1,
  };
}

interface StoredTofuEntry {
  userId: string;
  deviceId: string;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  ecdhPublicKey: ArrayBuffer;
  firstSeenAt: number;
  lastSeenAt: number;
}

function hybridSigningPublicKeyMaterial(seed: number): HybridSigningPublicKeyMaterial {
  return {
    protocol: "refmd.hybrid-signing-key-material",
    version: 1,
    owner_kind: "device",
    owner_id: "device-1",
    ed25519_public: `ed-${seed}`,
    mldsa65_public: `ml-${seed}`,
    suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
    suite_rank: 1000,
  };
}
