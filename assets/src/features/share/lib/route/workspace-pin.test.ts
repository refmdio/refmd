import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { ensureShareWorkspaceKeyDirectoryPin } from "./workspace-pin";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

const nodeFsPromises = "node:fs/promises";
const { readFile } = await import(/* @vite-ignore */ nodeFsPromises);
const securityFixture = JSON.parse(
  await readFile("../native/refmd_crypto/testdata/refmd-signed-pq-wrap-v1.json", "utf8"),
) as {
  negative: Array<{
    base: string;
    mutation: string;
    operations: Array<{ op: "remove"; path: string }>;
    expected_error: string;
  }>;
};

const mocks = vi.hoisted(() => ({
  advanceKeyDirectoryPinWithProof: vi.fn(),
  getKeyDirectoryPin: vi.fn(),
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor: vi.fn(),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin: mocks.getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope: vi.fn((checkpoint: KeyDirectoryEnvelope) => {
    const payload = checkpoint.payload as { sequence: number; test_hash?: unknown };
    return typeof payload.test_hash === "string"
      ? payload.test_hash
      : `checkpoint-${payload.sequence}`;
  }),
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor:
    mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor,
}));

vi.mock("@/shared/lib/key-directory/workspace-pin-bootstrap", () => ({
  verifyAndInstallWorkspacePinBootstrap: vi.fn(),
}));

describe("ensureShareWorkspaceKeyDirectoryPin", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getKeyDirectoryPin.mockResolvedValue({
      checkpointSequence: 2,
      checkpointHash: "checkpoint-2",
      eventHeadSequence: 2,
      eventHeadHash: "event-2",
    });
  });

  it("waits for trusted-anchor lineage when a workspace pin already exists", async () => {
    const deferred = promiseWithResolvers<void>();
    mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor.mockReturnValueOnce(
      deferred.promise,
    );

    let settled = false;
    const ready = ensureShareWorkspaceKeyDirectoryPin({
      workspaceId: "workspace-1",
      workspaceKeyDirectoryCheckpoint: checkpoint(1),
      workspaceKeyDirectoryLatestCheckpoint: checkpoint(2),
      workspaceKeyDirectoryCheckpointAncestry: [checkpoint(1)],
      workspaceKeyDirectoryEventAncestry: [event(2)],
      mismatchCode: "share_workspace_pin_bootstrap_hash_mismatch",
    }).then(() => {
      settled = true;
    });

    await flushPromises();
    expect(mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor).toHaveBeenCalledTimes(1);
    expect(settled).toBe(false);

    deferred.resolve();
    await ready;
    expect(settled).toBe(true);
  });

  it("fails when newer latest lineage omits the current pinned checkpoint", async () => {
    await expect(
      ensureShareWorkspaceKeyDirectoryPin({
        workspaceId: "workspace-1",
        workspaceKeyDirectoryCheckpoint: checkpoint(1),
        workspaceKeyDirectoryLatestCheckpoint: checkpoint(4),
        workspaceKeyDirectoryCheckpointAncestry: [checkpoint(1)],
        workspaceKeyDirectoryEventAncestry: [event(2), event(3), event(4)],
        mismatchCode: "share_workspace_pin_bootstrap_hash_mismatch",
      }),
    ).rejects.toThrow("share_workspace_pin_bootstrap_hash_mismatch");

    expect(mocks.advanceKeyDirectoryPinWithProof).not.toHaveBeenCalled();
  });

  it("fails when latest checkpoint matches the pinned sequence with a different hash", async () => {
    await expect(
      ensureShareWorkspaceKeyDirectoryPin({
        workspaceId: "workspace-1",
        workspaceKeyDirectoryCheckpoint: checkpoint(1),
        workspaceKeyDirectoryLatestCheckpoint: checkpoint(2, "checkpoint-2-fork"),
        workspaceKeyDirectoryCheckpointAncestry: [checkpoint(1)],
        workspaceKeyDirectoryEventAncestry: [event(2)],
        mismatchCode: "share_workspace_pin_bootstrap_hash_mismatch",
      }),
    ).rejects.toThrow("share_workspace_pin_bootstrap_hash_mismatch");

    expect(mocks.advanceKeyDirectoryPinWithProof).not.toHaveBeenCalled();
    expect(mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor).not.toHaveBeenCalled();
  });

  it.each(
    securityFixture.negative.filter((vector) => vector.base === "share-participant-bootstrap-v1"),
  )("rejects $mutation", async (vector) => {
    mocks.getKeyDirectoryPin.mockResolvedValueOnce(null);
    const input: Record<string, unknown> = {
      workspaceId: "workspace-1",
      workspacePinBootstrapHash: "workspace-pin-bootstrap-hash",
      workspacePinBootstrap: {},
      workspaceKeyDirectoryCheckpoint: checkpoint(1),
      mismatchCode: "share_workspace_pin_bootstrap_hash_mismatch",
    };
    for (const operation of vector.operations) {
      const field = operation.path.slice(1);
      if (!(field in input)) throw new Error("fixture_patch_path_invalid");
      delete input[field];
    }

    await expect(
      ensureShareWorkspaceKeyDirectoryPin(
        input as Parameters<typeof ensureShareWorkspaceKeyDirectoryPin>[0],
      ),
    ).rejects.toThrow(vector.expected_error);
  });
});

async function flushPromises(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function checkpoint(sequence: number, hash?: string): KeyDirectoryEnvelope {
  return {
    payload: {
      sequence,
      ...(hash ? { test_hash: hash } : {}),
      covered_event_head: {
        head_sequence: sequence,
        head_hash: `event-${sequence}`,
      },
    },
    signatures: [],
  } as unknown as KeyDirectoryEnvelope;
}

function event(sequence: number): KeyDirectoryEnvelope {
  return {
    payload: {
      sequence,
    },
    signatures: [],
  } as unknown as KeyDirectoryEnvelope;
}

function promiseWithResolvers<T>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}
