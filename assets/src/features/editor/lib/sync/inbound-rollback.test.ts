import { describe, expect, test } from "vitest";
import type { DocumentStatePin } from "@/shared/lib/anti-rollback/document-state-pins";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "@/shared/lib/crypto/suite";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { collectRollbackWarnings } from "./inbound-rollback";

function pinWithClock(clock: number): DocumentStatePin {
  return {
    documentId: "doc",
    targetDocumentId: "doc",
    latestSnapshotId: "snapshot-current",
    latestSnapshotProofHash: "proof",
    latestSnapshotCiphertextHash: "ciphertext",
    latestGlobalVersion: 10,
    observedAt: 1,
    perDeviceMaxClocks: {
      "workspace:device-key": clock,
    },
  };
}

function snapshotOnlyPayload(parentClock: number): DocumentPayload {
  return {
    snapshot: {
      ciphertext: "ciphertext",
      nonce: "nonce",
      signature: {
        protocol: "refmd.hybrid-signature",
        version: CURRENT_PROTOCOL_VERSION,
        suite_id: SUITE_IDS.HYBRID_SIGNATURE,
        suite_rank: CURRENT_SUITE_RANK,
        signing_key_id: "workspace:device-key",
        transcript_hash: "transcript",
        ed25519: "ed25519",
        mldsa65: "mldsa65",
      },
      admission: {
        workspaceKeyDirectoryEvents: [],
        workspaceKeyDirectoryCheckpoint: {},
      },
      publicData: {
        docId: "doc",
        snapshotId: "snapshot-current",
        signingKeyId: "workspace:device-key",
        ownerKind: "device",
        ownerId: "device-key",
        authorityKind: "workspace_device",
        authorityId: "device-key",
        authorityContextKey: "workspace",
        authorityScopeId: "workspace",
        authorityPermissionVersion: 1,
        keyCheckpointSequence: 1,
        keyCheckpointHash: "checkpoint",
        keyVersion: 1,
        parentSnapshotId: "snapshot-parent",
        parentProofHash: "proof-parent",
        parentSnapshotUpdateClocks: {
          "workspace:device-key": parentClock,
        },
      },
    },
    updates: [],
    snapshotProofChain: [],
    latestVersion: 10,
  };
}

function emptyDeltaPayload(): DocumentPayload {
  return {
    snapshot: null,
    updates: [],
    snapshotProofChain: [],
    latestVersion: 10,
  };
}

describe("inbound rollback detection", () => {
  test("detects clock rollback from snapshot-only parent clocks", () => {
    expect(collectRollbackWarnings(snapshotOnlyPayload(3), pinWithClock(5))).toContain(
      "Clock rollback: device=workspace:device-key clock=3 < pin=5",
    );
  });

  test("accepts snapshot-only parent clocks at the pinned maximum", () => {
    expect(collectRollbackWarnings(snapshotOnlyPayload(5), pinWithClock(5))).toEqual([]);
  });

  test("detects clock rollback when an empty delta baseline is below the pin", () => {
    expect(
      collectRollbackWarnings(emptyDeltaPayload(), pinWithClock(5), {
        "workspace:device-key": 3,
      }),
    ).toContain("Clock rollback: device=workspace:device-key clock=3 < pin=5");
  });

  test("accepts an empty delta baseline at the pinned maximum", () => {
    expect(
      collectRollbackWarnings(emptyDeltaPayload(), pinWithClock(5), {
        "workspace:device-key": 5,
      }),
    ).toEqual([]);
  });
});
