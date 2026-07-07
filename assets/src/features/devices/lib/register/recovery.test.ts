import { describe, expect, it } from "vite-plus/test";
import { buildRecoveryApproveDeviceRequest, type RecoveryApproveDeviceRequest } from "./recovery";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

const envelope = (label: string): KeyDirectoryEnvelope =>
  ({
    payload: {
      protocol: "refmd.key-directory",
      version: 1,
      label,
    },
    signatures: [],
  }) as unknown as KeyDirectoryEnvelope;

describe("recovery device registration", () => {
  it("keeps workspace base checkpoints out of the approve request body", () => {
    const baseCheckpoint = envelope("base");
    const event = envelope("event");
    const checkpoint = envelope("checkpoint");

    const request = buildRecoveryApproveDeviceRequest({
      approvalSignature: {
        protocol: "refmd.hybrid-signature",
        version: 1,
        signing_purpose: "recovery_device_approval",
        surface_id: "recovery_device_approval",
        surface_variant: "none",
        owner_kind: "identity",
        owner_id: "user-1",
        signing_key_id: "identity-signing-key",
        transcript_hash: "transcript-hash",
        signature: {
          ed25519: "ed25519",
          mldsa65: "mldsa65",
        },
      } as unknown as RecoveryApproveDeviceRequest["approval_signature"],
      approvalProof: {
        approval_signature_surface: "recovery_device_approval",
      } as unknown as RecoveryApproveDeviceRequest["approval_proof"],
      userKeyDirectory: {
        events: [event],
        checkpoint,
      },
      workspaceAppends: [
        {
          workspaceId: "00000000-0000-4000-8000-000000000001",
          baseCheckpoint,
          baseCheckpointAncestry: [],
          baseEventAncestry: [],
          events: [event],
          checkpoint,
        },
      ],
    });

    expect(request.approval_signature_surface).toBe("recovery_device_approval");
    expect(request.workspace_key_directory_appends).toEqual([
      {
        workspace_id: "00000000-0000-4000-8000-000000000001",
        events: [event],
        checkpoint,
      },
    ]);
    expect(JSON.stringify(request)).not.toContain("baseCheckpoint");
    expect(JSON.stringify(request)).not.toContain("base_checkpoint");
  });
});
