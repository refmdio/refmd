import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  verifyWorkspaceSignedPqWrapOperation: vi.fn(),
  openSignedPqMemberKekWrap: vi.fn(),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof", () => ({
  verifyWorkspaceSignedPqWrapOperation: mocks.verifyWorkspaceSignedPqWrapOperation,
}));

vi.mock("./worker/client", () => ({
  getCryptoWorker: () => ({
    openSignedPqMemberKekWrap: mocks.openSignedPqMemberKekWrap,
  }),
}));

import {
  assertWorkspaceSenderKeyAdmission,
  openAdmittedWorkspaceMemberKekEnvelope,
} from "./kek-resolver";

const workspaceId = "workspace-1";
const senderDeviceId = "device-1";
const signingKeyId = "signing-key-1";
const signingMaterial = {
  protocol: "refmd.hybrid-signing-key-material",
  version: 1,
  owner_kind: "device",
  owner_id: senderDeviceId,
  ed25519_public: "ed25519-public",
  mldsa65_public: "mldsa65-public",
  suite_id: "refmd-hybrid-signature-ed25519-mldsa65-v1",
  suite_rank: 100,
};

function eventReference(sequence: number) {
  return {
    scope_kind: "workspace",
    scope_id: workspaceId,
    event_sequence: sequence,
    event_hash: `event-hash-${sequence}`,
  };
}

function admittedWrap(): Record<string, unknown> {
  return {
    sender_device_id: senderDeviceId,
    sender_user_id: "user-1",
    sender_hybrid_signing_public_key_material: signingMaterial,
    sender: {
      signer_kind: "device",
      user_id: "user-1",
      device_id: senderDeviceId,
      signing_key_id: signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: workspaceId,
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: "checkpoint-hash-1",
    },
    event_scope: { scope_kind: "workspace", scope_id: workspaceId },
    event: {
      wrap_event_sequence: 7,
      wrap_event_hash: "event-hash-7",
      wrap_event_body_hash: "event-body-hash-7",
    },
    operation_checkpoint: {
      checkpoint_sequence: 3,
      checkpoint_hash: "checkpoint-hash-3",
      covered_event_head_sequence: 9,
      covered_event_head_hash: "event-hash-9",
    },
    workspace_key_directory_checkpoint: {
      payload: {
        scope_kind: "workspace",
        scope_id: workspaceId,
        sequence: 3,
        device_keys: [
          {
            key_id: signingKeyId,
            key_material: signingMaterial,
            valid_from: eventReference(7),
            revoked_at: eventReference(8),
          },
        ],
      },
      signatures: [],
    },
  };
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
  return value as Record<string, unknown>;
}

describe("workspace sender key admission", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.verifyWorkspaceSignedPqWrapOperation.mockResolvedValue({});
    mocks.openSignedPqMemberKekWrap.mockResolvedValue(undefined);
  });

  it("accepts a key at its valid-from boundary and before its revocation boundary", () => {
    expect(() => assertWorkspaceSenderKeyAdmission(workspaceId, admittedWrap())).not.toThrow();
  });

  it.each([
    [
      "not-yet-valid key",
      (wrap: Record<string, unknown>) => {
        const checkpoint = record(wrap.workspace_key_directory_checkpoint);
        const payload = record(checkpoint.payload);
        const entry = record((payload.device_keys as unknown[])[0]);
        entry.valid_from = eventReference(8);
      },
      "workspace_sender_signing_key_not_yet_valid",
    ],
    [
      "key revoked at the wrap event",
      (wrap: Record<string, unknown>) => {
        const checkpoint = record(wrap.workspace_key_directory_checkpoint);
        const payload = record(checkpoint.payload);
        const entry = record((payload.device_keys as unknown[])[0]);
        entry.revoked_at = eventReference(7);
      },
      "workspace_sender_signing_key_revoked",
    ],
    [
      "wrong workspace",
      (wrap: Record<string, unknown>) => {
        record(wrap.event_scope).scope_id = "workspace-2";
      },
      "workspace_sender_record_mismatch",
    ],
    [
      "wrong device",
      (wrap: Record<string, unknown>) => {
        wrap.sender_device_id = "device-2";
      },
      "workspace_sender_record_mismatch",
    ],
    [
      "wrong signing key id",
      (wrap: Record<string, unknown>) => {
        record(wrap.sender).signing_key_id = "signing-key-2";
      },
      "workspace_sender_signing_key_missing",
    ],
    [
      "wrong signing material",
      (wrap: Record<string, unknown>) => {
        wrap.sender_hybrid_signing_public_key_material = {
          ...signingMaterial,
          ed25519_public: "substituted",
        };
      },
      "workspace_sender_signing_material_mismatch",
    ],
    [
      "missing device key set",
      (wrap: Record<string, unknown>) => {
        const checkpoint = record(wrap.workspace_key_directory_checkpoint);
        delete record(checkpoint.payload).device_keys;
      },
      "workspace_sender_signing_key_set_invalid",
    ],
  ])("rejects %s", (_label, mutate, expectedError) => {
    const wrap = structuredClone(admittedWrap());
    mutate(wrap);
    expect(() => assertWorkspaceSenderKeyAdmission(workspaceId, wrap)).toThrow(expectedError);
  });

  it("opens a member envelope only after operation and sender admission verification", async () => {
    const envelope = admittedWrap();

    await openAdmittedWorkspaceMemberKekEnvelope(workspaceId, envelope);

    expect(mocks.verifyWorkspaceSignedPqWrapOperation).toHaveBeenCalledWith(workspaceId, envelope);
    expect(mocks.openSignedPqMemberKekWrap).toHaveBeenCalledWith({
      operationProof: envelope,
      senderSigningPublicKeyMaterial: signingMaterial,
    });
    expect(mocks.verifyWorkspaceSignedPqWrapOperation.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.openSignedPqMemberKekWrap.mock.invocationCallOrder[0] ?? 0,
    );
  });

  it("does not reach the Worker when sender admission fails", async () => {
    const envelope = admittedWrap();
    const checkpoint = record(envelope.workspace_key_directory_checkpoint);
    const payload = record(checkpoint.payload);
    const entry = record((payload.device_keys as unknown[])[0]);
    entry.revoked_at = eventReference(7);

    await expect(openAdmittedWorkspaceMemberKekEnvelope(workspaceId, envelope)).rejects.toThrow(
      "workspace_sender_signing_key_revoked",
    );
    expect(mocks.openSignedPqMemberKekWrap).not.toHaveBeenCalled();
  });
});
