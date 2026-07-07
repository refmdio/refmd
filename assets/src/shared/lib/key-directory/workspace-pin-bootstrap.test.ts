import { describe, expect, it } from "vite-plus/test";

import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import {
  assertWorkspacePinBootstrapEnvelope,
  buildWorkspacePinBootstrapHash,
  type WorkspacePinBootstrapEnvelope,
  type WorkspacePinBootstrapPayload,
} from "./workspace-pin-bootstrap";

const base64Url32 = (byte: number) => base64UrlEncode(new Uint8Array(32).fill(byte));

const HASH_A = base64Url32(1);
const HASH_B = base64Url32(2);
const HASH_C = base64Url32(3);
const NONCE = base64Url32(4);

const issuer = {
  signer_kind: "device",
  user_id: "user-1",
  device_id: "device-1",
  signing_key_id: "signing-key-1",
  key_scope_kind: "workspace",
  key_scope_id: "workspace-1",
  key_checkpoint_sequence: 1,
  key_checkpoint_hash: HASH_A,
} as const;

const payload: WorkspacePinBootstrapPayload = {
  protocol: "refmd.workspace-pin-bootstrap",
  version: 1,
  workspace_id: "workspace-1",
  checkpoint_sequence: 1,
  checkpoint_hash: HASH_A,
  event_head_sequence: 2,
  event_head_hash: HASH_B,
  suite_policy_version: 1,
  min_suite_rank: 1000,
  allowed_suite_ids_hash: HASH_C,
  issuer,
  issuing_event_hash: HASH_B,
  expires_event_sequence: Number.MAX_SAFE_INTEGER,
  bootstrap_nonce: NONCE,
};

const signature = {
  protocol: "refmd.hybrid-signature",
  version: 1,
  suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
  suite_rank: 1000,
  signing_key_id: "signing-key-1",
  transcript_hash: "transcript-hash",
  ed25519: "ed25519-signature",
  mldsa65: "mldsa65-signature",
};

function bootstrap(): WorkspacePinBootstrapEnvelope {
  return {
    payload,
    signatures: [{ signer: issuer, signature }],
  } as WorkspacePinBootstrapEnvelope;
}

describe("WorkspacePinBootstrap exact schema", () => {
  it("hashes an exact bootstrap envelope", () => {
    expect(() =>
      buildWorkspacePinBootstrapHash({
        workspaceId: "workspace-1",
        bootstrap: bootstrap(),
      }),
    ).not.toThrow();
  });

  it("rejects extra payload and issuer fields", () => {
    expect(() =>
      buildWorkspacePinBootstrapHash({
        workspaceId: "workspace-1",
        bootstrap: {
          ...bootstrap(),
          payload: { ...payload, resource_hash: "not-allowed" },
        },
      }),
    ).toThrow("workspace_pin_payload_invalid");

    expect(() =>
      buildWorkspacePinBootstrapHash({
        workspaceId: "workspace-1",
        bootstrap: {
          ...bootstrap(),
          payload: {
            ...payload,
            issuer: { ...issuer, recipient_device_id: "not-allowed" },
          },
        },
      }),
    ).toThrow("workspace_pin_issuer_invalid");
  });

  it("rejects a nonce that is not canonical base64url-encoded 32 bytes", () => {
    expect(() =>
      buildWorkspacePinBootstrapHash({
        workspaceId: "workspace-1",
        bootstrap: {
          ...bootstrap(),
          payload: { ...payload, bootstrap_nonce: "abc" },
        },
      }),
    ).toThrow("invalid_base64url_decoded_length");
  });

  it("rejects extra envelope and signature envelope fields", () => {
    expect(() =>
      assertWorkspacePinBootstrapEnvelope(
        { ...bootstrap(), compatibility_hash: "not-allowed" },
        "workspace_pin_bootstrap_invalid",
      ),
    ).toThrow("workspace_pin_bootstrap_invalid");

    expect(() =>
      assertWorkspacePinBootstrapEnvelope(
        {
          ...bootstrap(),
          signatures: [{ ...bootstrap().signatures[0], legacy: true }],
        },
        "workspace_pin_bootstrap_invalid",
      ),
    ).toThrow("workspace_pin_signature_invalid");
  });
});
