import { describe, expect, it } from "vite-plus/test";
import {
  assertGuestInvitationBootstrapPlaintext,
  assertWorkspaceInvitationBootstrapPlaintext,
} from "./bootstrap";

interface NegativeVector {
  base: string;
  mutation: string;
  operations: Array<{ op: "remove"; path: string }>;
  expected_error: string;
}

const nodeFsPromises = "node:fs/promises";
const { readFile } = await import(/* @vite-ignore */ nodeFsPromises);
const fixture = JSON.parse(
  await readFile("../native/refmd_crypto/testdata/refmd-signed-pq-wrap-v1.json", "utf8"),
) as { negative: NegativeVector[] };

describe("invitation bootstrap security vectors", () => {
  it.each(
    fixture.negative.filter((vector) =>
      ["workspace-invitation-bootstrap-v1", "guest-invitation-bootstrap-v1"].includes(vector.base),
    ),
  )("rejects $mutation", (vector) => {
    const value =
      vector.base === "workspace-invitation-bootstrap-v1"
        ? workspaceInvitationBootstrap()
        : guestInvitationBootstrap();
    for (const operation of vector.operations) {
      const field = operation.path.slice(1);
      if (!(field in value)) throw new Error("fixture_patch_path_invalid");
      delete value[field];
    }

    const validate =
      vector.base === "workspace-invitation-bootstrap-v1"
        ? assertWorkspaceInvitationBootstrapPlaintext
        : assertGuestInvitationBootstrapPlaintext;
    expect(() => validate(value)).toThrow(vector.expected_error);
  });
});

function workspaceInvitationBootstrap(): Record<string, unknown> {
  return {
    protocol: "refmd.workspace-invitation-bootstrap",
    version: 1,
    workspace_id: "workspace-1",
    invitation_id: "invitation-1",
    role_id: "role-1",
    invited_email: "invitee@example.com",
    kek_version: 1,
    workspace_key_directory_checkpoint: {},
    workspace_pin_bootstrap_hash: "pin-hash",
    workspace_pin_bootstrap: {},
    redeem_authority_signing_key_id: "signing-key-1",
    redeem_authority_hybrid_signing_public_key_material: {},
  };
}

function guestInvitationBootstrap(): Record<string, unknown> {
  return {
    protocol: "refmd.guest-invitation-bootstrap",
    version: 1,
    workspace_id: "workspace-1",
    guest_invitation_id: "guest-invitation-1",
    scope_kind: "workspace",
    scope_id: "workspace-1",
    permission: "view",
    key_version_context: {},
    workspace_key_directory_checkpoint: {},
    workspace_pin_bootstrap_hash: "pin-hash",
    workspace_pin_bootstrap: {},
    redeem_authority_signing_key_id: "signing-key-1",
    redeem_authority_hybrid_signing_public_key_material: {},
  };
}
