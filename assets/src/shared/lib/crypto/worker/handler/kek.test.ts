import { describe, expect, it } from "vitest";

import { base64UrlEncode, randomBytes } from "../../encoding";
import { createInitialState } from "../state";
import { handleUnwrapKekFromInvitationBootstrap, handleWrapKekForInvitationBootstrap } from "./kek";
import { handleGenerateInvitationRedeemAuthority } from "./sign";

const workspaceId = "workspace-1";
const guestInvitationId = "guest-invitation-1";

function scopedGuestAad() {
  return {
    protocol: "refmd.guest-invitation-bootstrap",
    version: 1,
    suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
    workspace_id: workspaceId,
    guest_invitation_id: guestInvitationId,
    scope_kind: "document",
    scope_id: "document-1",
    permission: "view",
    key_version_context: {
      workspace_kek_version: "NOT_APPLICABLE",
      share_key_version: "NOT_APPLICABLE",
      dek_version: 1,
    },
    token_hash: "token-hash",
  };
}

function scopedGuestPlaintext() {
  return {
    protocol: "refmd.guest-invitation-bootstrap",
    version: 1,
    workspace_id: workspaceId,
    guest_invitation_id: guestInvitationId,
    scope_kind: "document",
    scope_id: "document-1",
    permission: "view",
    key_version_context: {
      workspace_kek_version: "NOT_APPLICABLE",
      share_key_version: "NOT_APPLICABLE",
      dek_version: 1,
    },
    workspace_key_directory_checkpoint: { payload: { checkpoint: true }, signatures: [] },
    workspace_pin_bootstrap_hash: "pin-hash",
    workspace_pin_bootstrap: { payload: { pin: true }, signatures: [] },
  };
}

describe("invitation bootstrap package boundary", () => {
  it("creates scoped guest packages with scoped maintenance wraps and no workspace KEK state", () => {
    const issuerState = createInitialState();
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    const bootstrapSecret = base64UrlEncode(randomBytes(32));
    const bootstrap = handleWrapKekForInvitationBootstrap(issuerState, {
      protocol: "refmd.guest-invitation-bootstrap",
      workspaceId,
      keyVersion: 1,
      bootstrapSecret,
      aad: scopedGuestAad(),
      plaintext: scopedGuestPlaintext(),
      redeemAuthorityInvitationId: guestInvitationId,
      maintenanceWrapKey: randomBytes(32),
    }) as Record<string, unknown>;

    const recipientState = createInitialState();
    handleUnwrapKekFromInvitationBootstrap(recipientState, {
      bootstrap,
      bootstrapSecret,
    });
    expect(recipientState.kekCache.has(workspaceId)).toBe(false);
    expect(recipientState.activeKekVersions.has(workspaceId)).toBe(false);
  });

  it("rejects scoped guest package creation without a scoped maintenance key", () => {
    const issuerState = createInitialState();
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    expect(() =>
      handleWrapKekForInvitationBootstrap(issuerState, {
        protocol: "refmd.guest-invitation-bootstrap",
        workspaceId,
        keyVersion: 1,
        bootstrapSecret: base64UrlEncode(randomBytes(32)),
        aad: scopedGuestAad(),
        plaintext: scopedGuestPlaintext(),
        redeemAuthorityInvitationId: guestInvitationId,
      }),
    ).toThrow("invitation_bootstrap_maintenance_key_required");
  });

  it("rejects invitation bootstrap packages with extra envelope keys", () => {
    const issuerState = createInitialState();
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    const bootstrapSecret = base64UrlEncode(randomBytes(32));
    const bootstrap = handleWrapKekForInvitationBootstrap(issuerState, {
      protocol: "refmd.guest-invitation-bootstrap",
      workspaceId,
      keyVersion: 1,
      bootstrapSecret,
      aad: scopedGuestAad(),
      plaintext: scopedGuestPlaintext(),
      redeemAuthorityInvitationId: guestInvitationId,
      maintenanceWrapKey: randomBytes(32),
    }) as Record<string, unknown>;

    expect(() =>
      handleUnwrapKekFromInvitationBootstrap(createInitialState(), {
        bootstrap: { ...bootstrap, compatibility_hash: "not-allowed" },
        bootstrapSecret,
      }),
    ).toThrow("invitation_bootstrap_package_invalid");
  });
});
