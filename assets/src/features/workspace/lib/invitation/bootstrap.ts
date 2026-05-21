import {
  assertWorkspacePinBootstrapEnvelope,
  verifyAndInstallWorkspacePinBootstrap,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";

export interface WorkspaceInvitationBootstrapPlaintext {
  protocol: "refmd.workspace-invitation-bootstrap";
  version: 1;
  workspace_id: string;
  invitation_id: string;
  role_id: string;
  invited_email: string;
  kek_version: number;
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
  workspace_pin_bootstrap_hash: string;
  workspace_pin_bootstrap: WorkspacePinBootstrapEnvelope;
  redeem_authority_signing_key_id: string;
  redeem_authority_hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
}

export interface GuestInvitationBootstrapPlaintext {
  protocol: "refmd.guest-invitation-bootstrap";
  version: 1;
  workspace_id: string;
  guest_invitation_id: string;
  scope_kind: "workspace" | "document" | "folder" | "share";
  scope_id: string;
  permission: "view" | "edit";
  key_version_context: GuestInvitationKeyVersionContext;
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
  workspace_pin_bootstrap_hash: string;
  workspace_pin_bootstrap: WorkspacePinBootstrapEnvelope;
  redeem_authority_signing_key_id: string;
  redeem_authority_hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
}

function recordField(value: unknown, code: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function stringField(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function numberField(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) throw new Error(code);
  return value;
}

function permissionField(value: unknown): "view" | "edit" {
  if (value !== "view" && value !== "edit")
    throw new Error("invitation_bootstrap_permission_invalid");
  return value;
}

function scopeKindField(value: unknown): "workspace" | "document" | "folder" | "share" {
  if (value !== "workspace" && value !== "document" && value !== "folder" && value !== "share") {
    throw new Error("invitation_bootstrap_scope_invalid");
  }
  return value;
}

export interface GuestInvitationKeyVersionContext {
  workspace_kek_version: number | "NOT_APPLICABLE";
  share_key_version: number | "NOT_APPLICABLE";
  dek_version: number | "NOT_APPLICABLE";
}

function assertExactKeys(record: Record<string, unknown>, keys: string[], code: string): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(code);
  }
}

function keyVersionValue(value: unknown): number | "NOT_APPLICABLE" {
  if (value === "NOT_APPLICABLE") return value;
  return numberField(value, "guest_invitation_bootstrap_key_context_invalid");
}

function keyVersionContext(value: unknown): GuestInvitationKeyVersionContext {
  const record = recordField(value, "guest_invitation_bootstrap_key_context_invalid");
  assertExactKeys(
    record,
    ["workspace_kek_version", "share_key_version", "dek_version"],
    "guest_invitation_bootstrap_key_context_invalid",
  );
  return {
    workspace_kek_version: keyVersionValue(record.workspace_kek_version),
    share_key_version: keyVersionValue(record.share_key_version),
    dek_version: keyVersionValue(record.dek_version),
  };
}

export function assertWorkspaceInvitationBootstrapPlaintext(
  value: unknown,
): WorkspaceInvitationBootstrapPlaintext {
  const record = recordField(value, "invitation_bootstrap_plaintext_invalid");
  assertExactKeys(
    record,
    [
      "invitation_id",
      "invited_email",
      "kek_version",
      "protocol",
      "redeem_authority_hybrid_signing_public_key_material",
      "redeem_authority_signing_key_id",
      "role_id",
      "version",
      "workspace_id",
      "workspace_key_directory_checkpoint",
      "workspace_pin_bootstrap",
      "workspace_pin_bootstrap_hash",
    ],
    "invitation_bootstrap_plaintext_invalid",
  );
  if (record.protocol !== "refmd.workspace-invitation-bootstrap" || record.version !== 1) {
    throw new Error("invitation_bootstrap_protocol_invalid");
  }
  return {
    protocol: "refmd.workspace-invitation-bootstrap",
    version: 1,
    workspace_id: stringField(record.workspace_id, "invitation_bootstrap_workspace_invalid"),
    invitation_id: stringField(record.invitation_id, "invitation_bootstrap_id_invalid"),
    role_id: stringField(record.role_id, "invitation_bootstrap_role_invalid"),
    invited_email: stringField(record.invited_email, "invitation_bootstrap_email_invalid"),
    kek_version: numberField(record.kek_version, "invitation_bootstrap_kek_invalid"),
    workspace_key_directory_checkpoint: assertKeyDirectoryEnvelope(
      record.workspace_key_directory_checkpoint,
      "invitation_bootstrap_checkpoint_invalid",
    ),
    workspace_pin_bootstrap_hash: stringField(
      record.workspace_pin_bootstrap_hash,
      "invitation_bootstrap_pin_invalid",
    ),
    workspace_pin_bootstrap: assertWorkspacePinBootstrapEnvelope(
      record.workspace_pin_bootstrap,
      "invitation_bootstrap_pin_invalid",
    ),
    redeem_authority_signing_key_id: stringField(
      record.redeem_authority_signing_key_id,
      "invitation_bootstrap_redeem_authority_key_invalid",
    ),
    redeem_authority_hybrid_signing_public_key_material: recordField(
      record.redeem_authority_hybrid_signing_public_key_material,
      "invitation_bootstrap_redeem_authority_invalid",
    ) as unknown as HybridSigningPublicKeyMaterial,
  };
}

export function assertGuestInvitationBootstrapPlaintext(
  value: unknown,
): GuestInvitationBootstrapPlaintext {
  const record = recordField(value, "guest_invitation_bootstrap_plaintext_invalid");
  assertExactKeys(
    record,
    [
      "guest_invitation_id",
      "key_version_context",
      "permission",
      "protocol",
      "redeem_authority_hybrid_signing_public_key_material",
      "redeem_authority_signing_key_id",
      "scope_id",
      "scope_kind",
      "version",
      "workspace_id",
      "workspace_key_directory_checkpoint",
      "workspace_pin_bootstrap",
      "workspace_pin_bootstrap_hash",
    ],
    "guest_invitation_bootstrap_plaintext_invalid",
  );
  if (record.protocol !== "refmd.guest-invitation-bootstrap" || record.version !== 1) {
    throw new Error("guest_invitation_bootstrap_protocol_invalid");
  }
  const scopeKind = scopeKindField(record.scope_kind);
  const plaintext: GuestInvitationBootstrapPlaintext = {
    protocol: "refmd.guest-invitation-bootstrap",
    version: 1,
    workspace_id: stringField(record.workspace_id, "guest_invitation_bootstrap_workspace_invalid"),
    guest_invitation_id: stringField(
      record.guest_invitation_id,
      "guest_invitation_bootstrap_id_invalid",
    ),
    scope_kind: scopeKind,
    scope_id: stringField(record.scope_id, "guest_invitation_bootstrap_scope_invalid"),
    permission: permissionField(record.permission),
    key_version_context: keyVersionContext(record.key_version_context),
    workspace_key_directory_checkpoint: assertKeyDirectoryEnvelope(
      record.workspace_key_directory_checkpoint,
      "guest_invitation_bootstrap_checkpoint_invalid",
    ),
    workspace_pin_bootstrap_hash: stringField(
      record.workspace_pin_bootstrap_hash,
      "guest_invitation_bootstrap_pin_invalid",
    ),
    workspace_pin_bootstrap: assertWorkspacePinBootstrapEnvelope(
      record.workspace_pin_bootstrap,
      "guest_invitation_bootstrap_pin_invalid",
    ),
    redeem_authority_signing_key_id: stringField(
      record.redeem_authority_signing_key_id,
      "guest_invitation_bootstrap_redeem_authority_key_invalid",
    ),
    redeem_authority_hybrid_signing_public_key_material: recordField(
      record.redeem_authority_hybrid_signing_public_key_material,
      "guest_invitation_bootstrap_redeem_authority_invalid",
    ) as unknown as HybridSigningPublicKeyMaterial,
  };
  return plaintext;
}

export async function pinWorkspaceCheckpointFromBootstrap(params: {
  workspaceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  workspaceKeyDirectoryEventAncestry?: KeyDirectoryEnvelope[];
  workspacePinBootstrapHash: string;
  workspacePinBootstrap: WorkspacePinBootstrapEnvelope;
}): Promise<void> {
  await verifyAndInstallWorkspacePinBootstrap({
    workspaceId: params.workspaceId,
    authenticatedWorkspacePinBootstrapHash: params.workspacePinBootstrapHash,
    bootstrap: params.workspacePinBootstrap,
    checkpointEnvelope: params.checkpointEnvelope,
    workspaceKeyDirectoryEventAncestry: params.workspaceKeyDirectoryEventAncestry,
    operationSequence: checkpointEventHeadSequence(params.checkpointEnvelope),
  });
}

function checkpointEventHeadSequence(checkpointEnvelope: KeyDirectoryEnvelope): number {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const head = payload?.covered_event_head as Record<string, unknown> | undefined;
  const sequence = head?.head_sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) {
    throw new Error("workspace_key_directory_checkpoint_head_invalid");
  }
  return sequence;
}
