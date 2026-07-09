import { CURRENT_PROTOCOL_VERSION, SUITE_IDS } from "./suite";
import type { SigningOwnerKind } from "./signature-transcript-core";

export interface ActiveSigningSurface {
  surface_id: string;
  signing_purpose: string;
  transcript_owner: string;
  owner_kind: SigningOwnerKind;
  variant: string;
  suite_id: typeof SUITE_IDS.HYBRID_SIGNATURE;
  protocol_version: typeof CURRENT_PROTOCOL_VERSION;
}

export type SemanticValidator =
  | "ake_commitment"
  | "ake_prekey"
  | "device_approval"
  | "device_revocation"
  | "document_admission"
  | "editor_ephemeral"
  | "genesis_device_bootstrap"
  | "recovery_device_approval"
  | "initial_key_delivery"
  | "key_deletion"
  | "key_directory_checkpoint"
  | "key_directory_event"
  | "pin_gossip"
  | "plugin_bundle_approval"
  | "plugin_consent_event"
  | "plugin_network_proxy_request"
  | "rrp_request"
  | "pq_wrap"
  | "recipient_bound_authorization"
  | "recovery_authorization_proof"
  | "recovery_session"
  | "share_capability_authorization"
  | "share_participant_device_authorization"
  | "workspace_pin_bootstrap";

const OWNER_IDENTITY = ["identity"] as const;
const OWNER_DEVICE = ["device"] as const;
const OWNER_KEY_DIRECTORY_EVENT = ["identity", "device"] as const;
const OWNER_KEY_DIRECTORY_INVITATION_REDEEM_EVENT = [
  "device",
  "invitation_redeem_authority",
] as const;
const OWNER_KEY_DIRECTORY_DOCUMENT_EVENT = ["device", "share_participant_device"] as const;
const OWNER_SHARE_PARTICIPANT_DEVICE = ["share_participant_device"] as const;
const OWNER_SHARE_CAPABILITY = ["share_capability"] as const;
const OWNER_INVITATION_REDEEM_AUTHORITY = ["invitation_redeem_authority"] as const;
const ACTIVE_SURFACE_OWNER_KINDS = new Map<string, readonly SigningOwnerKind[]>();

const ACTIVE_SIGNING_SURFACES = [
  surface("pq_wrap", "pq_wrap", "refmd.wrap.pq_wrap", "none", OWNER_DEVICE),
  ...[
    { variant: "identity_initial", owners: OWNER_IDENTITY },
    { variant: "workspace_initial", owners: OWNER_DEVICE },
    { variant: "identity_active", owners: OWNER_IDENTITY },
    { variant: "identity_rotation", owners: OWNER_IDENTITY },
    { variant: "workspace_authorized", owners: OWNER_DEVICE },
    {
      variant: "invitation_redeem_authority",
      owners: OWNER_INVITATION_REDEEM_AUTHORITY,
    },
    {
      variant: "share_participant_document_operation",
      owners: OWNER_SHARE_PARTICIPANT_DEVICE,
    },
    { variant: "device_authorized", owners: OWNER_DEVICE },
  ].map(({ variant, owners }) =>
    surface(
      "key_directory_checkpoint",
      "key_directory_checkpoint",
      `refmd.key_directory.checkpoint.${variant}`,
      variant,
      owners,
    ),
  ),
  ...[
    "wrap_issued",
    "identity_key_added",
    "device_key_added",
    "member_added",
    "member_role_changed",
    "member_removed",
    "signing_key_revoked",
    "encryption_key_revoked",
    "suite_policy_changed",
    "share_created",
    "share_metadata_updated",
    "share_key_scope_added",
    "share_key_scope_replaced",
    "share_key_scope_removed",
    "share_exclusion_changed",
    "share_revoked",
    "recipient_bound_delivery_admitted",
    "workspace_invitation_created",
    "workspace_invitation_bootstrap_updated",
    "workspace_invitation_revoked",
    "workspace_invitation_redeemed",
    "guest_invitation_created",
    "guest_invitation_bootstrap_updated",
    "guest_invitation_revoked",
    "guest_invitation_redeemed",
    "guest_grant_revoked",
    "guest_device_revoked",
    "rotation_started",
    "rotation_completed",
    "old_key_deleted",
    "document_update_accepted",
    "document_write_session_admitted",
    "document_write_state_changed",
    "document_snapshot_accepted",
  ].map((eventType) =>
    surface(
      "key_directory_event",
      "key_directory_event",
      `refmd.key_directory.event.${eventType}`,
      eventType,
      eventType === "document_update_accepted" ||
        eventType === "document_write_session_admitted" ||
        eventType === "document_snapshot_accepted"
        ? OWNER_KEY_DIRECTORY_DOCUMENT_EVENT
        : eventType === "workspace_invitation_redeemed" || eventType === "guest_invitation_redeemed"
          ? OWNER_KEY_DIRECTORY_INVITATION_REDEEM_EVENT
          : OWNER_KEY_DIRECTORY_EVENT,
    ),
  ),
  surface(
    "workspace_pin_bootstrap",
    "workspace_pin_bootstrap",
    "refmd.workspace.pin_bootstrap",
    "none",
    OWNER_DEVICE,
  ),
  surface(
    "recipient_bound_authorization",
    "recipient_bound_authorization",
    "refmd.recipient_bound.authorization",
    "none",
    OWNER_DEVICE,
  ),
  surface(
    "share_capability_authorization",
    "share_capability_authorization",
    "refmd.share.capability_authorization",
    "none",
    OWNER_SHARE_CAPABILITY,
  ),
  surface(
    "share_participant_device_authorization",
    "share_participant_device_authorization",
    "refmd.share.participant_device_authorization",
    "none",
    OWNER_SHARE_PARTICIPANT_DEVICE,
  ),
  surface(
    "rrp_request",
    "rrp_request",
    "refmd.rrp.request.http_user_device",
    "http_user_device",
    OWNER_DEVICE,
  ),
  surface(
    "rrp_request",
    "rrp_request",
    "refmd.rrp.request.http_share_participant_device",
    "http_share_participant_device",
    OWNER_SHARE_PARTICIPANT_DEVICE,
  ),
  surface(
    "rrp_request",
    "rrp_request",
    "refmd.rrp.request.channel_user_device",
    "channel_user_device",
    OWNER_DEVICE,
  ),
  surface(
    "rrp_request",
    "rrp_request",
    "refmd.rrp.request.channel_share_participant_device",
    "channel_share_participant_device",
    OWNER_SHARE_PARTICIPANT_DEVICE,
  ),
  surface(
    "genesis_device_bootstrap",
    "genesis_device_bootstrap",
    "refmd.device.genesis_device_bootstrap",
    "none",
    OWNER_IDENTITY,
  ),
  surface("device_approval", "device_approval", "refmd.device.approval", "none", OWNER_DEVICE),
  surface(
    "plugin_bundle_approval",
    "plugin_bundle_approval",
    "refmd.plugin.bundle_approval",
    "none",
    OWNER_DEVICE,
  ),
  surface(
    "plugin_consent_event",
    "plugin_consent_event",
    "refmd.plugin.consent_event",
    "none",
    OWNER_DEVICE,
  ),
  surface(
    "plugin_network_proxy_request",
    "plugin_network_proxy_request",
    "refmd.plugin.network_proxy_request",
    "none",
    OWNER_DEVICE,
  ),
  surface(
    "responder_prekey",
    "responder_prekey",
    "refmd.ake.responder_prekey",
    "none",
    OWNER_DEVICE,
  ),
  surface(
    "initiator_ake_commitment",
    "initiator_ake_commitment",
    "refmd.ake.initiator_commitment",
    "none",
    OWNER_DEVICE,
  ),
  ...["umk_distribution", "device_approval_kek_initial", "trust_transfer"].map((variant) =>
    surface(
      "initial_key_delivery",
      "initial_key_delivery",
      `refmd.initial_key_delivery.${variant}`,
      variant,
      OWNER_DEVICE,
    ),
  ),
  surface(
    "recovery_device_approval",
    "recovery_device_approval",
    "refmd.device.recovery_approval",
    "none",
    OWNER_IDENTITY,
  ),
  surface(
    "device_revocation",
    "device_revocation",
    "refmd.device.revocation",
    "none",
    OWNER_DEVICE,
  ),
  surface("recovery_session", "recovery_session", "refmd.recovery.session", "none", OWNER_IDENTITY),
  surface(
    "recovery_authorization_proof",
    "recovery_authorization_proof",
    "refmd.recovery.authorization_proof",
    "none",
    OWNER_IDENTITY,
  ),
  surface(
    "pin_gossip_statement",
    "pin_gossip_statement",
    "refmd.pin.gossip_statement",
    "none",
    OWNER_DEVICE,
  ),
  ...["device_key_deletion_proof", "identity_key_deletion_proof"].map((variant) =>
    surface(
      "device_key_deletion_proof",
      "device_key_deletion_proof",
      variant === "device_key_deletion_proof"
        ? "refmd.device.key_deletion.device_key"
        : "refmd.device.key_deletion.identity_key",
      variant,
      OWNER_DEVICE,
    ),
  ),
  surface(
    "document_update",
    "document_update",
    "refmd.document.update.workspace_device",
    "workspace_device",
    OWNER_DEVICE,
  ),
  surface(
    "document_update",
    "document_update",
    "refmd.document.update.share_participant_device",
    "share_participant_device",
    OWNER_SHARE_PARTICIPANT_DEVICE,
  ),
  surface(
    "document_snapshot",
    "document_snapshot",
    "refmd.document.snapshot.workspace_device",
    "workspace_device",
    OWNER_DEVICE,
  ),
  surface(
    "document_snapshot",
    "document_snapshot",
    "refmd.document.snapshot.share_participant_device",
    "share_participant_device",
    OWNER_SHARE_PARTICIPANT_DEVICE,
  ),
  surface(
    "editor_ephemeral",
    "editor_ephemeral",
    "refmd.editor.ephemeral.workspace_device",
    "workspace_device",
    OWNER_DEVICE,
  ),
  surface(
    "editor_ephemeral",
    "editor_ephemeral",
    "refmd.editor.ephemeral.share_participant_device",
    "share_participant_device",
    OWNER_SHARE_PARTICIPANT_DEVICE,
  ),
  surface(
    "editor_ephemeral_session",
    "editor_ephemeral_session",
    "refmd.editor.ephemeral_session.workspace_device",
    "workspace_device",
    OWNER_DEVICE,
  ),
  surface(
    "editor_ephemeral_session",
    "editor_ephemeral_session",
    "refmd.editor.ephemeral_session.share_participant_device",
    "share_participant_device",
    OWNER_SHARE_PARTICIPANT_DEVICE,
  ),
] as const satisfies readonly ActiveSigningSurface[];

const ACTIVE_BY_PURPOSE_AND_VARIANT = new Map<string, ActiveSigningSurface>(
  ACTIVE_SIGNING_SURFACES.map((entry) => [
    inventoryKey(entry.signing_purpose, entry.variant),
    entry,
  ]),
);

validateInventory();

export function __testActiveSigningSurfaces(): readonly ActiveSigningSurface[] {
  return ACTIVE_SIGNING_SURFACES;
}

export function getActiveSigningSurface(
  signingPurpose: string,
  variant: string,
): ActiveSigningSurface {
  const entry = ACTIVE_BY_PURPOSE_AND_VARIANT.get(inventoryKey(signingPurpose, variant));
  if (!entry) throw new Error("signing_surface_not_active");
  return entry;
}

export function assertSigningSurfaceOwner(
  entry: ActiveSigningSurface,
  ownerKind: SigningOwnerKind,
): void {
  if (!ownerKindsForSurface(entry).includes(ownerKind)) {
    throw new Error("signing_surface_owner_kind_mismatch");
  }
}

function ownerKindsForSurface(entry: ActiveSigningSurface): readonly SigningOwnerKind[] {
  assertRegisteredInventoryEntry(entry);
  const ownerKinds = ACTIVE_SURFACE_OWNER_KINDS.get(
    inventoryKey(entry.signing_purpose, entry.variant),
  );
  if (!ownerKinds) throw new Error("signing_surface_owner_kind_mismatch");
  return ownerKinds;
}

function semanticValidatorForSurface(entry: ActiveSigningSurface): SemanticValidator {
  assertRegisteredInventoryEntry(entry);
  return semanticValidatorName(entry);
}

function assertRegisteredInventoryEntry(entry: ActiveSigningSurface): void {
  if (
    ACTIVE_BY_PURPOSE_AND_VARIANT.get(inventoryKey(entry.signing_purpose, entry.variant)) !== entry
  ) {
    throw new Error("signing_surface_not_active");
  }
}

function semanticValidatorName(entry: ActiveSigningSurface): SemanticValidator {
  if (entry.signing_purpose === "pq_wrap") return "pq_wrap";
  if (entry.signing_purpose === "workspace_pin_bootstrap") return "workspace_pin_bootstrap";
  if (entry.signing_purpose === "key_directory_checkpoint") return "key_directory_checkpoint";
  if (entry.signing_purpose === "key_directory_event") return "key_directory_event";
  if (entry.signing_purpose === "recipient_bound_authorization")
    return "recipient_bound_authorization";
  if (entry.signing_purpose === "share_capability_authorization")
    return "share_capability_authorization";
  if (entry.signing_purpose === "share_participant_device_authorization")
    return "share_participant_device_authorization";
  if (entry.signing_purpose === "rrp_request") return "rrp_request";
  if (entry.signing_purpose === "genesis_device_bootstrap") return "genesis_device_bootstrap";
  if (entry.signing_purpose === "device_approval") return "device_approval";
  if (entry.signing_purpose === "plugin_bundle_approval") return "plugin_bundle_approval";
  if (entry.signing_purpose === "plugin_consent_event") return "plugin_consent_event";
  if (entry.signing_purpose === "plugin_network_proxy_request")
    return "plugin_network_proxy_request";
  if (entry.signing_purpose === "responder_prekey") return "ake_prekey";
  if (entry.signing_purpose === "initiator_ake_commitment") return "ake_commitment";
  if (entry.signing_purpose === "initial_key_delivery") return "initial_key_delivery";
  if (entry.signing_purpose === "recovery_device_approval") return "recovery_device_approval";
  if (entry.signing_purpose === "device_revocation") return "device_revocation";
  if (entry.signing_purpose === "recovery_session") return "recovery_session";
  if (entry.signing_purpose === "recovery_authorization_proof")
    return "recovery_authorization_proof";
  if (entry.signing_purpose === "pin_gossip_statement") return "pin_gossip";
  if (entry.signing_purpose === "device_key_deletion_proof") return "key_deletion";
  if (
    entry.signing_purpose === "document_update" ||
    entry.signing_purpose === "document_snapshot"
  ) {
    return "document_admission";
  }
  if (
    entry.signing_purpose === "editor_ephemeral" ||
    entry.signing_purpose === "editor_ephemeral_session"
  ) {
    return "editor_ephemeral";
  }
  throw new Error("semantic_validator_missing");
}

function surface(
  surfaceId: string,
  signingPurpose: string,
  transcriptOwner: string,
  variant: string,
  ownerKinds: readonly SigningOwnerKind[],
): ActiveSigningSurface {
  ACTIVE_SURFACE_OWNER_KINDS.set(inventoryKey(signingPurpose, variant), ownerKinds);

  return {
    surface_id: surfaceId,
    signing_purpose: signingPurpose,
    transcript_owner: transcriptOwner,
    owner_kind: ownerKinds[0],
    variant,
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    protocol_version: CURRENT_PROTOCOL_VERSION,
  };
}

function inventoryKey(signingPurpose: string, variant: string): string {
  return `${signingPurpose}\u0000${variant}`;
}

function validateInventory(): void {
  const keys = new Set<string>();
  const owners = new Set<string>();
  for (const entry of ACTIVE_SIGNING_SURFACES) {
    if (entry.suite_id !== SUITE_IDS.HYBRID_SIGNATURE) throw new Error("inventory_suite_mismatch");
    if (entry.protocol_version !== CURRENT_PROTOCOL_VERSION)
      throw new Error("inventory_version_mismatch");
    if (entry.variant.length === 0) throw new Error("inventory_variant_empty");
    semanticValidatorForSurface(entry);
    if (keys.has(inventoryKey(entry.signing_purpose, entry.variant))) {
      throw new Error("inventory_duplicate_surface_variant");
    }
    keys.add(inventoryKey(entry.signing_purpose, entry.variant));
    if (owners.has(entry.transcript_owner)) throw new Error("inventory_duplicate_transcript_owner");
    owners.add(entry.transcript_owner);
  }
}
