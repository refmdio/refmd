import type { components } from "@/shared/api/schema";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

export interface ShareVerificationWorkspaceDevice {
  device_id: string;
  user_id: string;
  hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
  signing_key_id: string;
  hybrid_encryption_public_key_material: HybridEncryptionPublicKeyMaterial;
  encryption_key_id: string;
  identity_hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
  identity_hybrid_encryption_public_key_material: HybridEncryptionPublicKeyMaterial;
  approval_signature: unknown;
  approval_signature_surface: string;
  approval_proof: Record<string, unknown>;
  approval_delivery_commitments?: Record<string, unknown> | null;
  approval_delivery_artifacts?: Record<string, unknown> | null;
  client_nonce: string;
  historical?: boolean;
}

export interface ShareVerificationParticipantDevice {
  share_id: string;
  share_session_id: string;
  share_token_hash?: string | null;
  share_permission?: "view" | "edit" | null;
  share_password_protected?: boolean | null;
  share_scope_kind?: "document" | "folder" | null;
  share_scope_id?: string | null;
  share_created_event_hash?: string | null;
  share_latest_bootstrap_event_hash?: string | null;
  share_capability_context_hash?: string | null;
  share_capability_secret_commitment?: string | null;
  authorization_public_key_material?: HybridSigningPublicKeyMaterial | null;
  device_id: string;
  principal_id: string;
  display_name?: string | null;
  hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
  signing_key_id: string;
  hybrid_encryption_public_key_material?: HybridEncryptionPublicKeyMaterial | null;
  encryption_key_id?: string | null;
  participant_device_kind?: "share_participant_device";
  identity_hybrid_signing_public_key_material?: HybridSigningPublicKeyMaterial | null;
  identity_hybrid_encryption_public_key_material?: HybridEncryptionPublicKeyMaterial | null;
  approval_signature?: unknown;
  approval_signature_surface?: string | null;
  approval_proof?: Record<string, unknown> | null;
  approval_delivery_commitments?: Record<string, unknown> | null;
  approval_delivery_artifacts?: Record<string, unknown> | null;
  client_nonce?: string | null;
  historical?: boolean;
}

export interface ShareVerificationDirectory {
  workspace_devices: ShareVerificationWorkspaceDevice[];
  share_participant_devices: ShareVerificationParticipantDevice[];
}

type ApiShareVerificationDirectory = components["schemas"]["ShareVerificationDirectory"];

export function normalizeShareVerificationDirectory(
  directory: unknown,
): ShareVerificationDirectory {
  const record = directory as ApiShareVerificationDirectory;
  return {
    workspace_devices: record.workspace_devices.map(
      (device) => normalizeApprovalFields(device) as unknown as ShareVerificationWorkspaceDevice,
    ),
    share_participant_devices: record.share_participant_devices.map(
      (device) => normalizeApprovalFields(device) as unknown as ShareVerificationParticipantDevice,
    ),
  };
}

function normalizeApprovalFields(device: unknown): Record<string, unknown> {
  const record = device as Record<string, unknown>;
  return record;
}
