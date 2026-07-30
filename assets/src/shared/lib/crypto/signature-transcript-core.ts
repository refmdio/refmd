import type { StrictJsonValue } from "./jcs";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";

export const SIGNATURE_TRANSCRIPT_PROTOCOL = "refmd.hybrid-signature-transcript";
export const SIGNATURE_TRANSCRIPT_LABEL = "RefMD hybrid signature transcript v1";

export type SigningOwnerKind =
  | "identity"
  | "device"
  | "recovery_authorization"
  | "share_capability"
  | "share_participant_device"
  | "invitation_redeem_authority";

export function transcriptBase(
  signingPurpose: string,
  surface: { transcript_owner: string; surface_id: string; variant: string },
  ownerKind: SigningOwnerKind,
  ownerId: string,
  payload: Record<string, unknown>,
): StrictJsonValue {
  return {
    protocol: SIGNATURE_TRANSCRIPT_PROTOCOL,
    label: SIGNATURE_TRANSCRIPT_LABEL,
    version: CURRENT_PROTOCOL_VERSION,
    transcript_owner: surface.transcript_owner,
    surface_id: surface.surface_id,
    surface_variant: surface.variant,
    signing_purpose: signingPurpose,
    owner_kind: ownerKind,
    owner_id: ownerId,
    signature_suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    signature_suite_rank: CURRENT_SUITE_RANK,
    ...payload,
  } as StrictJsonValue;
}

export function collaborationVariant(
  ownerKind: SigningOwnerKind,
): "workspace_device" | "share_participant_device" {
  if (ownerKind === "share_participant_device") return "share_participant_device";
  if (ownerKind === "device") return "workspace_device";
  throw new Error("collaboration_owner_kind_invalid");
}

export function stringValue(value: unknown, error: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(error);
  return value;
}

export function numberValue(value: unknown, error: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) throw new Error(error);
  return value;
}
