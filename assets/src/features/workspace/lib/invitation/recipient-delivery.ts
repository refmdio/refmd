import type { components } from "@/shared/api";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import { invitationTokenWithFragmentSecrets } from "./token";

type RecipientResponse = components["schemas"]["InvitationRecipientResponse"];

export interface NormalizedInvitationRecipient {
  delivery_mode: "unknown_fragment" | "known_recipient";
  recipient_user_id: string | null;
  devices: Array<{
    device_id: string;
    encryption_key_id: string;
    hybrid_encryption_public_key_material: HybridEncryptionPublicKeyMaterial;
    key_checkpoint_sequence: number;
    key_checkpoint_hash: string;
  }>;
}

export function normalizeInvitationRecipient(
  response: RecipientResponse,
): NormalizedInvitationRecipient {
  if (response.delivery_mode === "unknown_fragment") {
    if (
      response.recipient_user_id !== null ||
      !Array.isArray(response.devices) ||
      response.devices.length !== 0
    ) {
      throw new Error("invitation_recipient_response_invalid");
    }
    return { delivery_mode: "unknown_fragment", recipient_user_id: null, devices: [] };
  }
  const devices = response.devices;
  if (
    response.delivery_mode !== "known_recipient" ||
    !response.recipient_user_id ||
    devices.length === 0 ||
    new Set(devices.map((device) => device.device_id)).size !== devices.length
  ) {
    throw new Error("invitation_recipient_response_invalid");
  }
  return {
    delivery_mode: "known_recipient",
    recipient_user_id: response.recipient_user_id,
    devices: devices.map((device) => ({
      device_id: device.device_id,
      encryption_key_id: device.encryption_key_id,
      hybrid_encryption_public_key_material:
        device.hybrid_encryption_public_key_material as HybridEncryptionPublicKeyMaterial,
      key_checkpoint_sequence: device.key_checkpoint_sequence,
      key_checkpoint_hash: device.key_checkpoint_hash,
    })),
  };
}

export function invitationRecipientDeviceIds(recipient: NormalizedInvitationRecipient): string[] {
  return recipient.devices.map((device) => device.device_id);
}

export function invitationRecipientAadUserId(recipient: NormalizedInvitationRecipient): string {
  return recipient.recipient_user_id ?? "NOT_APPLICABLE";
}

export function invitationRecipientDelivery(recipient: NormalizedInvitationRecipient) {
  if (recipient.delivery_mode === "unknown_fragment") return undefined;
  return {
    recipientUserId: recipient.recipient_user_id!,
  };
}

export function invitationRecipientToken(
  recipient: NormalizedInvitationRecipient,
  lookupToken: string,
  bootstrapSecret: string,
): string {
  return recipient.delivery_mode === "known_recipient"
    ? lookupToken
    : invitationTokenWithFragmentSecrets(lookupToken, bootstrapSecret);
}
