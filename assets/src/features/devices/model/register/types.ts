import type { DeviceHybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { DeviceHybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

export type DeviceRegistrationPhase =
  | "generating"
  | "approval_choice"
  | "waiting"
  | "restoring"
  | "done"
  | "error"
  | "expired"
  | "needs_password"
  | "reauth";

export interface DeviceRegistrationPublicKeys {
  deviceId: string;
  ecdhPublic: Uint8Array;
  hybridEncryptionPublicKeyMaterial: DeviceHybridEncryptionPublicKeyMaterial;
  encryptionKeyId: string;
  hybridSigningPublicKeyMaterial: DeviceHybridSigningPublicKeyMaterial;
  signingKeyId: string;
}
