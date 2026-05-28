import type { DeviceHybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { DeviceHybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import type { RegistrationInitialAkeResponderPrekeys } from "@/shared/lib/auth/registration-initial-ake-prekeys";

export type DeviceRegistrationPhase =
  | "generating"
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
  initialAkeResponderPrekeys?: RegistrationInitialAkeResponderPrekeys;
}
