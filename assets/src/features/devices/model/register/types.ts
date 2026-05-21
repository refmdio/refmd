import type { DeviceHybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { DeviceHybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import type { InitialAkeResponderPrekeyRecord } from "@/shared/lib/crypto/initial-ake";

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
  initialAkeResponderPrekeys?: {
    umk_distribution: InitialAkeResponderPrekeyRecord;
    trust_transfer: InitialAkeResponderPrekeyRecord;
    device_approval_kek_initial: Array<{
      workspace_id: string;
      prekey: InitialAkeResponderPrekeyRecord;
    }>;
  };
}
