import type {
  HybridSigningPrivateKeyMaterial,
  HybridSigningPublicKeyMaterial,
} from "../../signature";
import type {
  HybridEncryptionPrivateKeyMaterial,
  HybridEncryptionPublicKeyMaterial,
} from "../../hybrid-encryption";
import type { InitialAkeResponderPrekeyPrivate } from "../../initial-ake";

export interface HybridSigningState {
  privateKeyMaterial: HybridSigningPrivateKeyMaterial;
  publicKeyMaterial: HybridSigningPublicKeyMaterial;
  signingKeyId: string;
}

export interface WorkerKeyState {
  initialized: boolean;
  userId: string | null;
  deviceId: string | null;
  dsk: CryptoKey | null;
  umk: Uint8Array | null;
  identityEcdhPrivate: Uint8Array | null;
  identityEcdhPublic: Uint8Array | null;
  identityHybridEncryptionPrivateKeyMaterial: HybridEncryptionPrivateKeyMaterial | null;
  identityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial | null;
  identityHybridSigningState: HybridSigningState | null;
  recoveryAuthorizationHybridSigningState: HybridSigningState | null;
  deviceEcdhPrivate: Uint8Array | null;
  deviceEcdhPublic: Uint8Array | null;
  deviceHybridEncryptionPrivateKeyMaterial: HybridEncryptionPrivateKeyMaterial | null;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial | null;
  deviceHybridSigningState: HybridSigningState | null;
  shareParticipantHybridSigningState: HybridSigningState | null;
  initialAkeResponderPrekeys: Map<string, InitialAkeResponderPrekeyPrivate>;
  invitationRedeemAuthorities: Map<string, HybridSigningPrivateKeyMaterial>;
  shareSecrets: Map<
    string,
    {
      authorizationSecret?: Uint8Array;
      passwordChallengeAuthKey?: Uint8Array;
      dekEncryptionKey?: Uint8Array;
      capabilitySecret?: Uint8Array;
      passwordCapabilitySecret?: Uint8Array;
    }
  >;
  shareKeyRefs: Map<
    string,
    {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
      shareId: string;
      documentId: string;
      keyVersion: number;
    }
  >;
  kekCache: Map<string, Map<number, { kek: Uint8Array; resolvedAt: number }>>;
  activeKekVersions: Map<string, number>;
  dekCache: Map<string, Map<number, Uint8Array>>;
  activeDekVersions: Map<string, number>;
}

export function zeroOut(value: Uint8Array | null): void {
  if (value) {
    value.fill(0);
  }
}
