import type { StrictJsonValue } from "./jcs";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
import type { SigningOwnerKind } from "./signature-transcript-core";

export type PersistentSigningOwnerKind = Exclude<SigningOwnerKind, "share_capability">;

export interface HybridSigningPublicKeyMaterial {
  protocol: "refmd.hybrid-signing-key-material";
  version: typeof CURRENT_PROTOCOL_VERSION;
  owner_kind: PersistentSigningOwnerKind;
  owner_id: string;
  ed25519_public: string;
  mldsa65_public: string;
  suite_id: typeof SUITE_IDS.HYBRID_SIGNATURE;
  suite_rank: typeof CURRENT_SUITE_RANK;
}

export type IdentityHybridSigningPublicKeyMaterial = HybridSigningPublicKeyMaterial & {
  owner_kind: "identity";
};

export type DeviceHybridSigningPublicKeyMaterial = HybridSigningPublicKeyMaterial & {
  owner_kind: "device";
};

export type RecoveryAuthorizationHybridSigningPublicKeyMaterial = HybridSigningPublicKeyMaterial & {
  owner_kind: "recovery_authorization";
};

export interface ShareCapabilitySigningPublicKeyMaterial {
  protocol: "refmd.hybrid-signing-key-material";
  version: typeof CURRENT_PROTOCOL_VERSION;
  owner_kind: "share_capability";
  owner_id: string;
  ed25519_public: string;
  mldsa65_public: string;
  suite_id: typeof SUITE_IDS.HYBRID_SIGNATURE;
  suite_rank: typeof CURRENT_SUITE_RANK;
}

export type AnyHybridSigningPublicKeyMaterial =
  | HybridSigningPublicKeyMaterial
  | ShareCapabilitySigningPublicKeyMaterial;

export interface HybridSigningPrivateKeyMaterial {
  protocol: "refmd.hybrid-signing-private-key-material";
  version: typeof CURRENT_PROTOCOL_VERSION;
  owner_kind: SigningOwnerKind;
  owner_id: string;
  ed25519_private: string;
  ed25519_public: string;
  mldsa65_private: string;
  mldsa65_public: string;
  suite_id: typeof SUITE_IDS.HYBRID_SIGNATURE;
  suite_rank: typeof CURRENT_SUITE_RANK;
}

export interface HybridSignature {
  protocol: "refmd.hybrid-signature";
  version: typeof CURRENT_PROTOCOL_VERSION;
  suite_id: typeof SUITE_IDS.HYBRID_SIGNATURE;
  suite_rank: typeof CURRENT_SUITE_RANK;
  signing_key_id: string;
  transcript_hash: string;
  ed25519: string;
  mldsa65: string;
}

export interface SignHybridSignatureParams {
  signingPurpose: string;
  transcript: StrictJsonValue;
  privateKeyMaterial: HybridSigningPrivateKeyMaterial;
}

export interface VerifyHybridSignatureParams {
  signingPurpose: string;
  transcript: StrictJsonValue;
  signature: HybridSignature;
  publicKeyMaterial: AnyHybridSigningPublicKeyMaterial;
}
