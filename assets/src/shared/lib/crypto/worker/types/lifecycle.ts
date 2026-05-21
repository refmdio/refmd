import type { HybridSigningPublicKeyMaterial } from "../../signature";
import type { HybridEncryptionPublicKeyMaterial } from "../../hybrid-encryption";

interface DskWrappedBlob {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}

interface DskDeviceSigningKeys {
  wrappedDeviceEcdh: DskWrappedBlob;
  wrappedDeviceMlkem: DskWrappedBlob;
  wrappedDeviceSigning: DskWrappedBlob & { signingKeyId: string };
  deviceSigningKeyId: string;
}

interface NoDskDeviceSigningKeys {
  wrappedDeviceEcdh?: never;
  wrappedDeviceMlkem?: never;
  wrappedDeviceSigning?: never;
  deviceSigningKeyId?: string;
}

type DskDeviceKeyRestore = DskDeviceSigningKeys | NoDskDeviceSigningKeys;

interface InitPayloadBase {
  dsk: CryptoKey | null;
  wrappedUmk?: DskWrappedBlob;
  userId: string;
  deviceId: string;
  encryptedIdentityHybridEncryptionPrivateKeyMaterial?: Uint8Array;
  identityHybridEncryptionPrivateKeyMaterialNonce?: Uint8Array;
  identityEncryptionKeyId?: string;
  encryptedIdentityHybridSigningPrivateKeyMaterial?: Uint8Array;
  identityHybridSigningPrivateKeyMaterialNonce?: Uint8Array;
  identitySigningKeyId?: string;
  serverEncryptedUmk?: Uint8Array;
  serverUmkNonce?: Uint8Array;
  keyRestoreEndpointRef?: string | null;
  useStoredDsk?: boolean;
  passwordParams?: {
    password: string;
    salt: Uint8Array;
    kdfParams: {
      memory: number;
      iterations: number;
      parallelism: number;
    };
  };
}

export type InitPayload = InitPayloadBase & DskDeviceKeyRestore;

interface InitFromPasswordPayloadBase {
  password: string;
  salt: Uint8Array;
  kdfParams: {
    memory: number;
    iterations: number;
    parallelism: number;
  };
  dsk: CryptoKey | null;
  serverEncryptedUmk?: Uint8Array;
  serverUmkNonce?: Uint8Array;
  userId: string;
  deviceId: string;
  encryptedIdentityHybridEncryptionPrivateKeyMaterial?: Uint8Array;
  identityHybridEncryptionPrivateKeyMaterialNonce?: Uint8Array;
  identityEncryptionKeyId?: string;
  encryptedIdentityHybridSigningPrivateKeyMaterial?: Uint8Array;
  identityHybridSigningPrivateKeyMaterialNonce?: Uint8Array;
  identitySigningKeyId?: string;
  keyRestoreEndpointRef?: string | null;
  useStoredDsk?: boolean;
}

export type InitFromPasswordPayload = InitFromPasswordPayloadBase & DskDeviceKeyRestore;

export interface PublicKeys {
  deviceEcdhPublic: Uint8Array | null;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial | null;
  deviceEncryptionKeyId: string | null;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
  deviceSigningKeyId: string | null;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
  identityEcdhPublic: Uint8Array | null;
  identityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial | null;
  identityEncryptionKeyId: string | null;
}
