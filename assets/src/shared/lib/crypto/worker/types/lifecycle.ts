export interface PdkWrappedBlobs {
  ciphertext: string;
  nonce: string;
}

export interface InitPdkResult {
  wrappedUmk?: PdkWrappedBlobs;
  wrappedDeviceKeys?: {
    ecdh: PdkWrappedBlobs;
    signing: PdkWrappedBlobs;
  };
}

export interface InitPayload {
  dsk: CryptoKey | null;
  wrappedUmk?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  wrappedDeviceEcdh?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  wrappedDeviceSigning?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  userId: string;
  deviceId: string;
  encryptedIdentityEcdh?: Uint8Array;
  identityEcdhNonce?: Uint8Array;
  encryptedIdentitySigning?: Uint8Array;
  identitySigningNonce?: Uint8Array;
  serverEncryptedUmk?: Uint8Array;
  serverUmkNonce?: Uint8Array;
  pdkWrappedUmk?: PdkWrappedBlobs;
  pdkWrappedDeviceEcdh?: PdkWrappedBlobs;
  pdkWrappedDeviceSigning?: PdkWrappedBlobs;
  returnPdkWrapped?: boolean;
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

export interface InitFromPasswordPayload {
  password: string;
  salt: Uint8Array;
  kdfParams: {
    memory: number;
    iterations: number;
    parallelism: number;
  };
  dsk: CryptoKey | null;
  wrappedDeviceEcdh?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  wrappedDeviceSigning?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  serverEncryptedUmk?: Uint8Array;
  serverUmkNonce?: Uint8Array;
  userId: string;
  deviceId: string;
  encryptedIdentityEcdh?: Uint8Array;
  identityEcdhNonce?: Uint8Array;
  encryptedIdentitySigning?: Uint8Array;
  identitySigningNonce?: Uint8Array;
  pdkWrappedUmk?: PdkWrappedBlobs;
  pdkWrappedDeviceEcdh?: PdkWrappedBlobs;
  pdkWrappedDeviceSigning?: PdkWrappedBlobs;
  returnPdkWrapped?: boolean;
}

export interface PublicKeys {
  deviceSigningPublic: Uint8Array;
  deviceEcdhPublic: Uint8Array;
  identitySigningPublic: Uint8Array | null;
  identityEcdhPublic: Uint8Array | null;
}
