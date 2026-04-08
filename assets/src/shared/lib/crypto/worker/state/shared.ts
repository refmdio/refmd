export interface WorkerKeyState {
  initialized: boolean;
  userId: string | null;
  deviceId: string | null;
  dsk: CryptoKey | null;
  umk: Uint8Array | null;
  identityEcdhPrivate: Uint8Array | null;
  identityEcdhPublic: Uint8Array | null;
  identitySigningPrivate: Uint8Array | null;
  identitySigningPublic: Uint8Array | null;
  deviceEcdhPrivate: Uint8Array | null;
  deviceEcdhPublic: Uint8Array | null;
  deviceSigningPrivate: Uint8Array | null;
  deviceSigningPublic: Uint8Array | null;
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
