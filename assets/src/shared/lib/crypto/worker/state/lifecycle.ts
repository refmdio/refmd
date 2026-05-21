import type { WorkerKeyState } from "./shared";
import { zeroOut } from "./shared";

export function createInitialState(): WorkerKeyState {
  return {
    initialized: false,
    userId: null,
    deviceId: null,
    dsk: null,
    umk: null,
    identityEcdhPrivate: null,
    identityEcdhPublic: null,
    identityHybridEncryptionPrivateKeyMaterial: null,
    identityHybridEncryptionPublicKeyMaterial: null,
    identityHybridSigningState: null,
    recoveryAuthorizationHybridSigningState: null,
    deviceEcdhPrivate: null,
    deviceEcdhPublic: null,
    deviceHybridEncryptionPrivateKeyMaterial: null,
    deviceHybridEncryptionPublicKeyMaterial: null,
    deviceHybridSigningState: null,
    shareParticipantHybridSigningState: null,
    initialAkeResponderPrekeys: new Map(),
    invitationRedeemAuthorities: new Map(),
    shareSecrets: new Map(),
    shareKeyRefs: new Map(),
    kekCache: new Map(),
    activeKekVersions: new Map(),
    dekCache: new Map(),
    activeDekVersions: new Map(),
  };
}

export function clearState(state: WorkerKeyState): void {
  state.initialized = false;
  state.userId = null;
  state.deviceId = null;
  state.dsk = null;

  zeroOut(state.umk);
  state.umk = null;

  zeroOut(state.identityEcdhPrivate);
  state.identityEcdhPrivate = null;
  state.identityEcdhPublic = null;
  state.identityHybridEncryptionPrivateKeyMaterial = null;
  state.identityHybridEncryptionPublicKeyMaterial = null;
  state.identityHybridSigningState = null;
  state.recoveryAuthorizationHybridSigningState = null;

  zeroOut(state.deviceEcdhPrivate);
  state.deviceEcdhPrivate = null;
  state.deviceEcdhPublic = null;
  state.deviceHybridEncryptionPrivateKeyMaterial = null;
  state.deviceHybridEncryptionPublicKeyMaterial = null;
  state.deviceHybridSigningState = null;
  state.shareParticipantHybridSigningState = null;
  state.initialAkeResponderPrekeys.clear();
  state.invitationRedeemAuthorities.clear();
  for (const secret of state.shareSecrets.values()) {
    zeroOut(secret.authorizationSecret ?? null);
    zeroOut(secret.passwordChallengeAuthKey ?? null);
    zeroOut(secret.dekEncryptionKey ?? null);
    zeroOut(secret.capabilitySecret ?? null);
    zeroOut(secret.passwordCapabilitySecret ?? null);
  }
  state.shareSecrets.clear();
  for (const keyRef of state.shareKeyRefs.values()) {
    zeroOut(keyRef.encryptedDek);
    zeroOut(keyRef.nonce);
  }
  state.shareKeyRefs.clear();

  for (const versionMap of state.kekCache.values()) {
    for (const entry of versionMap.values()) {
      zeroOut(entry.kek);
    }
  }
  state.kekCache.clear();
  state.activeKekVersions.clear();

  for (const versionMap of state.dekCache.values()) {
    for (const dek of versionMap.values()) {
      zeroOut(dek);
    }
  }
  state.dekCache.clear();
  state.activeDekVersions.clear();
}
