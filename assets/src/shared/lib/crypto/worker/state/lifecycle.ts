import type { WorkerKeyState } from "./shared";
import { zeroOut } from "./shared";
import { destroyHybridEncryptionPrivateKeyMaterial } from "../../hybrid-encryption";
import { destroyHybridSigningPrivateKeyMaterial } from "../../signature";

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
    pendingIdentitySuccessor: null,
    identityRotationDueAtMs: null,
    identityRotationActivation: null,
    identityRotationFinalization: null,
    identityRotationTrustedCheckpointPayload: null,
    recoveryAuthorizationHybridSigningState: null,
    deviceEcdhPrivate: null,
    deviceEcdhPublic: null,
    deviceHybridEncryptionPrivateKeyMaterial: null,
    deviceHybridEncryptionPublicKeyMaterial: null,
    deviceHybridSigningState: null,
    shareParticipantHybridSigningState: null,
    initialAkeResponderPrekeys: new Map(),
    initialAkeInitiatorSessions: new Map(),
    initialAkeResponderSessions: new Map(),
    invitationRedeemAuthorities: new Map(),
    shareSecrets: new Map(),
    shareKeyRefs: new Map(),
    guestShareKeys: new Map(),
    pendingGuestInvitationShareKeys: new Map(),
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
  if (state.identityHybridEncryptionPrivateKeyMaterial) {
    destroyHybridEncryptionPrivateKeyMaterial(state.identityHybridEncryptionPrivateKeyMaterial);
  }
  state.identityHybridEncryptionPrivateKeyMaterial = null;
  state.identityHybridEncryptionPublicKeyMaterial = null;
  if (state.identityHybridSigningState) {
    destroyHybridSigningPrivateKeyMaterial(state.identityHybridSigningState.privateKeyMaterial);
  }
  state.identityHybridSigningState = null;
  if (state.pendingIdentitySuccessor) {
    zeroOut(state.pendingIdentitySuccessor.ecdhPrivate);
    destroyHybridEncryptionPrivateKeyMaterial(
      state.pendingIdentitySuccessor.hybridEncryptionPrivateKeyMaterial,
    );
    destroyHybridSigningPrivateKeyMaterial(
      state.pendingIdentitySuccessor.hybridSigningPrivateKeyMaterial,
    );
  }
  state.pendingIdentitySuccessor = null;
  state.identityRotationDueAtMs = null;
  state.identityRotationActivation = null;
  state.identityRotationFinalization = null;
  state.identityRotationTrustedCheckpointPayload = null;
  state.recoveryAuthorizationHybridSigningState = null;

  zeroOut(state.deviceEcdhPrivate);
  state.deviceEcdhPrivate = null;
  state.deviceEcdhPublic = null;
  state.deviceHybridEncryptionPrivateKeyMaterial = null;
  state.deviceHybridEncryptionPublicKeyMaterial = null;
  state.deviceHybridSigningState = null;
  state.shareParticipantHybridSigningState = null;
  for (const prekey of state.initialAkeResponderPrekeys.values()) {
    zeroOut(prekey.x25519_private);
    zeroOut(prekey.mlkem768_private);
  }
  state.initialAkeResponderPrekeys.clear();
  for (const session of state.initialAkeInitiatorSessions.values()) zeroOut(session.secret);
  state.initialAkeInitiatorSessions.clear();
  for (const session of state.initialAkeResponderSessions.values()) zeroOut(session.secret);
  state.initialAkeResponderSessions.clear();
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
  for (const guestShareKey of state.guestShareKeys.values()) {
    zeroOut(guestShareKey.key);
  }
  state.guestShareKeys.clear();
  for (const key of state.pendingGuestInvitationShareKeys.values()) key.fill(0);
  state.pendingGuestInvitationShareKeys.clear();

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
