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
    identitySigningPrivate: null,
    identitySigningPublic: null,
    deviceEcdhPrivate: null,
    deviceEcdhPublic: null,
    deviceSigningPrivate: null,
    deviceSigningPublic: null,
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
  zeroOut(state.identitySigningPrivate);
  state.identitySigningPrivate = null;
  state.identitySigningPublic = null;

  zeroOut(state.deviceEcdhPrivate);
  state.deviceEcdhPrivate = null;
  state.deviceEcdhPublic = null;
  zeroOut(state.deviceSigningPrivate);
  state.deviceSigningPrivate = null;
  state.deviceSigningPublic = null;

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
