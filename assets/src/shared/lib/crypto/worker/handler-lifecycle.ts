import type { InitPdkResult, PdkWrappedBlobs } from "./types";
import type { WorkerKeyState } from "./state";
import { clearState } from "./state";
import { base64UrlDecode, base64UrlEncode } from "../encoding";
import { buildDskDeviceEcdhAad, buildDskDeviceSigningAad, buildDskUmkCacheAad } from "../aad";
import { deriveAuthKeys } from "../kdf";
import { decryptIdentityPrivateKeys } from "../identity";
import { unwrapUmk } from "../umk";
import { pdkUnwrapDeviceKeys, pdkUnwrapUmk, pdkWrapDeviceKeys, pdkWrapUmk } from "../pdk";
import { clearTransientKeys, clearTransientPuk, cloneTransientPuk } from "./handler-transient";
import {
  dskDecrypt,
  type HandlerPayload,
  requireDeviceId,
  setDeviceFromPrivateKeys,
  setIdentityFromDecrypted,
} from "./handler-utils";
type DskWrappedBlob = {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
};
async function restoreKeysFromBlobs(
  state: WorkerKeyState,
  p: HandlerPayload,
  params: {
    dsk: CryptoKey | null;
    userId: string;
    localPdk: Uint8Array | null;
    localPuk: Uint8Array | null;
  },
): Promise<InitPdkResult | null> {
  const { dsk, userId, localPdk, localPuk } = params;
  if (dsk) {
    state.dsk = dsk;
    if (p.wrappedDeviceEcdh && p.wrappedDeviceSigning) {
      try {
        const wrappedEcdh = p.wrappedDeviceEcdh as DskWrappedBlob;
        const wrappedSigning = p.wrappedDeviceSigning as DskWrappedBlob;
        const ecdhPrivate = await dskDecrypt(
          dsk,
          wrappedEcdh.ciphertext,
          wrappedEcdh.iv,
          buildDskDeviceEcdhAad(userId),
        );
        const signingPrivate = await dskDecrypt(
          dsk,
          wrappedSigning.ciphertext,
          wrappedSigning.iv,
          buildDskDeviceSigningAad(userId),
        );
        setDeviceFromPrivateKeys(state, ecdhPrivate, signingPrivate);
      } catch {
        // Stale or cross-account DSK data; skip device key restoration
      }
    }
    if (p.wrappedUmk) {
      try {
        const wrappedUmk = p.wrappedUmk as DskWrappedBlob;
        state.umk = await dskDecrypt(
          dsk,
          wrappedUmk.ciphertext,
          wrappedUmk.iv,
          buildDskUmkCacheAad(userId),
        );
      } catch {
        // Stale DSK data; fall through to PDK/PUK fallback
      }
    }
  }
  if (
    !state.deviceSigningPrivate &&
    localPdk &&
    p.pdkWrappedDeviceEcdh &&
    p.pdkWrappedDeviceSigning
  ) {
    try {
      const deviceKeys = pdkUnwrapDeviceKeys(
        localPdk,
        p.pdkWrappedDeviceEcdh as PdkWrappedBlobs,
        p.pdkWrappedDeviceSigning as PdkWrappedBlobs,
        userId,
      );
      setDeviceFromPrivateKeys(state, deviceKeys.ecdhPrivate, deviceKeys.signingPrivate);
    } catch {
      // PDK unwrap failed
    }
  }
  if (!state.umk && localPdk && p.pdkWrappedUmk) {
    try {
      state.umk = pdkUnwrapUmk(localPdk, p.pdkWrappedUmk as PdkWrappedBlobs, userId);
    } catch {
      // PDK unwrap failed
    }
  }
  if (!state.umk && p.serverEncryptedUmk && p.serverUmkNonce && localPuk) {
    state.umk = unwrapUmk(
      p.serverEncryptedUmk as Uint8Array,
      p.serverUmkNonce as Uint8Array,
      localPuk,
      userId,
    );
  }
  if (
    state.umk &&
    p.encryptedIdentityEcdh &&
    p.identityEcdhNonce &&
    p.encryptedIdentitySigning &&
    p.identitySigningNonce
  ) {
    setIdentityFromDecrypted(
      state,
      decryptIdentityPrivateKeys(
        {
          encryptedEcdhPrivate: p.encryptedIdentityEcdh as Uint8Array,
          ecdhPrivateNonce: p.identityEcdhNonce as Uint8Array,
          encryptedSigningPrivate: p.encryptedIdentitySigning as Uint8Array,
          signingPrivateNonce: p.identitySigningNonce as Uint8Array,
        },
        state.umk,
        userId,
      ),
    );
  }
  let pdkWrapped: InitPdkResult | null = null;
  if (p.returnPdkWrapped && localPdk && state.umk) {
    pdkWrapped = { wrappedUmk: pdkWrapUmk(localPdk, state.umk, userId) };
    if (state.deviceEcdhPrivate && state.deviceSigningPrivate) {
      pdkWrapped.wrappedDeviceKeys = pdkWrapDeviceKeys(
        localPdk,
        state.deviceEcdhPrivate,
        state.deviceSigningPrivate,
        userId,
      );
    }
  }
  const identityKeysRequested = Boolean(
    p.encryptedIdentityEcdh &&
    p.identityEcdhNonce &&
    p.encryptedIdentitySigning &&
    p.identitySigningNonce,
  );
  const identityRestored = state.identitySigningPrivate !== null;
  state.initialized =
    state.deviceSigningPrivate !== null &&
    state.umk !== null &&
    (!identityKeysRequested || identityRestored);
  return pdkWrapped;
}
export async function handleInit(state: WorkerKeyState, p: HandlerPayload): Promise<unknown> {
  let localPuk = cloneTransientPuk();
  clearState(state);
  clearTransientPuk();
  const dsk = p.dsk as CryptoKey | null;
  const userId = p.userId as string;
  const deviceId = p.deviceId as string;
  let localPdk: Uint8Array | null = null;
  if (p.passwordParams) {
    const pp = p.passwordParams as {
      password: string;
      salt: Uint8Array;
      kdfParams: {
        memory: number;
        iterations: number;
        parallelism: number;
      };
    };
    const saltBase64 = base64UrlEncode(pp.salt);
    const derived = await deriveAuthKeys(pp.password, saltBase64, {
      algorithm: "argon2id",
      memory: pp.kdfParams.memory,
      iterations: pp.kdfParams.iterations,
      parallelism: pp.kdfParams.parallelism,
      hash_length: 32,
    });
    localPdk = derived.pdk;
    derived.puk.fill(0);
  }
  state.userId = userId;
  state.deviceId = deviceId;
  try {
    const pdkWrapped = await restoreKeysFromBlobs(state, p, {
      dsk,
      userId,
      localPdk,
      localPuk,
    });
    return { status: state.initialized ? "initialized" : "partial", pdkWrapped };
  } finally {
    if (localPdk) {
      localPdk.fill(0);
      localPdk = null;
    }
    if (localPuk) {
      localPuk.fill(0);
      localPuk = null;
    }
  }
}
export async function handleInitFromPassword(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  clearState(state);
  clearTransientPuk();
  const password = p.password as string;
  const salt = p.salt as Uint8Array;
  const kdfParams = p.kdfParams as {
    memory: number;
    iterations: number;
    parallelism: number;
  };
  const userId = p.userId as string;
  const deviceId = p.deviceId as string;
  const dsk = p.dsk as CryptoKey | null;
  const saltBase64 = base64UrlEncode(salt);
  const derived = await deriveAuthKeys(password, saltBase64, {
    algorithm: "argon2id",
    memory: kdfParams.memory,
    iterations: kdfParams.iterations,
    parallelism: kdfParams.parallelism,
    hash_length: 32,
  });
  state.userId = userId;
  state.deviceId = deviceId;
  let localPdk: Uint8Array | null = derived.pdk;
  let localPuk: Uint8Array | null = derived.puk;
  try {
    const pdkWrapped = await restoreKeysFromBlobs(state, p, {
      dsk,
      userId,
      localPdk,
      localPuk,
    });
    return { authKey: base64UrlDecode(derived.authKeyBase64), pdkWrapped };
  } finally {
    if (localPdk) {
      localPdk.fill(0);
      localPdk = null;
    }
    if (localPuk) {
      localPuk.fill(0);
      localPuk = null;
    }
  }
}
export function handleLock(state: WorkerKeyState): unknown {
  clearState(state);
  clearTransientKeys();
  return { status: "locked" };
}
export function handleGetPublicKeys(state: WorkerKeyState): unknown {
  return {
    deviceSigningPublic: state.deviceSigningPublic,
    deviceEcdhPublic: state.deviceEcdhPublic,
    identitySigningPublic: state.identitySigningPublic,
    identityEcdhPublic: state.identityEcdhPublic,
  };
}
export function handleGetDeviceId(state: WorkerKeyState): unknown {
  return { deviceId: requireDeviceId(state) };
}
export function handleIsReady(state: WorkerKeyState): unknown {
  return { ready: state.initialized };
}
export function handleSetUserContext(state: WorkerKeyState, p: HandlerPayload): unknown {
  state.userId = p.userId as string;
  state.deviceId = (p.deviceId as string) ?? state.deviceId;
  return { status: "ok" };
}
export function handleSetDsk(state: WorkerKeyState, p: HandlerPayload): unknown {
  state.dsk = p.dsk as CryptoKey;
  return { status: "ok" };
}
export function handleSetInitialized(state: WorkerKeyState): unknown {
  state.initialized = true;
  return { status: "ok" };
}
export function handleClearTransientKeys(): unknown {
  clearTransientKeys();
  return { status: "ok" };
}
