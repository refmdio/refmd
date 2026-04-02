import type { WorkerKeyState } from "./state";
import { CryptoOperationError } from "./operation-error";
import { base64UrlDecode, base64UrlEncode, randomBytes } from "../encoding";
import { buildDskDeviceEcdhAad, buildDskDeviceSigningAad, buildDskUmkCacheAad } from "../aad";
import { deriveAuthKeys } from "../kdf";
import {
  decryptIdentityPrivateKeys,
  encryptIdentityKeys,
  generateIdentityKeyPair,
} from "../identity";
import { generateUmk, wrapUmk } from "../umk";
import {
  deriveRukFromMnemonic,
  generateRecoveryKey,
  isValidMnemonic,
  unwrapUmkWithRuk,
  wrapUmkWithRuk,
} from "../recovery";
import { generateClientNonce, generateDeviceKeyPair } from "../device";
import { storeDsk } from "../dsk";
import { pdkUnwrapDeviceKeys, pdkUnwrapUmk, pdkWrapDeviceKeys, pdkWrapUmk } from "../pdk";
import {
  clearTransientPuk,
  setTransientPuk,
  setTransientRuk,
  takeTransientPuk,
  takeTransientRuk,
} from "./handler-transient";
import {
  dskDecrypt,
  dskEncrypt,
  type HandlerPayload,
  requireDsk,
  requireUmk,
  requireUserId,
  setDeviceFromPrivateKeys,
  setIdentityFromDecrypted,
} from "./handler-utils";

export function handleImportIdentityKeys(state: WorkerKeyState, p: HandlerPayload): unknown {
  const umk = requireUmk(state);
  const userId = requireUserId(state);

  const identity = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: p.encryptedEcdhPrivate as Uint8Array,
      ecdhPrivateNonce: p.ecdhPrivateNonce as Uint8Array,
      encryptedSigningPrivate: p.encryptedSigningPrivate as Uint8Array,
      signingPrivateNonce: p.signingPrivateNonce as Uint8Array,
    },
    umk,
    userId,
  );
  setIdentityFromDecrypted(state, identity);

  return {
    deviceSigningPublic: state.deviceSigningPublic,
    deviceEcdhPublic: state.deviceEcdhPublic,
    identitySigningPublic: identity.signingPublic,
    identityEcdhPublic: identity.ecdhPublic,
  };
}

export function handleImportDeviceKeys(state: WorkerKeyState, p: HandlerPayload): unknown {
  setDeviceFromPrivateKeys(state, p.ecdhPrivate as Uint8Array, p.signingPrivate as Uint8Array);
  return {
    ecdhPublic: state.deviceEcdhPublic,
    signingPublic: state.deviceSigningPublic,
  };
}

export function handleImportUmk(state: WorkerKeyState, p: HandlerPayload): unknown {
  state.umk = p.umk as Uint8Array;
  return { status: "ok" };
}

export function handleGenerateIdentityKeys(state: WorkerKeyState): unknown {
  const kp = generateIdentityKeyPair();
  setIdentityFromDecrypted(state, kp);
  return { ecdhPublic: kp.ecdhPublic, signingPublic: kp.signingPublic };
}

export function handleGenerateDeviceKeys(state: WorkerKeyState): unknown {
  const kp = generateDeviceKeyPair();
  state.deviceEcdhPrivate = kp.ecdhPrivate;
  state.deviceEcdhPublic = kp.ecdhPublic;
  state.deviceSigningPrivate = kp.signingPrivate;
  state.deviceSigningPublic = kp.signingPublic;
  return { ecdhPublic: kp.ecdhPublic, signingPublic: kp.signingPublic };
}

export function handleGenerateUmk(state: WorkerKeyState): unknown {
  state.umk = generateUmk();
  return { status: "ok" };
}

export function handleGenerateClientNonce(): Uint8Array {
  return generateClientNonce();
}

export async function handleGenerateRecoveryKey(state: WorkerKeyState): Promise<unknown> {
  const umk = requireUmk(state);
  const userId = requireUserId(state);

  const { mnemonic, ruk } = await generateRecoveryKey();
  const { encryptedUmk, nonce } = wrapUmkWithRuk(umk, ruk, userId);
  ruk.fill(0);

  return { mnemonic, encryptedUmk, nonce };
}

export async function handleDeriveAuthKeys(p: HandlerPayload): Promise<unknown> {
  const password = p.password as string;
  const salt = p.salt as Uint8Array;
  const kdfParams = p.kdfParams as { memory: number; iterations: number; parallelism: number };

  const saltBase64 = base64UrlEncode(salt);
  const derived = await deriveAuthKeys(password, saltBase64, {
    algorithm: "argon2id",
    memory: kdfParams.memory,
    iterations: kdfParams.iterations,
    parallelism: kdfParams.parallelism,
    hash_length: 32,
  });

  clearTransientPuk();
  setTransientPuk(derived.puk);
  derived.pdk.fill(0);

  return { authKey: base64UrlDecode(derived.authKeyBase64) };
}

export function handleValidateMnemonic(p: HandlerPayload): unknown {
  return { valid: isValidMnemonic(p.mnemonic as string) };
}

export async function handleDeriveRuk(p: HandlerPayload): Promise<unknown> {
  const mnemonic = p.mnemonic as string;
  const ruk = await deriveRukFromMnemonic(mnemonic);
  setTransientRuk(ruk);
  return { status: "ok" };
}

export function handleWrapUmkForServer(state: WorkerKeyState, p: HandlerPayload): unknown {
  const umk = requireUmk(state);
  const userId = p.userId as string;
  const puk = takeTransientPuk();

  if (!puk) {
    throw new CryptoOperationError("not_initialized", "PUK not available - derive auth keys first");
  }

  const { encryptedUmk, nonce } = wrapUmk(umk, puk, userId);
  puk.fill(0);
  return { encrypted: encryptedUmk, nonce };
}

export function handleWrapUmkWithRuk(state: WorkerKeyState): unknown {
  const umk = requireUmk(state);
  const userId = requireUserId(state);
  const ruk = takeTransientRuk();

  if (!ruk) {
    throw new CryptoOperationError("not_initialized", "RUK not available - derive RUK first");
  }

  const { encryptedUmk, nonce } = wrapUmkWithRuk(umk, ruk, userId);
  ruk.fill(0);
  return { encrypted: encryptedUmk, nonce };
}

export function handleUnwrapUmkWithRuk(state: WorkerKeyState, p: HandlerPayload): unknown {
  const encrypted = p.encrypted as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const userId = p.userId as string;
  const ruk = takeTransientRuk();

  if (!ruk) {
    throw new CryptoOperationError("not_initialized", "RUK not available - derive RUK first");
  }

  state.umk = unwrapUmkWithRuk(encrypted, nonce, ruk, userId);
  state.userId = userId;
  ruk.fill(0);

  return { status: "ok" };
}

export function handleWrapIdentityKeysForServer(state: WorkerKeyState, p: HandlerPayload): unknown {
  const umk = requireUmk(state);
  const userId = p.userId as string;

  if (
    !state.identityEcdhPrivate ||
    !state.identityEcdhPublic ||
    !state.identitySigningPrivate ||
    !state.identitySigningPublic
  ) {
    throw new CryptoOperationError("not_initialized", "Identity keys not available");
  }

  const encrypted = encryptIdentityKeys(
    {
      ecdhPrivate: state.identityEcdhPrivate,
      ecdhPublic: state.identityEcdhPublic,
      signingPrivate: state.identitySigningPrivate,
      signingPublic: state.identitySigningPublic,
    },
    umk,
    userId,
  );

  return {
    encryptedEcdhPrivate: encrypted.encryptedEcdhPrivate,
    ecdhPrivateNonce: encrypted.ecdhPrivateNonce,
    encryptedSigningPrivate: encrypted.encryptedSigningPrivate,
    signingPrivateNonce: encrypted.signingPrivateNonce,
  };
}

export async function handleWrapWithDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const plaintext = p.plaintext as Uint8Array;
  const aad = p.aad as Uint8Array;
  return await dskEncrypt(dsk, plaintext, aad);
}

export async function handleUnwrapWithDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = p.ciphertext as ArrayBuffer;
  const iv = p.iv as ArrayBuffer;
  const aad = p.aad as Uint8Array;
  return { plaintext: await dskDecrypt(dsk, ciphertext, iv, aad) };
}

export async function handleWrapUmkWithDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const umk = requireUmk(state);
  const userId = p.userId as string;
  return await dskEncrypt(dsk, umk, buildDskUmkCacheAad(userId));
}

export async function handleUnwrapUmkFromDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = p.ciphertext as ArrayBuffer;
  const iv = p.iv as ArrayBuffer;
  const userId = p.userId as string;
  state.umk = await dskDecrypt(dsk, ciphertext, iv, buildDskUmkCacheAad(userId));
  return { status: "ok" };
}

export async function handleWrapDeviceKeysWithDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const userId = p.userId as string;

  if (!state.deviceEcdhPrivate || !state.deviceSigningPrivate) {
    throw new CryptoOperationError("not_initialized", "Device keys not available");
  }

  const wrappedEcdh = await dskEncrypt(dsk, state.deviceEcdhPrivate, buildDskDeviceEcdhAad(userId));
  const wrappedSigning = await dskEncrypt(
    dsk,
    state.deviceSigningPrivate,
    buildDskDeviceSigningAad(userId),
  );

  return { wrappedEcdh, wrappedSigning };
}

export async function handleUnwrapDeviceKeysFromDsk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const wrappedEcdh = p.wrappedEcdh as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  const wrappedSigning = p.wrappedSigning as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  const userId = p.userId as string;

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

  return { status: "ok" };
}

export async function handleWrapWithPdk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const userId = requireUserId(state);
  const pp = p.passwordParams as {
    password: string;
    salt: Uint8Array;
    kdfParams: { memory: number; iterations: number; parallelism: number };
  };

  if (!pp) {
    throw new CryptoOperationError("internal_error", "passwordParams required for PDK wrapping");
  }

  const saltBase64 = base64UrlEncode(pp.salt);
  const derived = await deriveAuthKeys(pp.password, saltBase64, {
    algorithm: "argon2id",
    memory: pp.kdfParams.memory,
    iterations: pp.kdfParams.iterations,
    parallelism: pp.kdfParams.parallelism,
    hash_length: 32,
  });
  const pdk = derived.pdk;
  derived.puk.fill(0);

  let wrappedUmk: { ciphertext: string; nonce: string } | null = null;
  if (state.umk) {
    wrappedUmk = pdkWrapUmk(pdk, state.umk, userId);
  }
  let wrappedDeviceKeys: {
    ecdh: { ciphertext: string; nonce: string };
    signing: { ciphertext: string; nonce: string };
  } | null = null;
  if (state.deviceEcdhPrivate && state.deviceSigningPrivate) {
    wrappedDeviceKeys = pdkWrapDeviceKeys(
      pdk,
      state.deviceEcdhPrivate,
      state.deviceSigningPrivate,
      userId,
    );
  }

  pdk.fill(0);
  return { wrappedUmk, wrappedDeviceKeys };
}

export async function handleUnwrapWithPdk(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const userId = (p.userId as string) ?? requireUserId(state);
  const pp = p.passwordParams as {
    password: string;
    salt: Uint8Array;
    kdfParams: { memory: number; iterations: number; parallelism: number };
  };

  if (!pp) {
    throw new CryptoOperationError("internal_error", "passwordParams required for PDK unwrapping");
  }

  const saltBase64 = base64UrlEncode(pp.salt);
  const derived = await deriveAuthKeys(pp.password, saltBase64, {
    algorithm: "argon2id",
    memory: pp.kdfParams.memory,
    iterations: pp.kdfParams.iterations,
    parallelism: pp.kdfParams.parallelism,
    hash_length: 32,
  });
  const pdk = derived.pdk;
  derived.puk.fill(0);

  let umkRestored = false;
  let deviceKeysRestored = false;

  if (p.wrappedUmk) {
    const wrapped = p.wrappedUmk as { ciphertext: string; nonce: string };
    state.umk = pdkUnwrapUmk(pdk, wrapped, userId);
    umkRestored = true;
  }

  if (p.wrappedDeviceEcdh && p.wrappedDeviceSigning) {
    const deviceKeys = pdkUnwrapDeviceKeys(
      pdk,
      p.wrappedDeviceEcdh as { ciphertext: string; nonce: string },
      p.wrappedDeviceSigning as { ciphertext: string; nonce: string },
      userId,
    );
    setDeviceFromPrivateKeys(state, deviceKeys.ecdhPrivate, deviceKeys.signingPrivate);
    deviceKeysRestored = true;
  }

  pdk.fill(0);
  return { umkRestored, deviceKeysRestored };
}

export async function handleGenerateDskKey(state: WorkerKeyState): Promise<unknown> {
  const dsk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  state.dsk = dsk;
  await storeDsk(dsk);
  return { status: "ok" };
}

export async function handleGenerateInvitationToken(): Promise<unknown> {
  const tokenBytes = randomBytes(32);
  const tokenBase64 = base64UrlEncode(tokenBytes);
  const hashBuffer = await crypto.subtle.digest("SHA-256", tokenBytes.buffer as ArrayBuffer);
  const tokenHash = base64UrlEncode(new Uint8Array(hashBuffer));
  const tokenPrefix = tokenBase64.slice(0, 4);
  return { token: tokenBase64, tokenHash, tokenPrefix };
}

export async function handleSha256Hash(p: HandlerPayload): Promise<unknown> {
  const data = p.data as Uint8Array;
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return { hash: base64UrlEncode(new Uint8Array(hashBuffer)) };
}
