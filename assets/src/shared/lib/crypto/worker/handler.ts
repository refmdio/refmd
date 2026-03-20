import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";

import type { CryptoRequest, TitleDecryptItem, TitleDecryptResult } from "./types";
import type { WorkerKeyState } from "./state";
import { getCachedKek, setCachedKek, getCachedDek, setCachedDek, clearState } from "./state";

import { base64UrlEncode, base64UrlDecode, randomBytes } from "../encoding";
import {
  buildDskUmkCacheAad,
  buildDskDeviceEcdhAad,
  buildDskDeviceSigningAad,
  buildDocumentContentAad,
  buildDeviceUmkDistributionAad,
  canonicalizeBytes,
} from "../aad";
import { generateDek, wrapDek, unwrapDek, encryptTitle, decryptTitle } from "../dek";
import {
  generateKek,
  encryptKekForDevice,
  decryptKekFromDeviceEnvelope,
  encryptKekForMember,
  decryptKekFromMemberEnvelope,
  wrapKekWithUmk,
  unwrapKekFromBackup,
  encryptKekForInvitation,
  decryptKekFromInvitation,
} from "../kek";
import {
  generateIdentityKeyPair,
  encryptIdentityKeys,
  decryptIdentityPrivateKeys,
  sign,
  verify,
} from "../identity";
import { generateUmk, wrapUmk, unwrapUmk } from "../umk";
import { deriveAuthKeys } from "../kdf";
import {
  generateRecoveryKey,
  deriveRukFromMnemonic,
  wrapUmkWithRuk,
  unwrapUmkWithRuk,
  isValidMnemonic,
} from "../recovery";
import {
  generateDeviceKeyPair,
  generateClientNonce,
  signDeviceApproval,
  signDeviceRegistration,
  verifyDeviceIdentitySignature,
} from "../device";
import { ecdhEncrypt, ecdhDecrypt } from "../ecdh-cipher";
import { buildSignatureMessage, SIGNATURE_ACTION } from "../signature";
import { calculateFingerprint, formatFingerprint } from "../fingerprint";
import { computeSas } from "../sas";
import {
  verifyTofu,
  trustDevice,
  updateDeviceLastSeen,
  handleTofuResult,
  verifyAllDeviceTofu,
} from "../tofu";
import { getAllTofuEntries, importTofuEntries } from "../../trust-store";
import { storeDsk } from "../dsk";
import { encryptTrustState, decryptTrustState } from "../trust-transfer";
import type { TrustTransferAadParams } from "../trust-transfer";
import { pdkWrapUmk, pdkUnwrapUmk, pdkWrapDeviceKeys, pdkUnwrapDeviceKeys } from "../pdk";

// ── Transient key storage ────────────────────────────────────
// Keys that are ephemeral across multi-step flows (e.g. PUK from
// password derivation used for UMK wrap, RUK from mnemonic derivation
// used for UMK unwrap). Stored at module level because WorkerKeyState
// intentionally omits them (they are not session-persistent keys).

let transientPuk: Uint8Array | null = null;
let transientRuk: Uint8Array | null = null;

// ── Helpers ──────────────────────────────────────────────────

function requireUmk(state: WorkerKeyState): Uint8Array {
  if (!state.umk) throw new Error("UMK not available");
  return state.umk;
}

function requireDeviceEcdhPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.deviceEcdhPrivate) throw new Error("Device ECDH private key not available");
  return state.deviceEcdhPrivate;
}

function requireDeviceSigningPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.deviceSigningPrivate) throw new Error("Device signing private key not available");
  return state.deviceSigningPrivate;
}

function requireIdentitySigningPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.identitySigningPrivate) throw new Error("Identity signing private key not available");
  return state.identitySigningPrivate;
}

function requireIdentityEcdhPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.identityEcdhPrivate) throw new Error("Identity ECDH private key not available");
  return state.identityEcdhPrivate;
}

function requireDsk(state: WorkerKeyState): CryptoKey {
  if (!state.dsk) throw new Error("DSK not available");
  return state.dsk;
}

function requireUserId(state: WorkerKeyState): string {
  if (!state.userId) throw new Error("userId not available");
  return state.userId;
}

function requireDeviceId(state: WorkerKeyState): string {
  if (!state.deviceId) throw new Error("deviceId not available");
  return state.deviceId;
}

function requireKekForWorkspace(
  state: WorkerKeyState,
  workspaceId: string,
): { kek: Uint8Array; keyVersion: number } {
  const cached = getCachedKek(state, workspaceId);
  if (!cached) throw new Error(`KEK not cached for workspace ${workspaceId}`);
  return cached;
}

function requireDekForDocument(
  state: WorkerKeyState,
  documentId: string,
): { dek: Uint8Array; keyVersion: number } {
  const cached = getCachedDek(state, documentId);
  if (!cached) throw new Error(`DEK not cached for document ${documentId}`);
  return cached;
}

async function dskEncrypt(
  dsk: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new Uint8Array(aad).buffer },
    dsk,
    new Uint8Array(plaintext),
  );
  return { ciphertext, iv: iv.buffer };
}

async function dskDecrypt(
  dsk: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: ArrayBuffer,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: new Uint8Array(aad).buffer },
    dsk,
    ciphertext,
  );
  return new Uint8Array(plaintext);
}

function setIdentityFromDecrypted(
  state: WorkerKeyState,
  identity: {
    ecdhPrivate: Uint8Array;
    ecdhPublic: Uint8Array;
    signingPrivate: Uint8Array;
    signingPublic: Uint8Array;
  },
): void {
  state.identityEcdhPrivate = identity.ecdhPrivate;
  state.identityEcdhPublic = identity.ecdhPublic;
  state.identitySigningPrivate = identity.signingPrivate;
  state.identitySigningPublic = identity.signingPublic;
}

function setDeviceFromPrivateKeys(
  state: WorkerKeyState,
  ecdhPrivate: Uint8Array,
  signingPrivate: Uint8Array,
): void {
  state.deviceEcdhPrivate = ecdhPrivate;
  state.deviceEcdhPublic = x25519.getPublicKey(ecdhPrivate);
  state.deviceSigningPrivate = signingPrivate;
  state.deviceSigningPublic = ed25519.getPublicKey(signingPrivate);
}

// ── Main handler ─────────────────────────────────────────────

export async function handleRequest(
  state: WorkerKeyState,
  request: CryptoRequest,
): Promise<unknown> {
  const p = request.payload;

  switch (request.type) {
    // Lifecycle
    case "init":
      return handleInit(state, p);
    case "init-from-password":
      return handleInitFromPassword(state, p);
    case "lock":
      return handleLock(state);
    case "get-public-keys":
      return handleGetPublicKeys(state);
    case "get-device-id":
      return handleGetDeviceId(state);
    case "is-ready":
      return { ready: state.initialized };
    case "set-user-context": {
      state.userId = p.userId as string;
      state.deviceId = (p.deviceId as string) ?? state.deviceId;
      return { status: "ok" };
    }
    case "set-dsk": {
      state.dsk = p.dsk as CryptoKey;
      return { status: "ok" };
    }
    case "set-initialized": {
      state.initialized = true;
      return { status: "ok" };
    }
    case "clear-transient-keys": {
      if (transientPuk) {
        transientPuk.fill(0);
        transientPuk = null;
      }
      if (transientRuk) {
        transientRuk.fill(0);
        transientRuk = null;
      }
      return { status: "ok" };
    }

    // Key import
    case "import-identity-keys":
      return handleImportIdentityKeys(state, p);
    case "import-device-keys":
      return handleImportDeviceKeys(state, p);
    case "import-umk":
      return handleImportUmk(state, p);

    // Key generation
    case "generate-identity-keys":
      return handleGenerateIdentityKeys(state);
    case "generate-device-keys":
      return handleGenerateDeviceKeys(state);
    case "generate-umk":
      return handleGenerateUmk(state);
    case "generate-kek":
      return handleGenerateKek(state, p);
    case "generate-dek":
      return handleGenerateDek(state, p);
    case "generate-client-nonce":
      return generateClientNonce();
    case "generate-recovery-key":
      return handleGenerateRecoveryKey(state);

    // Password derivation
    case "derive-auth-keys":
      return handleDeriveAuthKeys(p);
    case "validate-mnemonic":
      return { valid: isValidMnemonic(p.mnemonic as string) };
    case "derive-ruk":
      return handleDeriveRuk(p);

    // UMK wrapping
    case "wrap-umk-for-server":
      return handleWrapUmkForServer(state, p);
    case "wrap-umk-with-ruk":
      return handleWrapUmkWithRuk(state);
    case "unwrap-umk-with-ruk":
      return handleUnwrapUmkWithRuk(state, p);

    // Identity key wrapping
    case "wrap-identity-keys-for-server":
      return handleWrapIdentityKeysForServer(state, p);

    // DEK operations
    case "wrap-dek":
      return handleWrapDek(state, p);
    case "unwrap-dek":
      return handleUnwrapDek(state, p);
    case "encrypt-title":
      return handleEncryptTitle(state, p);
    case "decrypt-title":
      return handleDecryptTitle(state, p);
    case "decrypt-title-batch":
      return handleDecryptTitleBatch(state, p);
    case "encrypt-content":
      return handleEncryptContent(state, p);
    case "decrypt-content":
      return handleDecryptContent(state, p);
    case "encrypt-snapshot":
      return handleEncryptContent(state, p);
    case "decrypt-snapshot":
      return handleDecryptContent(state, p);
    case "has-dek":
      return handleHasDek(state, p);
    case "cache-dek":
      return handleCacheDek(state, p);

    // KEK operations
    case "resolve-kek":
      return handleResolveKek(state, p);
    case "encrypt-kek-for-device":
      return handleEncryptKekForDevice(state, p);
    case "decrypt-kek-from-device-envelope":
      return handleDecryptKekFromDeviceEnvelope(state, p);
    case "encrypt-kek-for-member":
      return handleEncryptKekForMember(state, p);
    case "decrypt-kek-from-member-envelope":
      return handleDecryptKekFromMemberEnvelope(state, p);
    case "wrap-kek-with-umk":
      return handleWrapKekWithUmk(state, p);
    case "unwrap-kek-from-backup":
      return handleUnwrapKekFromBackup(state, p);
    case "encrypt-kek-for-invitation":
      return handleEncryptKekForInvitation(state, p);
    case "decrypt-kek-from-invitation":
      return handleDecryptKekFromInvitation(state, p);
    case "cache-kek":
      return handleCacheKek(state, p);

    // Signing
    case "sign-pop":
      return handleSignPop(state, p);
    case "sign-ws-envelope":
      return handleSignWsEnvelope(state, p);
    case "sign-message":
      return handleSignMessage(state, p);
    case "sign-device-approval":
      return handleSignDeviceApproval(state, p);
    case "sign-device-registration":
      return handleSignDeviceRegistration(state, p);
    case "sign-recovery-challenge":
      return handleSignRecoveryChallenge(state, p);

    // Verification
    case "verify-ws-signature":
      return handleVerifyWsSignature(p);
    case "verify-ed25519":
      return handleVerifyEd25519(p);
    case "verify-device-identity-signature":
      return handleVerifyDeviceIdentitySignature(p);

    // Hashing
    case "compute-update-hash":
      return handleComputeUpdateHash(p);
    case "compute-snapshot-proof":
      return handleComputeSnapshotProof(p);
    case "blake3-hash":
      return handleBlake3Hash(p);
    case "compute-sas":
      return handleComputeSas(p);
    case "calculate-fingerprint":
      return handleCalculateFingerprint(p);

    // ECDH
    case "ecdh-encrypt":
      return handleEcdhEncrypt(state, p);
    case "ecdh-decrypt":
      return handleEcdhDecrypt(state, p);
    case "ecdh-encrypt-umk":
      return handleEcdhEncryptUmk(state, p);
    case "ecdh-decrypt-umk":
      return handleEcdhDecryptUmk(state, p);

    // Trust transfer
    case "encrypt-trust-state":
      return handleEncryptTrustState(state, p);
    case "decrypt-trust-state":
      return handleDecryptTrustState(state, p);

    // TOFU
    case "tofu-verify":
      return handleTofuVerify(p);
    case "tofu-verify-all-devices":
      return handleTofuVerifyAllDevices(state, p);
    case "tofu-trust-device":
      return handleTofuTrustDevice(p);
    case "tofu-update-last-seen":
      return handleTofuUpdateLastSeen(p);
    case "tofu-handle-result":
      return handleTofuHandleResult(p);
    case "tofu-get-all-entries":
      return handleTofuGetAllEntries();
    case "tofu-import-entries":
      return handleTofuImportEntries(p);

    // DSK generation
    case "generate-dsk":
      return handleGenerateDskKey(state);

    // DSK wrapping
    case "wrap-with-dsk":
      return handleWrapWithDsk(state, p);
    case "unwrap-with-dsk":
      return handleUnwrapWithDsk(state, p);
    case "wrap-umk-with-dsk":
      return handleWrapUmkWithDsk(state, p);
    case "unwrap-umk-from-dsk":
      return handleUnwrapUmkFromDsk(state, p);
    case "wrap-device-keys-with-dsk":
      return handleWrapDeviceKeysWithDsk(state, p);
    case "unwrap-device-keys-from-dsk":
      return handleUnwrapDeviceKeysFromDsk(state, p);

    // PDK wrapping
    case "wrap-with-pdk":
      return handleWrapWithPdk(state, p);
    case "unwrap-with-pdk":
      return handleUnwrapWithPdk(state, p);

    case "generate-invitation-token":
      return handleGenerateInvitationToken();
    case "sha256-hash":
      return handleSha256Hash(p);

    default:
      throw new Error(`Unknown request type: ${request.type}`);
  }
}

// ── Lifecycle ────────────────────────────────────────────────

async function handleInit(state: WorkerKeyState, p: Record<string, unknown>): Promise<unknown> {
  // Capture PUK locally (consume from transient, allowed per design)
  let localPuk = transientPuk ? new Uint8Array(transientPuk) : null;

  clearState(state);
  if (transientPuk) transientPuk.fill(0);
  transientPuk = null;

  const dsk = p.dsk as CryptoKey;
  const userId = p.userId as string;
  const deviceId = p.deviceId as string;

  // Derive PDK within this request if password params provided
  let localPdk: Uint8Array | null = null;
  if (p.passwordParams) {
    const pp = p.passwordParams as {
      password: string;
      salt: Uint8Array;
      kdfParams: { memory: number; iterations: number; parallelism: number };
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
    // PUK from this derivation is discarded (localPuk from transient is used)
    derived.puk.fill(0);
  }

  state.dsk = dsk;
  state.userId = userId;
  state.deviceId = deviceId;

  try {
    // DSK: restore device keys
    if (p.wrappedDeviceEcdh && p.wrappedDeviceSigning) {
      try {
        const wrappedEcdh = p.wrappedDeviceEcdh as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
        const wrappedSigning = p.wrappedDeviceSigning as {
          ciphertext: ArrayBuffer;
          iv: ArrayBuffer;
        };
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

    // PDK fallback: restore device keys from PDK-wrapped blobs
    if (
      !state.deviceSigningPrivate &&
      localPdk &&
      p.pdkWrappedDeviceEcdh &&
      p.pdkWrappedDeviceSigning
    ) {
      try {
        const deviceKeys = pdkUnwrapDeviceKeys(
          localPdk,
          p.pdkWrappedDeviceEcdh as { ciphertext: string; nonce: string },
          p.pdkWrappedDeviceSigning as { ciphertext: string; nonce: string },
          userId,
        );
        setDeviceFromPrivateKeys(state, deviceKeys.ecdhPrivate, deviceKeys.signingPrivate);
      } catch {
        // PDK unwrap failed
      }
    }

    // DSK: restore UMK
    if (p.wrappedUmk) {
      try {
        const wrappedUmk = p.wrappedUmk as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
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

    // PDK fallback: restore UMK from PDK-wrapped blob
    if (!state.umk && localPdk && p.pdkWrappedUmk) {
      try {
        state.umk = pdkUnwrapUmk(
          localPdk,
          p.pdkWrappedUmk as { ciphertext: string; nonce: string },
          userId,
        );
      } catch {
        // PDK unwrap failed
      }
    }

    // PUK fallback: unwrap UMK from server-provided encrypted data
    if (!state.umk && p.serverEncryptedUmk && p.serverUmkNonce && localPuk) {
      state.umk = unwrapUmk(
        p.serverEncryptedUmk as Uint8Array,
        p.serverUmkNonce as Uint8Array,
        localPuk,
        userId,
      );
    }

    // Identity keys
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

    // PDK persistence: re-wrap restored keys if caller requested
    let pdkWrapped: {
      wrappedUmk?: { ciphertext: string; nonce: string };
      wrappedDeviceKeys?: {
        ecdh: { ciphertext: string; nonce: string };
        signing: { ciphertext: string; nonce: string };
      };
    } | null = null;
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

    const identityKeysRequested =
      p.encryptedIdentityEcdh &&
      p.identityEcdhNonce &&
      p.encryptedIdentitySigning &&
      p.identitySigningNonce;
    const identityRestored = state.identitySigningPrivate !== null;
    state.initialized =
      state.deviceSigningPrivate !== null &&
      state.umk !== null &&
      (!identityKeysRequested || identityRestored);
    return { status: state.initialized ? "initialized" : "partial", pdkWrapped };
  } finally {
    // Guarantee PDK/PUK zeroization even if operations above throw
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

async function handleInitFromPassword(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  clearState(state);
  if (transientPuk) transientPuk.fill(0);
  transientPuk = null;

  const password = p.password as string;
  const salt = p.salt as Uint8Array;
  const kdfParams = p.kdfParams as { memory: number; iterations: number; parallelism: number };
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
  // PDK/PUK kept as locals only, not stored in state
  let localPdk: Uint8Array | null = derived.pdk;
  let localPuk: Uint8Array | null = derived.puk;

  try {
    if (dsk) {
      state.dsk = dsk;

      if (p.wrappedDeviceEcdh && p.wrappedDeviceSigning) {
        try {
          const wrappedEcdh = p.wrappedDeviceEcdh as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
          const wrappedSigning = p.wrappedDeviceSigning as {
            ciphertext: ArrayBuffer;
            iv: ArrayBuffer;
          };
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
    }

    // PDK fallback: restore device keys from PDK-wrapped blobs
    if (
      !state.deviceSigningPrivate &&
      localPdk &&
      p.pdkWrappedDeviceEcdh &&
      p.pdkWrappedDeviceSigning
    ) {
      try {
        const deviceKeys = pdkUnwrapDeviceKeys(
          localPdk,
          p.pdkWrappedDeviceEcdh as { ciphertext: string; nonce: string },
          p.pdkWrappedDeviceSigning as { ciphertext: string; nonce: string },
          userId,
        );
        setDeviceFromPrivateKeys(state, deviceKeys.ecdhPrivate, deviceKeys.signingPrivate);
      } catch {
        // PDK unwrap failed
      }
    }

    // PDK fallback: restore UMK from PDK-wrapped blob (preferred over server UMK)
    if (!state.umk && localPdk && p.pdkWrappedUmk) {
      try {
        state.umk = pdkUnwrapUmk(
          localPdk,
          p.pdkWrappedUmk as { ciphertext: string; nonce: string },
          userId,
        );
      } catch {
        // PDK unwrap failed
      }
    }

    // PUK fallback: unwrap UMK from server-provided encrypted data
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

    // PDK persistence: re-wrap restored keys if caller requested
    let pdkWrapped: {
      wrappedUmk?: { ciphertext: string; nonce: string };
      wrappedDeviceKeys?: {
        ecdh: { ciphertext: string; nonce: string };
        signing: { ciphertext: string; nonce: string };
      };
    } | null = null;
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

    const identityKeysRequested =
      p.encryptedIdentityEcdh &&
      p.identityEcdhNonce &&
      p.encryptedIdentitySigning &&
      p.identitySigningNonce;
    const identityRestored = state.identitySigningPrivate !== null;
    state.initialized =
      state.deviceSigningPrivate !== null &&
      state.umk !== null &&
      (!identityKeysRequested || identityRestored);

    return { authKey: base64UrlDecode(derived.authKeyBase64), pdkWrapped };
  } finally {
    // Guarantee PDK/PUK zeroization even if operations above throw
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

function handleLock(state: WorkerKeyState): unknown {
  clearState(state);
  if (transientPuk) {
    transientPuk.fill(0);
  }
  transientPuk = null;
  if (transientRuk) {
    transientRuk.fill(0);
  }
  transientRuk = null;
  return { status: "locked" };
}

function handleGetPublicKeys(state: WorkerKeyState): unknown {
  return {
    deviceSigningPublic: state.deviceSigningPublic,
    deviceEcdhPublic: state.deviceEcdhPublic,
    identitySigningPublic: state.identitySigningPublic,
    identityEcdhPublic: state.identityEcdhPublic,
  };
}

function handleGetDeviceId(state: WorkerKeyState): unknown {
  return { deviceId: requireDeviceId(state) };
}

// ── Key import ───────────────────────────────────────────────

function handleImportIdentityKeys(state: WorkerKeyState, p: Record<string, unknown>): unknown {
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

function handleImportDeviceKeys(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  setDeviceFromPrivateKeys(state, p.ecdhPrivate as Uint8Array, p.signingPrivate as Uint8Array);
  return {
    ecdhPublic: state.deviceEcdhPublic,
    signingPublic: state.deviceSigningPublic,
  };
}

function handleImportUmk(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  state.umk = p.umk as Uint8Array;
  return { status: "ok" };
}

// ── Key generation ───────────────────────────────────────────

function handleGenerateIdentityKeys(state: WorkerKeyState): unknown {
  const kp = generateIdentityKeyPair();
  setIdentityFromDecrypted(state, kp);
  return { ecdhPublic: kp.ecdhPublic, signingPublic: kp.signingPublic };
}

function handleGenerateDeviceKeys(state: WorkerKeyState): unknown {
  const kp = generateDeviceKeyPair();
  state.deviceEcdhPrivate = kp.ecdhPrivate;
  state.deviceEcdhPublic = kp.ecdhPublic;
  state.deviceSigningPrivate = kp.signingPrivate;
  state.deviceSigningPublic = kp.signingPublic;
  return { ecdhPublic: kp.ecdhPublic, signingPublic: kp.signingPublic };
}

function handleGenerateUmk(state: WorkerKeyState): unknown {
  state.umk = generateUmk();
  return { status: "ok" };
}

function handleGenerateKek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = (p.keyVersion as number) ?? 1;
  const kek = generateKek();
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { keyVersion };
}

function handleGenerateDek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const documentId = p.documentId as string;
  const workspaceId = p.workspaceId as string;
  const { kek, keyVersion: kekVersion } = requireKekForWorkspace(state, workspaceId);

  const dek = generateDek();
  const dekKeyVersion = (p.dekKeyVersion as number) ?? 1;
  setCachedDek(state, documentId, dek, dekKeyVersion);

  const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, workspaceId);
  return { encryptedDek, nonce, keyVersion: kekVersion };
}

async function handleGenerateRecoveryKey(state: WorkerKeyState): Promise<unknown> {
  const umk = requireUmk(state);
  const userId = requireUserId(state);

  const { mnemonic, ruk } = await generateRecoveryKey();
  const { encryptedUmk, nonce } = wrapUmkWithRuk(umk, ruk, userId);
  ruk.fill(0);

  return { mnemonic, encryptedUmk, nonce };
}

// ── Password derivation ──────────────────────────────────────

async function handleDeriveAuthKeys(p: Record<string, unknown>): Promise<unknown> {
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

  if (transientPuk) transientPuk.fill(0);
  transientPuk = derived.puk;

  // PDK is zeroed immediately — must only be derived and consumed
  // within a single worker request (init/initFromPassword)
  derived.pdk.fill(0);

  return { authKey: base64UrlDecode(derived.authKeyBase64) };
}

async function handleDeriveRuk(p: Record<string, unknown>): Promise<unknown> {
  const mnemonic = p.mnemonic as string;
  const ruk = await deriveRukFromMnemonic(mnemonic);
  transientRuk = ruk;
  return { status: "ok" };
}

// ── UMK wrapping ─────────────────────────────────────────────

function handleWrapUmkForServer(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const umk = requireUmk(state);
  const userId = p.userId as string;

  if (!transientPuk) {
    throw new Error("PUK not available - derive auth keys first");
  }

  const { encryptedUmk, nonce } = wrapUmk(umk, transientPuk, userId);

  // PUK is single-use for this wrapping operation
  transientPuk.fill(0);
  transientPuk = null;

  return { encrypted: encryptedUmk, nonce };
}

function handleWrapUmkWithRuk(state: WorkerKeyState): unknown {
  const umk = requireUmk(state);
  const userId = requireUserId(state);

  if (!transientRuk) {
    throw new Error("RUK not available - derive RUK first");
  }

  const { encryptedUmk, nonce } = wrapUmkWithRuk(umk, transientRuk, userId);

  transientRuk.fill(0);
  transientRuk = null;

  return { encrypted: encryptedUmk, nonce };
}

function handleUnwrapUmkWithRuk(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const encrypted = p.encrypted as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const userId = p.userId as string;

  if (!transientRuk) {
    throw new Error("RUK not available - derive RUK first");
  }

  state.umk = unwrapUmkWithRuk(encrypted, nonce, transientRuk, userId);
  state.userId = userId;

  transientRuk.fill(0);
  transientRuk = null;

  return { status: "ok" };
}

// ── Identity key wrapping ────────────────────────────────────

function handleWrapIdentityKeysForServer(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): unknown {
  const umk = requireUmk(state);
  const userId = p.userId as string;

  if (
    !state.identityEcdhPrivate ||
    !state.identityEcdhPublic ||
    !state.identitySigningPrivate ||
    !state.identitySigningPublic
  ) {
    throw new Error("Identity keys not available");
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

// ── DEK operations ───────────────────────────────────────────

function handleWrapDek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const documentId = p.documentId as string;
  const workspaceId = p.workspaceId as string;
  const { dek } = requireDekForDocument(state, documentId);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { encryptedDek, nonce } = wrapDek(dek, kek, documentId, workspaceId);
  return { encryptedDek, nonce };
}

function handleUnwrapDek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const encryptedDek = p.encryptedDek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const dek = unwrapDek(encryptedDek, nonce, kek, documentId, workspaceId);
  setCachedDek(state, documentId, dek, keyVersion);
  return { status: "ok" };
}

function handleEncryptTitle(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const title = p.title as string;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId);

  const result = encryptTitle(title, dek, documentId, keyVersion);
  return { encrypted: result.encrypted, nonce: result.nonce };
}

function handleDecryptTitle(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const encrypted = p.encrypted as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId);

  const title = decryptTitle(encrypted, nonce, dek, documentId, keyVersion);
  return { title };
}

function handleDecryptTitleBatch(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const items = p.items as TitleDecryptItem[];
  const results: TitleDecryptResult[] = [];

  for (const item of items) {
    try {
      const cached = getCachedDek(state, item.documentId);
      if (!cached) {
        results.push({ documentId: item.documentId, title: null });
        continue;
      }
      const title = decryptTitle(
        item.encrypted,
        item.nonce,
        cached.dek,
        item.documentId,
        item.keyVersion,
      );
      results.push({ documentId: item.documentId, title });
    } catch {
      results.push({ documentId: item.documentId, title: null });
    }
  }

  return results;
}

function handleEncryptContent(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const plaintext = p.plaintext as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId);

  const nonce = randomBytes(24);
  const aad = buildDocumentContentAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);

  return { ciphertext, nonce };
}

function handleDecryptContent(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const documentId = p.documentId as string;
  const keyVersion = p.keyVersion as number;
  const { dek } = requireDekForDocument(state, documentId);

  const aad = buildDocumentContentAad(documentId, keyVersion);
  const cipher = xchacha20poly1305(dek, nonce, aad);
  const plaintext = cipher.decrypt(ciphertext);

  return { plaintext };
}

function handleHasDek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const documentId = p.documentId as string;
  const requiredVersion = p.keyVersion as number | undefined;
  const cached = getCachedDek(state, documentId);
  if (!cached) return { hasDek: false };
  if (requiredVersion !== undefined && cached.keyVersion !== requiredVersion)
    return { hasDek: false };
  return { hasDek: true };
}

function handleCacheDek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const documentId = p.documentId as string;
  const dek = p.dek as Uint8Array;
  const keyVersion = p.keyVersion as number;
  setCachedDek(state, documentId, dek, keyVersion);
  return { status: "ok" };
}

// ── KEK operations ───────────────────────────────────────────

function handleResolveKek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const cached = getCachedKek(state, workspaceId);
  if (!cached) {
    return { found: false };
  }
  return { found: true, keyVersion: cached.keyVersion };
}

function handleEncryptKekForDevice(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const targetDeviceEcdhPublic = p.targetDeviceEcdhPublic as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { ciphertext, nonce } = encryptKekForDevice(
    kek,
    deviceEcdhPrivate,
    targetDeviceEcdhPublic,
    workspaceId,
    userId,
    senderDeviceId,
    targetDeviceId,
    keyVersion,
  );
  return { encrypted: ciphertext, nonce };
}

function handleDecryptKekFromDeviceEnvelope(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const senderEcdhPublic = p.senderEcdhPublic as Uint8Array;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const kek = decryptKekFromDeviceEnvelope(
    encryptedKek,
    nonce,
    deviceEcdhPrivate,
    senderEcdhPublic,
    workspaceId,
    userId,
    senderDeviceId,
    targetDeviceId,
    keyVersion,
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

function handleEncryptKekForMember(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const targetUserId = p.targetUserId as string;
  const targetIdentityEcdhPublic = p.targetIdentityEcdhPublic as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;
  const keyVersion = p.keyVersion as number;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { ciphertext, nonce } = encryptKekForMember(
    kek,
    deviceEcdhPrivate,
    targetIdentityEcdhPublic,
    workspaceId,
    targetUserId,
    senderDeviceId,
    keyVersion,
  );
  return { encrypted: ciphertext, nonce };
}

function handleDecryptKekFromMemberEnvelope(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): unknown {
  const workspaceId = p.workspaceId as string;
  const targetUserId = p.targetUserId as string;
  const senderDeviceId = p.senderDeviceId as string;
  const senderIdentityEcdhPublic = p.senderIdentityEcdhPublic as Uint8Array;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const identityEcdhPrivate = requireIdentityEcdhPrivate(state);

  const kek = decryptKekFromMemberEnvelope(
    encryptedKek,
    nonce,
    identityEcdhPrivate,
    senderIdentityEcdhPublic,
    workspaceId,
    targetUserId,
    keyVersion,
    senderDeviceId,
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

function handleWrapKekWithUmk(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const keyVersion = p.keyVersion as number;
  const umk = requireUmk(state);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { encryptedKek, nonce } = wrapKekWithUmk(kek, umk, workspaceId, userId, keyVersion);
  return { encrypted: encryptedKek, nonce };
}

function handleUnwrapKekFromBackup(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const umk = requireUmk(state);

  const kek = unwrapKekFromBackup(encryptedKek, nonce, umk, workspaceId, userId, keyVersion);
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

function handleEncryptKekForInvitation(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const invitationId = p.invitationId as string;
  const token = p.token as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { encryptedKek, nonce } = encryptKekForInvitation(
    kek,
    token,
    workspaceId,
    invitationId,
    keyVersion,
  );
  return { encrypted: encryptedKek, nonce };
}

function handleDecryptKekFromInvitation(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): unknown {
  const workspaceId = p.workspaceId as string;
  const invitationId = p.invitationId as string;
  const token = p.token as Uint8Array;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;

  const kek = decryptKekFromInvitation(
    encryptedKek,
    nonce,
    token,
    workspaceId,
    invitationId,
    keyVersion,
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

function handleCacheKek(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const workspaceId = p.workspaceId as string;
  const kek = p.kek as Uint8Array;
  const keyVersion = p.keyVersion as number;
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

// ── Signing ──────────────────────────────────────────────────

function handleSignPop(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const challenge = p.challenge as string;
  const deviceId = p.deviceId as string;
  const signingPrivate = requireDeviceSigningPrivate(state);

  const message = buildSignatureMessage(SIGNATURE_ACTION.POP_CHALLENGE, {
    challenge,
    device_id: deviceId,
  });
  return { signature: sign(message, signingPrivate) };
}

function buildWsSignatureMessage(
  prefix: string,
  nonce: string,
  ciphertext: string,
  publicData: Record<string, unknown>,
): Uint8Array {
  const publicDataJcs = canonicalizeBytes(publicData);
  const publicDataB64 = base64UrlEncode(publicDataJcs);
  const body = canonicalizeBytes({ nonce, ciphertext, publicData: publicDataB64 });
  const prefixBytes = new TextEncoder().encode(prefix);
  const result = new Uint8Array(prefixBytes.length + body.length);
  result.set(prefixBytes);
  result.set(body, prefixBytes.length);
  return result;
}

function handleSignWsEnvelope(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const prefix = p.prefix as string;
  const ciphertext = p.ciphertext as string;
  const nonce = p.nonce as string;
  const publicData = p.publicData as Record<string, unknown>;
  const signingPrivate = requireDeviceSigningPrivate(state);

  const message = buildWsSignatureMessage(prefix, nonce, ciphertext, publicData);
  return { signature: sign(message, signingPrivate) };
}

function handleSignMessage(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const action = p.action as string;
  const payload = p.payload as Record<string, unknown>;

  const identityActions: Set<string> = new Set([
    SIGNATURE_ACTION.DEVICE_APPROVAL,
    SIGNATURE_ACTION.DEVICE_REGISTRATION,
    SIGNATURE_ACTION.DEVICE_REVOCATION,
  ]);

  const signingPrivate = identityActions.has(action)
    ? requireIdentitySigningPrivate(state)
    : requireDeviceSigningPrivate(state);

  const message = buildSignatureMessage(action, payload);
  return { signature: sign(message, signingPrivate) };
}

function handleSignDeviceApproval(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;
  const identitySigningPrivate = requireIdentitySigningPrivate(state);

  const signature = signDeviceApproval(
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
    identitySigningPrivate,
  );
  return { signature };
}

function handleSignDeviceRegistration(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;
  const identitySigningPrivate = requireIdentitySigningPrivate(state);

  const signature = signDeviceRegistration(
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
    identitySigningPrivate,
  );
  return { signature };
}

function handleSignRecoveryChallenge(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const message = p.message as Uint8Array;
  const identitySigningPrivate = requireIdentitySigningPrivate(state);
  return { signature: sign(message, identitySigningPrivate) };
}

// ── Verification ─────────────────────────────────────────────

function handleVerifyWsSignature(p: Record<string, unknown>): unknown {
  const prefix = p.prefix as string;
  const ciphertext = p.ciphertext as string;
  const nonce = p.nonce as string;
  const publicData = p.publicData as Record<string, unknown>;
  const signature = p.signature as Uint8Array;
  const signingPubKey = p.signingPubKey as Uint8Array;

  const message = buildWsSignatureMessage(prefix, nonce, ciphertext, publicData);

  try {
    return { valid: verify(message, signature, signingPubKey) };
  } catch {
    return { valid: false };
  }
}

function handleVerifyEd25519(p: Record<string, unknown>): unknown {
  const message = p.message as Uint8Array;
  const signature = p.signature as Uint8Array;
  const publicKey = p.publicKey as Uint8Array;

  try {
    return { valid: verify(message, signature, publicKey) };
  } catch {
    return { valid: false };
  }
}

function handleVerifyDeviceIdentitySignature(p: Record<string, unknown>): unknown {
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;
  const identitySignature = p.identitySignature as Uint8Array;
  const identitySigningPublic = p.identitySigningPublic as Uint8Array;

  const valid = verifyDeviceIdentitySignature(
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
    identitySignature,
    identitySigningPublic,
  );
  return { valid };
}

// ── Hashing ──────────────────────────────────────────────────

function handleComputeUpdateHash(p: Record<string, unknown>): unknown {
  const bytes = canonicalizeBytes(p);
  const hash = blake3(bytes);
  return { hash: base64UrlEncode(hash) };
}

function handleComputeSnapshotProof(p: Record<string, unknown>): unknown {
  const ciphertextHash = p.ciphertextHash as string;
  const parentProof = p.parentProof as string;
  const snapshotId = p.snapshotId as string;

  const input = canonicalizeBytes({
    ciphertext_hash: ciphertextHash,
    parent_proof: parentProof,
    snapshot_id: snapshotId,
  });
  return { proof: base64UrlEncode(blake3(input)) };
}

function handleBlake3Hash(p: Record<string, unknown>): unknown {
  const data = p.data as Uint8Array;
  return blake3(data);
}

function handleComputeSas(p: Record<string, unknown>): unknown {
  const identitySigningPublic = p.identitySigningPublic as Uint8Array;
  const deviceSigningPublic = p.deviceSigningPublic as Uint8Array;
  const deviceEcdhPublic = p.deviceEcdhPublic as Uint8Array;
  const clientNonce = p.clientNonce as Uint8Array;

  const result = computeSas(
    identitySigningPublic,
    deviceSigningPublic,
    deviceEcdhPublic,
    clientNonce,
  );
  return {
    emojis: result.emojis.map((emoji) => ({ emoji, name: "" })),
    hash: result.bytes,
  };
}

function handleCalculateFingerprint(p: Record<string, unknown>): unknown {
  const signingPublicKey = p.signingPublicKey as Uint8Array;
  const raw = calculateFingerprint(signingPublicKey);
  return { fingerprint: formatFingerprint(raw) };
}

// ── ECDH ─────────────────────────────────────────────────────

function handleEcdhEncrypt(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const plaintext = p.plaintext as Uint8Array;
  const aad = p.aad as Uint8Array;
  const hkdfInfo = p.hkdfInfo as string;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const result = ecdhEncrypt(plaintext, deviceEcdhPrivate, theirPublic, hkdfInfo, aad);
  return { ciphertext: result.ciphertext, nonce: result.nonce };
}

function handleEcdhDecrypt(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const aad = p.aad as Uint8Array;
  const hkdfInfo = p.hkdfInfo as string;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const plaintext = ecdhDecrypt(ciphertext, nonce, deviceEcdhPrivate, theirPublic, hkdfInfo, aad);
  return { plaintext };
}

function handleEcdhEncryptUmk(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const userId = requireUserId(state);
  const aad = buildDeviceUmkDistributionAad(userId, senderDeviceId, targetDeviceId);
  const hkdfInfo = "device_umk_wrap";
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const umk = requireUmk(state);

  const result = ecdhEncrypt(umk, deviceEcdhPrivate, theirPublic, hkdfInfo, aad);
  return { ciphertext: result.ciphertext, nonce: result.nonce };
}

function handleEcdhDecryptUmk(state: WorkerKeyState, p: Record<string, unknown>): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const userId = requireUserId(state);
  const aad = buildDeviceUmkDistributionAad(userId, senderDeviceId, targetDeviceId);
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const umk = ecdhDecrypt(
    ciphertext,
    nonce,
    deviceEcdhPrivate,
    theirPublic,
    "device_umk_wrap",
    aad,
  );
  // Store UMK directly in Worker state — never return raw UMK to main thread
  state.umk = umk;
  return { status: "ok" };
}

// ── Trust transfer ───────────────────────────────────────────

async function handleEncryptTrustState(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const targetDeviceEcdhPublic = p.targetDeviceEcdhPublic as Uint8Array;
  const transferNonce = p.transferNonce as Uint8Array;

  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const deviceSigningPrivate = requireDeviceSigningPrivate(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const targetDeviceId = p.targetDeviceId as string;

  const tofuEntries = await getAllTofuEntries();
  if (tofuEntries.length === 0) return { empty: true };

  const aadParams: TrustTransferAadParams = {
    userId,
    senderDeviceId: deviceId,
    targetDeviceId,
  };

  const result = encryptTrustState(
    { tofuEntries, transferNonce },
    deviceEcdhPrivate,
    targetDeviceEcdhPublic,
    deviceSigningPrivate,
    aadParams,
  );

  return {
    ciphertext: result.encryptedState,
    nonce: result.nonce,
    signature: result.signature,
  };
}

async function handleDecryptTrustState(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const senderDeviceEcdhPublic = p.senderDeviceEcdhPublic as Uint8Array;
  const senderIdentitySigningPublic = p.senderIdentitySigningPublic as Uint8Array;
  const transferNonce = p.transferNonce as Uint8Array;
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const signature = p.signature as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;

  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);

  const aadParams: TrustTransferAadParams = {
    userId,
    senderDeviceId,
    targetDeviceId: deviceId,
  };

  const snapshot = decryptTrustState(
    { encryptedState: ciphertext, nonce, signature },
    deviceEcdhPrivate,
    senderDeviceEcdhPublic,
    senderIdentitySigningPublic,
    transferNonce,
    aadParams,
  ) as {
    tofuEntries: Array<{
      userId: string;
      deviceId: string;
      signingPublicKey: Uint8Array;
      ecdhPublicKey: Uint8Array;
      firstSeenAt: number;
      lastSeenAt: number;
    }>;
  };

  await importTofuEntries(snapshot.tofuEntries);

  return { imported: snapshot.tofuEntries.length };
}

// ── TOFU ─────────────────────────────────────────────────────

async function handleTofuVerify(p: Record<string, unknown>): Promise<unknown> {
  const userId = p.userId as string;
  const deviceId = p.deviceId as string;
  const signingPublicKey = p.signingPublicKey as Uint8Array;
  const ecdhPublicKey = p.ecdhPublicKey as Uint8Array;

  const result = await verifyTofu(userId, deviceId, signingPublicKey, ecdhPublicKey);
  return { status: result.status };
}

async function handleTofuVerifyAllDevices(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const rawDevices = p.devices as Array<{
    userId: string;
    deviceId: string;
    name?: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
    identitySignature?: string | null;
    clientNonce?: string | null;
  }>;
  const userId = requireUserId(state);

  const devices = rawDevices.map((d) => ({
    id: d.deviceId,
    name: d.name ?? d.deviceId,
    signing_public_key: base64UrlEncode(d.signingPublicKey),
    ecdh_public_key: base64UrlEncode(d.ecdhPublicKey),
    identity_signature: d.identitySignature ?? null,
    client_nonce: d.clientNonce ?? null,
  }));

  const errors = await verifyAllDeviceTofu(
    userId,
    devices as Parameters<typeof verifyAllDeviceTofu>[1],
    state.identitySigningPublic,
  );
  return { errors };
}

async function handleTofuTrustDevice(p: Record<string, unknown>): Promise<unknown> {
  await trustDevice({
    userId: p.userId as string,
    deviceId: p.deviceId as string,
    signingPublicKey: p.signingPublicKey as Uint8Array,
    ecdhPublicKey: p.ecdhPublicKey as Uint8Array,
    firstSeenAt: (p.firstSeenAt as number) ?? Date.now(),
    lastSeenAt: (p.lastSeenAt as number) ?? Date.now(),
  });
  return { status: "ok" };
}

async function handleTofuUpdateLastSeen(p: Record<string, unknown>): Promise<unknown> {
  await updateDeviceLastSeen(p.userId as string, p.deviceId as string);
  return { status: "ok" };
}

async function handleTofuHandleResult(p: Record<string, unknown>): Promise<unknown> {
  await handleTofuResult(p.result as Parameters<typeof handleTofuResult>[0]);
  return { status: "ok" };
}

// ── DSK wrapping ─────────────────────────────────────────────

async function handleWrapWithDsk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const plaintext = p.plaintext as Uint8Array;
  const aad = p.aad as Uint8Array;
  return await dskEncrypt(dsk, plaintext, aad);
}

async function handleUnwrapWithDsk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = p.ciphertext as ArrayBuffer;
  const iv = p.iv as ArrayBuffer;
  const aad = p.aad as Uint8Array;
  return { plaintext: await dskDecrypt(dsk, ciphertext, iv, aad) };
}

async function handleWrapUmkWithDsk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const umk = requireUmk(state);
  const userId = p.userId as string;
  return await dskEncrypt(dsk, umk, buildDskUmkCacheAad(userId));
}

async function handleUnwrapUmkFromDsk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = p.ciphertext as ArrayBuffer;
  const iv = p.iv as ArrayBuffer;
  const userId = p.userId as string;
  state.umk = await dskDecrypt(dsk, ciphertext, iv, buildDskUmkCacheAad(userId));
  return { status: "ok" };
}

async function handleWrapDeviceKeysWithDsk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const userId = p.userId as string;

  if (!state.deviceEcdhPrivate || !state.deviceSigningPrivate) {
    throw new Error("Device keys not available");
  }

  const wrappedEcdh = await dskEncrypt(dsk, state.deviceEcdhPrivate, buildDskDeviceEcdhAad(userId));
  const wrappedSigning = await dskEncrypt(
    dsk,
    state.deviceSigningPrivate,
    buildDskDeviceSigningAad(userId),
  );

  return { wrappedEcdh, wrappedSigning };
}

async function handleUnwrapDeviceKeysFromDsk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
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

// ── PDK wrapping ─────────────────────────────────────────────

async function handleWrapWithPdk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const userId = requireUserId(state);

  // PDK must be derived within this single request, then zeroed
  const pp = p.passwordParams as {
    password: string;
    salt: Uint8Array;
    kdfParams: { memory: number; iterations: number; parallelism: number };
  };
  if (!pp) throw new Error("passwordParams required for PDK wrapping");
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

async function handleUnwrapWithPdk(
  state: WorkerKeyState,
  p: Record<string, unknown>,
): Promise<unknown> {
  const userId = (p.userId as string) ?? requireUserId(state);

  // PDK must be derived within this single request, then zeroed
  const pp = p.passwordParams as {
    password: string;
    salt: Uint8Array;
    kdfParams: { memory: number; iterations: number; parallelism: number };
  };
  if (!pp) throw new Error("passwordParams required for PDK unwrapping");
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

async function handleGenerateDskKey(state: WorkerKeyState): Promise<unknown> {
  const dsk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  state.dsk = dsk;
  await storeDsk(dsk);
  return { status: "ok" };
}

async function handleTofuGetAllEntries(): Promise<unknown> {
  const entries = await getAllTofuEntries();
  return {
    entries: entries.map((e) => ({
      userId: e.userId,
      deviceId: e.deviceId,
      signingPublicKey: e.signingPublicKey,
      ecdhPublicKey: e.ecdhPublicKey,
      firstSeenAt: e.firstSeenAt,
      lastSeenAt: e.lastSeenAt,
    })),
  };
}

async function handleTofuImportEntries(p: Record<string, unknown>): Promise<unknown> {
  const entries = p.entries as Array<{
    userId: string;
    deviceId: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
    firstSeenAt: number;
    lastSeenAt: number;
  }>;
  await importTofuEntries(entries);
  return { status: "ok" };
}

async function handleGenerateInvitationToken(): Promise<unknown> {
  const tokenBytes = randomBytes(32);
  const tokenBase64 = base64UrlEncode(tokenBytes);
  const hashBuffer = await crypto.subtle.digest("SHA-256", tokenBytes.buffer as ArrayBuffer);
  const tokenHash = base64UrlEncode(new Uint8Array(hashBuffer));
  const tokenPrefix = tokenBase64.slice(0, 4);
  return { token: tokenBase64, tokenHash, tokenPrefix };
}

async function handleSha256Hash(p: Record<string, unknown>): Promise<unknown> {
  const data = p.data as Uint8Array;
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return { hash: base64UrlEncode(new Uint8Array(hashBuffer)) };
}
