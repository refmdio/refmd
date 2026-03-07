import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { argon2id } from "hash-wasm";
import { base64UrlDecode, base64UrlEncode } from "./encoding";

export interface KdfParams {
  algorithm: string;
  memory: number;
  iterations: number;
  parallelism: number;
  hash_length: number;
}

export interface DerivedKeys {
  authKeyBase64: string;
  puk: Uint8Array;
  pdk: Uint8Array;
}

const HKDF_ZERO_SALT = new Uint8Array(32);

const KDF_BOUNDS = {
  memory: { min: 16384, max: 262144 },
  iterations: { min: 2, max: 10 },
  parallelism: { min: 1, max: 8 },
} as const;

function validateKdfParams(params: KdfParams): void {
  if (params.algorithm !== "argon2id") {
    throw new Error("Unsupported KDF algorithm: " + params.algorithm);
  }
  if (params.memory < KDF_BOUNDS.memory.min || params.memory > KDF_BOUNDS.memory.max) {
    throw new Error("KDF memory out of bounds");
  }
  if (params.iterations < KDF_BOUNDS.iterations.min || params.iterations > KDF_BOUNDS.iterations.max) {
    throw new Error("KDF iterations out of bounds");
  }
  if (params.parallelism < KDF_BOUNDS.parallelism.min || params.parallelism > KDF_BOUNDS.parallelism.max) {
    throw new Error("KDF parallelism out of bounds");
  }
}

export async function deriveAuthKeys(
  password: string,
  saltBase64: string,
  params: KdfParams,
): Promise<DerivedKeys> {
  validateKdfParams(params);

  const salt = base64UrlDecode(saltBase64);
  if (salt.length !== 16) {
    throw new Error("Salt must be 16 bytes");
  }

  const masterKeyHex = await argon2id({
    password,
    salt,
    memorySize: params.memory,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: params.hash_length || 32,
    outputType: "hex",
  });

  if (masterKeyHex.length !== 64) {
    throw new Error("Unexpected Argon2id output length");
  }

  const masterKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    masterKey[i] = parseInt(masterKeyHex.slice(i * 2, i * 2 + 2), 16);
  }

  const enc = new TextEncoder();
  const authKey = hkdf(sha256, masterKey, HKDF_ZERO_SALT, enc.encode("password_auth"), 32);
  const puk = hkdf(sha256, masterKey, HKDF_ZERO_SALT, enc.encode("password_unlock"), 32);
  const pdk = hkdf(sha256, masterKey, HKDF_ZERO_SALT, enc.encode("password_device_key"), 32);

  masterKey.fill(0);

  return {
    authKeyBase64: base64UrlEncode(authKey),
    puk,
    pdk,
  };
}
