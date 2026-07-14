import init, {
  refmd_hpke_derive_key_material,
  refmd_hpke_discard_sender,
  refmd_hpke_generate_key_material,
  refmd_hpke_open,
  refmd_hpke_sender_seal,
  refmd_hpke_setup_sender,
} from "./native/refmd_crypto.js";
import wasmUrl from "./native/refmd_crypto_bg.wasm?url";

const PRIVATE_KEY_BYTES = 32;
const X25519_PRIVATE_KEY_BYTES = 32;
const MLKEM768_PUBLIC_KEY_BYTES = 1184;
const PUBLIC_KEY_BYTES = 1216;
const ENCAPSULATED_KEY_BYTES = 1120;
const SETUP_HANDLE_BYTES = 4;

let initialized = false;
let initialization: Promise<void> | null = null;

if (import.meta.env.MODE === "test") await initializeNativeHpke();

export interface NativeHybridEncryptionKeyMaterial {
  privateKey: Uint8Array;
  x25519PrivateKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  mlkem768PublicKey: Uint8Array;
  publicKey: Uint8Array;
}

export function initializeNativeHpke(): Promise<void> {
  initialization ??= (async () => {
    await init({ module_or_path: await wasmModuleInput() });
    initialized = true;
  })();
  return initialization;
}

export function generateNativeHybridEncryptionKey(): NativeHybridEncryptionKeyMaterial {
  const material = invoke("hpke_key_generation_failed", () => refmd_hpke_generate_key_material());
  try {
    if (material.length !== PRIVATE_KEY_BYTES + X25519_PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES) {
      throw new Error("hpke_key_material_invalid");
    }
    return splitKeyMaterial(
      material.slice(0, PRIVATE_KEY_BYTES),
      material.slice(PRIVATE_KEY_BYTES, PRIVATE_KEY_BYTES + X25519_PRIVATE_KEY_BYTES),
      material.slice(PRIVATE_KEY_BYTES + X25519_PRIVATE_KEY_BYTES),
    );
  } finally {
    material.fill(0);
  }
}

export function deriveNativeHybridEncryptionKey(
  privateKey: Uint8Array,
): NativeHybridEncryptionKeyMaterial {
  const material = invoke("hpke_private_key_invalid", () =>
    refmd_hpke_derive_key_material(privateKey),
  );
  try {
    if (material.length !== X25519_PRIVATE_KEY_BYTES + PUBLIC_KEY_BYTES) {
      throw new Error("hpke_key_material_invalid");
    }
    return splitKeyMaterial(
      privateKey.slice(),
      material.slice(0, X25519_PRIVATE_KEY_BYTES),
      material.slice(X25519_PRIVATE_KEY_BYTES),
    );
  } finally {
    material.fill(0);
  }
}

export function nativeHpkeSetupSender(params: { publicKey: Uint8Array; info: Uint8Array }): {
  contextHandle: number;
  enc: Uint8Array;
} {
  const setup = invoke("hpke_setup_sender_failed", () =>
    refmd_hpke_setup_sender(params.publicKey, params.info),
  );
  if (setup.length !== SETUP_HANDLE_BYTES + ENCAPSULATED_KEY_BYTES) {
    throw new Error("hpke_sender_setup_invalid");
  }
  const view = new DataView(setup.buffer, setup.byteOffset, SETUP_HANDLE_BYTES);
  return {
    contextHandle: view.getUint32(0, true),
    enc: setup.slice(SETUP_HANDLE_BYTES),
  };
}

export function nativeHpkeSeal(params: {
  contextHandle: number;
  aad: Uint8Array;
  plaintext: Uint8Array;
}): Uint8Array {
  return invoke("hpke_seal_failed", () =>
    refmd_hpke_sender_seal(params.contextHandle, params.aad, params.plaintext),
  );
}

export function discardNativeHpkeSender(contextHandle: number): void {
  refmd_hpke_discard_sender(contextHandle);
}

export function nativeHpkeOpen(params: {
  privateKey: Uint8Array;
  enc: Uint8Array;
  info: Uint8Array;
  aad: Uint8Array;
  ciphertext: Uint8Array;
}): Uint8Array {
  return invoke("hpke_open_failed", () =>
    refmd_hpke_open(params.privateKey, params.enc, params.info, params.aad, params.ciphertext),
  );
}

function splitKeyMaterial(
  privateKey: Uint8Array,
  x25519PrivateKey: Uint8Array,
  publicKey: Uint8Array,
): NativeHybridEncryptionKeyMaterial {
  if (publicKey.length !== PUBLIC_KEY_BYTES) throw new Error("hpke_public_key_invalid");
  return {
    privateKey,
    x25519PrivateKey,
    mlkem768PublicKey: publicKey.slice(0, MLKEM768_PUBLIC_KEY_BYTES),
    x25519PublicKey: publicKey.slice(MLKEM768_PUBLIC_KEY_BYTES),
    publicKey,
  };
}

function invoke<T>(errorCode: string, operation: () => T): T {
  if (!initialized) throw new Error("hpke_native_not_initialized");
  try {
    return operation();
  } catch {
    throw new Error(errorCode);
  }
}

async function wasmModuleInput(): Promise<string | Uint8Array> {
  if (import.meta.env.MODE !== "test") return wasmUrl;
  const nodeFsPromises = "node:fs/promises";
  const { readFile } = await import(/* @vite-ignore */ nodeFsPromises);
  return readFile(wasmUrl.startsWith("/") ? `.${wasmUrl}` : wasmUrl);
}
