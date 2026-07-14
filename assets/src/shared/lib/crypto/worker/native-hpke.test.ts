import { describe, expect, it } from "vite-plus/test";
import {
  deriveNativeHybridEncryptionKey,
  discardNativeHpkeSender,
  generateNativeHybridEncryptionKey,
  nativeHpkeOpen,
  nativeHpkeSeal,
  nativeHpkeSetupSender,
} from "./native-hpke";

describe("Rust/WASM HPKE boundary", () => {
  it("generates and derives the same MLKEM768-X25519 key material", () => {
    const generated = generateNativeHybridEncryptionKey();
    const derived = deriveNativeHybridEncryptionKey(generated.privateKey);

    expect(generated.privateKey).toHaveLength(32);
    expect(generated.x25519PrivateKey).toHaveLength(32);
    expect(generated.mlkem768PublicKey).toHaveLength(1184);
    expect(generated.x25519PublicKey).toHaveLength(32);
    expect(generated.publicKey).toHaveLength(1216);
    expect(derived).toEqual(generated);
  });

  it("seals and opens through a single-use sender context", () => {
    const recipient = generateNativeHybridEncryptionKey();
    const info = new TextEncoder().encode("info");
    const aad = new TextEncoder().encode("aad");
    const plaintext = new TextEncoder().encode("secret");
    const sender = nativeHpkeSetupSender({ publicKey: recipient.publicKey, info });
    const ciphertext = nativeHpkeSeal({
      contextHandle: sender.contextHandle,
      aad,
      plaintext,
    });

    expect(sender.enc).toHaveLength(1120);
    expect(
      Array.from(
        nativeHpkeOpen({
          privateKey: recipient.privateKey,
          enc: sender.enc,
          info,
          aad,
          ciphertext,
        }),
      ),
    ).toEqual(Array.from(plaintext));
    expect(() => nativeHpkeSeal({ contextHandle: sender.contextHandle, aad, plaintext })).toThrow(
      "hpke_seal_failed",
    );
  });

  it("rejects a discarded sender context", () => {
    const recipient = generateNativeHybridEncryptionKey();
    const sender = nativeHpkeSetupSender({
      publicKey: recipient.publicKey,
      info: new Uint8Array(),
    });
    discardNativeHpkeSender(sender.contextHandle);

    expect(() =>
      nativeHpkeSeal({
        contextHandle: sender.contextHandle,
        aad: new Uint8Array(),
        plaintext: new Uint8Array(),
      }),
    ).toThrow("hpke_seal_failed");
  });

  it("rejects malformed keys and encapsulated values", () => {
    expect(() => deriveNativeHybridEncryptionKey(new Uint8Array(31))).toThrow(
      "hpke_private_key_invalid",
    );
    expect(() =>
      nativeHpkeOpen({
        privateKey: new Uint8Array(32),
        enc: new Uint8Array(1119),
        info: new Uint8Array(),
        aad: new Uint8Array(),
        ciphertext: new Uint8Array(),
      }),
    ).toThrow("hpke_open_failed");
  });
});
