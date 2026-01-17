import { describe, it, expect, beforeAll } from 'vitest'

import { getSodium } from '../sodium'
import {
  encrypt,
  decrypt,
  encryptDek,
  decryptDek,
  encryptString,
  decryptString,
  generateKey,
  generateNonce,
  KEY_SIZE,
  NONCE_SIZE,
} from '../xchacha20'

describe('XChaCha20-Poly1305', () => {
  beforeAll(async () => {
    // Ensure sodium is initialized
    await getSodium()
  })

  describe('generateKey', () => {
    it('should generate a 32-byte key', async () => {
      const key = await generateKey()
      expect(key).toBeInstanceOf(Uint8Array)
      expect(key.length).toBe(KEY_SIZE)
    })

    it('should generate unique keys', async () => {
      const key1 = await generateKey()
      const key2 = await generateKey()
      expect(key1).not.toEqual(key2)
    })
  })

  describe('generateNonce', () => {
    it('should generate a 24-byte nonce', async () => {
      const nonce = await generateNonce()
      expect(nonce).toBeInstanceOf(Uint8Array)
      expect(nonce.length).toBe(NONCE_SIZE)
    })

    it('should generate unique nonces', async () => {
      const nonce1 = await generateNonce()
      const nonce2 = await generateNonce()
      expect(nonce1).not.toEqual(nonce2)
    })
  })

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt data correctly', async () => {
      const key = await generateKey()
      const plaintext = new TextEncoder().encode('Hello, E2EE World!')

      const { ciphertext, nonce } = await encrypt(key, plaintext)
      const decrypted = await decrypt(key, ciphertext, nonce)

      expect(decrypted).toEqual(plaintext)
    })

    it('should encrypt empty data', async () => {
      const key = await generateKey()
      const plaintext = new Uint8Array(0)

      const { ciphertext, nonce } = await encrypt(key, plaintext)
      const decrypted = await decrypt(key, ciphertext, nonce)

      expect(decrypted).toEqual(plaintext)
    })

    it('should encrypt large data', async () => {
      const key = await generateKey()
      const plaintext = new Uint8Array(1024 * 1024) // 1MB
      plaintext.fill(0xAB)

      const { ciphertext, nonce } = await encrypt(key, plaintext)
      const decrypted = await decrypt(key, ciphertext, nonce)

      expect(decrypted).toEqual(plaintext)
    })

    it('should fail with wrong key', async () => {
      const key1 = await generateKey()
      const key2 = await generateKey()
      const plaintext = new TextEncoder().encode('Secret message')

      const { ciphertext, nonce } = await encrypt(key1, plaintext)

      await expect(decrypt(key2, ciphertext, nonce)).rejects.toThrow('Decryption failed')
    })

    it('should fail with corrupted ciphertext', async () => {
      const key = await generateKey()
      const plaintext = new TextEncoder().encode('Secret message')

      const { ciphertext, nonce } = await encrypt(key, plaintext)

      // Corrupt the ciphertext
      ciphertext[0] ^= 0xFF

      await expect(decrypt(key, ciphertext, nonce)).rejects.toThrow('Decryption failed')
    })

    it('should throw on invalid key length', async () => {
      const shortKey = new Uint8Array(16)
      const plaintext = new Uint8Array([1, 2, 3])

      await expect(encrypt(shortKey, plaintext)).rejects.toThrow('Invalid key length')
    })

    it('should throw on invalid nonce length', async () => {
      const key = await generateKey()
      const ciphertext = new Uint8Array(32)
      const shortNonce = new Uint8Array(12)

      await expect(decrypt(key, ciphertext, shortNonce)).rejects.toThrow('Invalid nonce length')
    })
  })

  describe('encryptDek/decryptDek', () => {
    it('should encrypt and decrypt a DEK', async () => {
      const kek = await generateKey()
      const dek = await generateKey()

      const { ciphertext, nonce } = await encryptDek(kek, dek)
      const decryptedDek = await decryptDek(kek, ciphertext, nonce)

      expect(decryptedDek).toEqual(dek)
    })
  })

  describe('encryptString/decryptString', () => {
    it('should encrypt and decrypt strings', async () => {
      const key = await generateKey()
      const plaintext = 'Hello, World! 日本語テスト 🎉'

      const { ciphertext, nonce } = await encryptString(key, plaintext)
      const decrypted = await decryptString(key, ciphertext, nonce)

      expect(decrypted).toBe(plaintext)
    })
  })
})
