import { describe, it, expect, beforeAll } from 'vitest'
import {
  sign,
  verify,
  signToBase64,
  verifyFromBase64,
  generateKeyPair,
  buildSigningMessage,
  SIGNATURE_DOMAINS,
  PUBLIC_KEY_SIZE,
  PRIVATE_KEY_SIZE,
  SIGNATURE_SIZE,
} from '../ed25519'
import { getSodium } from '../sodium'

describe('Ed25519', () => {
  beforeAll(async () => {
    await getSodium()
  })

  describe('generateKeyPair', () => {
    it('should generate valid key pair sizes', async () => {
      const { publicKey, privateKey } = await generateKeyPair()

      expect(publicKey).toBeInstanceOf(Uint8Array)
      expect(publicKey.length).toBe(PUBLIC_KEY_SIZE)

      expect(privateKey).toBeInstanceOf(Uint8Array)
      expect(privateKey.length).toBe(PRIVATE_KEY_SIZE)
    })

    it('should generate unique key pairs', async () => {
      const kp1 = await generateKeyPair()
      const kp2 = await generateKeyPair()

      expect(kp1.publicKey).not.toEqual(kp2.publicKey)
      expect(kp1.privateKey).not.toEqual(kp2.privateKey)
    })
  })

  describe('buildSigningMessage', () => {
    it('should build message with correct format', () => {
      const message = buildSigningMessage(SIGNATURE_DOMAINS.UPDATE, {
        ciphertext: 'Y2lwaGVy',
        nonce: 'bm9uY2U=',
        publicData: 'cHVibGljRGF0YQ==',
      })

      const expected = 'refmd_update{"ciphertext":"Y2lwaGVy","nonce":"bm9uY2U=","publicData":"cHVibGljRGF0YQ=="}'
      expect(new TextDecoder().decode(message)).toBe(expected)
    })

    it('should produce deterministic output', () => {
      const msg1 = buildSigningMessage(SIGNATURE_DOMAINS.SNAPSHOT, {
        ciphertext: 'abc',
        nonce: 'def',
        publicData: 'ghi',
      })

      const msg2 = buildSigningMessage(SIGNATURE_DOMAINS.SNAPSHOT, {
        nonce: 'def', // different order
        ciphertext: 'abc',
        publicData: 'ghi',
      })

      expect(msg1).toEqual(msg2)
    })
  })

  describe('sign/verify', () => {
    it('should sign and verify a message', async () => {
      const { publicKey, privateKey } = await generateKeyPair()
      const message = {
        ciphertext: 'encrypted_content',
        nonce: 'random_nonce',
        publicData: 'public_metadata',
      }

      const signature = await sign(privateKey, SIGNATURE_DOMAINS.UPDATE, message)

      expect(signature).toBeInstanceOf(Uint8Array)
      expect(signature.length).toBe(SIGNATURE_SIZE)

      const isValid = await verify(publicKey, signature, SIGNATURE_DOMAINS.UPDATE, message)
      expect(isValid).toBe(true)
    })

    it('should fail verification with wrong public key', async () => {
      const kp1 = await generateKeyPair()
      const kp2 = await generateKeyPair()
      const message = {
        ciphertext: 'encrypted_content',
        nonce: 'random_nonce',
        publicData: 'public_metadata',
      }

      const signature = await sign(kp1.privateKey, SIGNATURE_DOMAINS.UPDATE, message)
      const isValid = await verify(kp2.publicKey, signature, SIGNATURE_DOMAINS.UPDATE, message)

      expect(isValid).toBe(false)
    })

    it('should fail verification with modified message', async () => {
      const { publicKey, privateKey } = await generateKeyPair()
      const message = {
        ciphertext: 'encrypted_content',
        nonce: 'random_nonce',
        publicData: 'public_metadata',
      }

      const signature = await sign(privateKey, SIGNATURE_DOMAINS.UPDATE, message)

      const modifiedMessage = { ...message, ciphertext: 'tampered_content' }
      const isValid = await verify(publicKey, signature, SIGNATURE_DOMAINS.UPDATE, modifiedMessage)

      expect(isValid).toBe(false)
    })

    it('should fail verification with wrong domain', async () => {
      const { publicKey, privateKey } = await generateKeyPair()
      const message = {
        ciphertext: 'encrypted_content',
        nonce: 'random_nonce',
        publicData: 'public_metadata',
      }

      const signature = await sign(privateKey, SIGNATURE_DOMAINS.UPDATE, message)
      const isValid = await verify(publicKey, signature, SIGNATURE_DOMAINS.SNAPSHOT, message)

      expect(isValid).toBe(false)
    })
  })

  describe('signToBase64/verifyFromBase64', () => {
    it('should work with Base64 encoding', async () => {
      const { publicKey, privateKey } = await generateKeyPair()
      const message = {
        ciphertext: 'encrypted_content',
        nonce: 'random_nonce',
        publicData: 'public_metadata',
      }

      const signatureBase64 = await signToBase64(privateKey, SIGNATURE_DOMAINS.UPDATE, message)
      expect(typeof signatureBase64).toBe('string')

      const isValid = await verifyFromBase64(publicKey, signatureBase64, SIGNATURE_DOMAINS.UPDATE, message)
      expect(isValid).toBe(true)
    })
  })

  describe('input validation', () => {
    it('should throw on invalid private key length', async () => {
      const shortKey = new Uint8Array(32)
      const message = {
        ciphertext: 'test',
        nonce: 'test',
        publicData: 'test',
      }

      await expect(sign(shortKey, SIGNATURE_DOMAINS.UPDATE, message)).rejects.toThrow('Invalid private key length')
    })

    it('should throw on invalid public key length', async () => {
      const shortKey = new Uint8Array(16)
      const signature = new Uint8Array(SIGNATURE_SIZE)
      const message = {
        ciphertext: 'test',
        nonce: 'test',
        publicData: 'test',
      }

      await expect(verify(shortKey, signature, SIGNATURE_DOMAINS.UPDATE, message)).rejects.toThrow('Invalid public key length')
    })

    it('should throw on invalid signature length', async () => {
      const { publicKey } = await generateKeyPair()
      const shortSignature = new Uint8Array(32)
      const message = {
        ciphertext: 'test',
        nonce: 'test',
        publicData: 'test',
      }

      await expect(verify(publicKey, shortSignature, SIGNATURE_DOMAINS.UPDATE, message)).rejects.toThrow('Invalid signature length')
    })
  })
})
