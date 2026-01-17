import { describe, it, expect } from 'vitest'

import {
  generateRecoveryKey,
  validateRecoveryKey,
  recoveryKeyToUmk,
  umkToRecoveryKey,
  getWordsAtIndices,
  verifyWords,
  generateVerificationIndices,
  getWordList,
  WORD_COUNT,
  ENTROPY_BYTES,
} from '../bip39'

describe('BIP39 Recovery Key', () => {
  describe('generateRecoveryKey', () => {
    it('should generate 24 words', () => {
      const mnemonic = generateRecoveryKey()
      const words = mnemonic.split(' ')
      expect(words.length).toBe(WORD_COUNT)
    })

    it('should generate valid mnemonic', () => {
      const mnemonic = generateRecoveryKey()
      expect(validateRecoveryKey(mnemonic)).toBe(true)
    })

    it('should generate unique mnemonics', () => {
      const mnemonic1 = generateRecoveryKey()
      const mnemonic2 = generateRecoveryKey()
      expect(mnemonic1).not.toBe(mnemonic2)
    })

    it('should only use words from BIP39 wordlist', () => {
      const wordlist = getWordList()
      const mnemonic = generateRecoveryKey()
      const words = mnemonic.split(' ')

      for (const word of words) {
        expect(wordlist).toContain(word)
      }
    })
  })

  describe('validateRecoveryKey', () => {
    it('should validate correct mnemonic', () => {
      const mnemonic = generateRecoveryKey()
      expect(validateRecoveryKey(mnemonic)).toBe(true)
    })

    it('should reject invalid mnemonic', () => {
      expect(validateRecoveryKey('not a valid mnemonic phrase')).toBe(false)
    })

    it('should reject mnemonic with wrong word count', () => {
      const mnemonic = generateRecoveryKey()
      const words = mnemonic.split(' ').slice(0, 12).join(' ')
      expect(validateRecoveryKey(words)).toBe(false)
    })

    it('should reject mnemonic with invalid checksum', () => {
      const mnemonic = generateRecoveryKey()
      const words = mnemonic.split(' ')
      words[0] = 'abandon' // Replace first word to break checksum
      expect(validateRecoveryKey(words.join(' '))).toBe(false)
    })
  })

  describe('recoveryKeyToUmk / umkToRecoveryKey', () => {
    it('should convert mnemonic to UMK and back', () => {
      const mnemonic = generateRecoveryKey()
      const umk = recoveryKeyToUmk(mnemonic)

      expect(umk).toBeInstanceOf(Uint8Array)
      expect(umk.length).toBe(ENTROPY_BYTES)

      const recoveredMnemonic = umkToRecoveryKey(umk)
      expect(recoveredMnemonic).toBe(mnemonic)
    })

    it('should produce consistent UMK for same mnemonic', () => {
      const mnemonic = generateRecoveryKey()
      const umk1 = recoveryKeyToUmk(mnemonic)
      const umk2 = recoveryKeyToUmk(mnemonic)

      expect(umk1).toEqual(umk2)
    })

    it('should throw on invalid mnemonic', () => {
      expect(() => recoveryKeyToUmk('invalid mnemonic')).toThrow('Invalid recovery key')
    })

    it('should throw on invalid UMK length', () => {
      const shortUmk = new Uint8Array(16)
      expect(() => umkToRecoveryKey(shortUmk)).toThrow('Invalid UMK length')
    })
  })

  describe('getWordsAtIndices', () => {
    it('should get correct words at specified indices', () => {
      const mnemonic = generateRecoveryKey()
      const words = mnemonic.split(' ')

      const result = getWordsAtIndices(mnemonic, [0, 5, 23])

      expect(result[0]).toBe(words[0])
      expect(result[1]).toBe(words[5])
      expect(result[2]).toBe(words[23])
    })

    it('should throw on out of bounds index', () => {
      const mnemonic = generateRecoveryKey()
      expect(() => getWordsAtIndices(mnemonic, [24])).toThrow('Invalid word index')
      expect(() => getWordsAtIndices(mnemonic, [-1])).toThrow('Invalid word index')
    })
  })

  describe('verifyWords', () => {
    it('should verify correct words', () => {
      const mnemonic = generateRecoveryKey()
      const indices = [2, 7]
      const words = getWordsAtIndices(mnemonic, indices)

      expect(verifyWords(mnemonic, indices, words)).toBe(true)
    })

    it('should reject incorrect words', () => {
      const mnemonic = generateRecoveryKey()
      const indices = [2, 7]

      expect(verifyWords(mnemonic, indices, ['wrong', 'words'])).toBe(false)
    })

    it('should be case insensitive', () => {
      const mnemonic = generateRecoveryKey()
      const indices = [0]
      const words = getWordsAtIndices(mnemonic, indices)

      expect(verifyWords(mnemonic, indices, [words[0].toUpperCase()])).toBe(true)
    })

    it('should trim whitespace', () => {
      const mnemonic = generateRecoveryKey()
      const indices = [0]
      const words = getWordsAtIndices(mnemonic, indices)

      expect(verifyWords(mnemonic, indices, [`  ${words[0]}  `])).toBe(true)
    })
  })

  describe('generateVerificationIndices', () => {
    it('should generate specified number of indices', () => {
      const indices = generateVerificationIndices(3)
      expect(indices.length).toBe(3)
    })

    it('should generate unique indices', () => {
      const indices = generateVerificationIndices(5)
      const uniqueIndices = new Set(indices)
      expect(uniqueIndices.size).toBe(5)
    })

    it('should generate indices within valid range', () => {
      const indices = generateVerificationIndices(5)
      for (const i of indices) {
        expect(i).toBeGreaterThanOrEqual(0)
        expect(i).toBeLessThan(WORD_COUNT)
      }
    })

    it('should return sorted indices', () => {
      const indices = generateVerificationIndices(5)
      const sorted = [...indices].sort((a, b) => a - b)
      expect(indices).toEqual(sorted)
    })
  })

  describe('getWordList', () => {
    it('should return BIP39 English wordlist', () => {
      const wordlist = getWordList()
      expect(wordlist.length).toBe(2048)
      expect(wordlist).toContain('abandon')
      expect(wordlist).toContain('zoo')
    })
  })
})
