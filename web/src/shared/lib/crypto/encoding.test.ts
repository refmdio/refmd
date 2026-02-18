import { describe, it, expect } from 'vitest'
import { base64UrlEncode, base64UrlDecode } from './encoding'

describe('base64UrlEncode', () => {
  it('encodes empty array', () => {
    expect(base64UrlEncode(new Uint8Array(0))).toBe('')
  })

  it('encodes known bytes to base64url', () => {
    // "Hello" → SGVsbG8
    const bytes = new TextEncoder().encode('Hello')
    expect(base64UrlEncode(bytes)).toBe('SGVsbG8')
  })

  it('uses URL-safe characters (no + / =)', () => {
    // 0xfb, 0xff, 0xfe produce + and / in standard base64
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe])
    const encoded = base64UrlEncode(bytes)
    expect(encoded).not.toContain('+')
    expect(encoded).not.toContain('/')
    expect(encoded).not.toContain('=')
  })

  it('round-trips arbitrary data', () => {
    const original = new Uint8Array(256)
    for (let i = 0; i < 256; i++) original[i] = i
    const decoded = base64UrlDecode(base64UrlEncode(original))
    expect(decoded).toEqual(original)
  })
})

describe('base64UrlDecode', () => {
  it('decodes empty string to empty array', () => {
    expect(base64UrlDecode('')).toEqual(new Uint8Array(0))
  })

  it('decodes valid base64url', () => {
    const decoded = base64UrlDecode('SGVsbG8')
    expect(new TextDecoder().decode(decoded)).toBe('Hello')
  })

  it('rejects padding characters', () => {
    expect(() => base64UrlDecode('SGVsbG8=')).toThrow('padding not allowed')
  })

  it('rejects standard base64 characters', () => {
    expect(() => base64UrlDecode('a+b/c')).toThrow('invalid characters')
  })

  it('rejects invalid length (mod 4 == 1)', () => {
    expect(() => base64UrlDecode('A')).toThrow('invalid length')
  })

  it('rejects whitespace', () => {
    expect(() => base64UrlDecode('SGVs bG8')).toThrow('invalid characters')
  })
})
