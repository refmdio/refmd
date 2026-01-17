import { describe, it, expect, beforeAll } from 'vitest'

import { generateKey } from '@/shared/lib/crypto'

import { derivePluginDEK } from '../plugin-dek'
import {
  encryptKV,
  decryptKV,
  isEncryptedKVValue,
  isLegacyKVValue,
} from '../plugin-kv'
import {
  encryptRecordData,
  decryptRecordData,
  decryptRecords,
  isEncryptedRecordData,
} from '../plugin-records'

describe('Plugin DEK derivation', () => {
  let documentDEK: Uint8Array

  beforeAll(async () => {
    documentDEK = await generateKey()
  })

  it('derives a 32-byte DEK from document DEK', async () => {
    const pluginDEK = await derivePluginDEK(documentDEK, 'test-plugin')
    expect(pluginDEK).toBeInstanceOf(Uint8Array)
    expect(pluginDEK.length).toBe(32)
  })

  it('derives different DEKs for different plugins', async () => {
    const dek1 = await derivePluginDEK(documentDEK, 'plugin-a')
    const dek2 = await derivePluginDEK(documentDEK, 'plugin-b')

    expect(dek1).not.toEqual(dek2)
  })

  it('derives the same DEK for the same plugin', async () => {
    const dek1 = await derivePluginDEK(documentDEK, 'test-plugin')
    const dek2 = await derivePluginDEK(documentDEK, 'test-plugin')

    expect(dek1).toEqual(dek2)
  })

  it('derives different DEKs for different document DEKs', async () => {
    const anotherDocDEK = await generateKey()
    const dek1 = await derivePluginDEK(documentDEK, 'test-plugin')
    const dek2 = await derivePluginDEK(anotherDocDEK, 'test-plugin')

    expect(dek1).not.toEqual(dek2)
  })
})

describe('Plugin KV encryption', () => {
  let documentDEK: Uint8Array
  const pluginId = 'test-plugin'

  beforeAll(async () => {
    documentDEK = await generateKey()
  })

  it('encrypts and decrypts string value', async () => {
    const original = 'hello world'
    const encrypted = await encryptKV(original, documentDEK, pluginId)
    const decrypted = await decryptKV(encrypted, documentDEK, pluginId)

    expect(decrypted).toBe(original)
    expect(isEncryptedKVValue(encrypted)).toBe(true)
  })

  it('encrypts and decrypts object value', async () => {
    const original = { isKanban: true, columns: ['todo', 'doing', 'done'] }
    const encrypted = await encryptKV(original, documentDEK, pluginId)
    const decrypted = await decryptKV(encrypted, documentDEK, pluginId)

    expect(decrypted).toEqual(original)
  })

  it('encrypts and decrypts array value', async () => {
    const original = [1, 2, 3, 'four', { five: 5 }]
    const encrypted = await encryptKV(original, documentDEK, pluginId)
    const decrypted = await decryptKV(encrypted, documentDEK, pluginId)

    expect(decrypted).toEqual(original)
  })

  it('handles null value', async () => {
    const decrypted = await decryptKV(null, documentDEK, pluginId)
    expect(decrypted).toBeNull()
  })

  it('handles undefined value', async () => {
    const decrypted = await decryptKV(undefined, documentDEK, pluginId)
    expect(decrypted).toBeUndefined()
  })

  it('handles legacy plaintext value', async () => {
    const legacy = { value: 'old data', _encrypted: false as const }
    expect(isLegacyKVValue(legacy)).toBe(true)
    const decrypted = await decryptKV(legacy, documentDEK, pluginId)
    expect(decrypted).toBe('old data')
  })

  it('returns unknown format as-is for backward compatibility', async () => {
    const unknown = { someData: 'raw' }
    const decrypted = await decryptKV(unknown, documentDEK, pluginId)
    expect(decrypted).toEqual(unknown)
  })

  it('different plugins cannot decrypt each other data', async () => {
    const original = 'secret data'
    const encrypted = await encryptKV(original, documentDEK, 'plugin-a')

    await expect(
      decryptKV(encrypted, documentDEK, 'plugin-b')
    ).rejects.toThrow()
  })
})

describe('Plugin Records encryption', () => {
  let documentDEK: Uint8Array
  const pluginId = 'test-plugin'

  beforeAll(async () => {
    documentDEK = await generateKey()
  })

  it('encrypts and decrypts record data', async () => {
    const original = { title: 'Task 1', description: 'Do something', priority: 1 }
    const encrypted = await encryptRecordData(original, documentDEK, pluginId)
    const decrypted = await decryptRecordData(encrypted, documentDEK, pluginId)

    expect(decrypted).toEqual(original)
    expect(isEncryptedRecordData(encrypted)).toBe(true)
  })

  it('handles null data', async () => {
    const decrypted = await decryptRecordData(null, documentDEK, pluginId)
    expect(decrypted).toBeNull()
  })

  it('returns unknown format as-is for backward compatibility', async () => {
    const legacy = { title: 'Old task' }
    const decrypted = await decryptRecordData(legacy, documentDEK, pluginId)
    expect(decrypted).toEqual(legacy)
  })

  it('decrypts multiple records', async () => {
    const records = [
      { id: '1', data: await encryptRecordData({ title: 'Task 1' }, documentDEK, pluginId), createdAt: '2024-01-01' },
      { id: '2', data: await encryptRecordData({ title: 'Task 2' }, documentDEK, pluginId), createdAt: '2024-01-02' },
      { id: '3', data: { title: 'Legacy Task' }, createdAt: '2024-01-03' }, // legacy plaintext
    ]

    const decrypted = await decryptRecords(records, documentDEK, pluginId)

    expect(decrypted).toHaveLength(3)
    expect(decrypted[0].data).toEqual({ title: 'Task 1' })
    expect(decrypted[1].data).toEqual({ title: 'Task 2' })
    expect(decrypted[2].data).toEqual({ title: 'Legacy Task' })
    expect(decrypted[0].id).toBe('1')
    expect(decrypted[0].createdAt).toBe('2024-01-01')
  })

  it('handles records without data field', async () => {
    const records = [
      { id: '1', someOtherField: 'value' },
    ]

    const decrypted = await decryptRecords(records, documentDEK, pluginId)
    expect(decrypted[0]).toEqual({ id: '1', someOtherField: 'value' })
  })

  it('different plugins cannot decrypt each other records', async () => {
    const original = { secret: 'data' }
    const encrypted = await encryptRecordData(original, documentDEK, 'plugin-a')

    await expect(
      decryptRecordData(encrypted, documentDEK, 'plugin-b')
    ).rejects.toThrow()
  })
})
