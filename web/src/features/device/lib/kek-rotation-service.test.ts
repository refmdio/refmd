/**
 * Integration tests for kek-rotation-service.
 *
 * Tests the full KEK/DEK rotation pipeline after device revocation:
 *   get current key → generate new KEK → distribute to devices → backup → complete → rotate DEKs
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// --- Mocks ---

vi.mock('@/shared/api', () => {
  class MockApiError extends Error {
    status: number
    constructor(message: string, status: number) {
      super(message)
      this.name = 'ApiError'
      this.status = status
    }
  }
  return {
    encryptionApi: {
      getWorkspaceKey: vi.fn(),
      saveDocumentKey: vi.fn(),
      saveWorkspaceKekBackup: vi.fn(),
      completeKekRotation: vi.fn(),
    },
    ApiError: MockApiError,
  }
})

vi.mock('@/shared/lib/crypto', () => ({
  base64UrlDecode: vi.fn((s: string) => new Uint8Array(Buffer.from(s, 'base64url'))),
  base64UrlEncode: vi.fn((a: Uint8Array) => Buffer.from(a).toString('base64url')),
  generateDek: vi.fn(() => new Uint8Array([50, 51])),
  wrapDek: vi.fn(() => ({ encryptedDek: new Uint8Array([60]), nonce: new Uint8Array([61]) })),
  generateKek: vi.fn(() => new Uint8Array([40, 41])),
}))

vi.mock('@/shared/lib/anti-rollback', () => ({
  checkAndPinKeyVersion: vi.fn(),
  getKeyVersionPin: vi.fn(),
}))

vi.mock('@/entities/workspace', () => ({
  clearKekCache: vi.fn(),
  encryptAndSaveKekForDevice: vi.fn(),
  wrapAndSaveKekBackup: vi.fn(),
}))

vi.mock('@/shared/lib/logger', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

import { executeKekRotation } from './kek-rotation-service'
import { encryptionApi, ApiError } from '@/shared/api'
import { checkAndPinKeyVersion, getKeyVersionPin } from '@/shared/lib/anti-rollback'
import { clearKekCache, encryptAndSaveKekForDevice, wrapAndSaveKekBackup } from '@/entities/workspace'

// --- Fixtures ---

const baseParams = {
  userId: 'user-1',
  umk: new Uint8Array([10, 20]),
  deviceId: 'my-device',
  deviceKeys: { ecdhPrivateKey: new Uint8Array([30, 31]) },
  activeDevices: [
    { id: 'dev-a', ecdh_public_key: 'ZWNkaC1h' },
    { id: 'dev-b', ecdh_public_key: 'ZWNkaC1i' },
  ] as any[],
  workspacesToRotate: ['ws-1'],
  documentsForRotation: [{ workspace_id: 'ws-1', document_ids: ['doc-1', 'doc-2'] }] as any[],
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(checkAndPinKeyVersion).mockResolvedValue(true)
  vi.mocked(getKeyVersionPin).mockResolvedValue(null)
})

describe('executeKekRotation', () => {
  it('rotates KEK, distributes to all devices, backs up, completes, and rotates DEKs', async () => {
    vi.mocked(encryptionApi.getWorkspaceKey).mockResolvedValue({ key_version: 1 } as any)
    vi.mocked(encryptAndSaveKekForDevice).mockResolvedValue(undefined)
    vi.mocked(encryptionApi.saveWorkspaceKekBackup).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.completeKekRotation).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.saveDocumentKey).mockResolvedValue({ key_version: 1 } as any)

    const result = await executeKekRotation(baseParams)

    expect(result.completedWorkspaces).toContain('ws-1')
    expect(result.failures).toHaveLength(0)

    // KEK distributed to 2 devices
    expect(encryptAndSaveKekForDevice).toHaveBeenCalledTimes(2)

    // UMK backup saved
    expect(wrapAndSaveKekBackup).toHaveBeenCalledTimes(1)

    // Rotation completed
    expect(encryptionApi.completeKekRotation).toHaveBeenCalledWith('ws-1', 2) // version+1

    // KEK cache cleared
    expect(clearKekCache).toHaveBeenCalledWith('ws-1')

    // DEK rotated for 2 documents
    expect(encryptionApi.saveDocumentKey).toHaveBeenCalledTimes(2)
  })

  it('records failure but continues when KEK distribution fails for a device', async () => {
    vi.mocked(encryptionApi.getWorkspaceKey).mockResolvedValue({ key_version: 1 } as any)
    vi.mocked(encryptAndSaveKekForDevice)
      .mockResolvedValueOnce(undefined) // dev-a succeeds
      .mockRejectedValueOnce(new Error('device offline')) // dev-b fails
    vi.mocked(encryptionApi.saveWorkspaceKekBackup).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.completeKekRotation).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.saveDocumentKey).mockResolvedValue({ key_version: 1 } as any)

    const result = await executeKekRotation(baseParams)

    // Workspace still completed despite partial distribution failure
    expect(result.completedWorkspaces).toContain('ws-1')
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0].phase).toBe('kek_distribution')
  })

  it('skips workspaces returning 404', async () => {
    vi.mocked(encryptionApi.getWorkspaceKey).mockRejectedValue(
      new (ApiError as any)('Not found', 404)
    )

    const result = await executeKekRotation(baseParams)

    expect(result.completedWorkspaces).toHaveLength(0)
    expect(result.failures).toHaveLength(0)
  })

  it('records generation failure for non-404 errors', async () => {
    vi.mocked(encryptionApi.getWorkspaceKey).mockRejectedValue(new Error('DB error'))

    const result = await executeKekRotation(baseParams)

    expect(result.completedWorkspaces).toHaveLength(0)
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0].phase).toBe('kek_generation')
  })

  it('handles multiple workspaces with mixed success', async () => {
    const multiParams = {
      ...baseParams,
      workspacesToRotate: ['ws-1', 'ws-2', 'ws-3'],
      documentsForRotation: [
        { workspace_id: 'ws-1', document_ids: ['doc-1'] },
        { workspace_id: 'ws-3', document_ids: ['doc-3'] },
      ] as any[],
    }

    vi.mocked(encryptionApi.getWorkspaceKey)
      .mockResolvedValueOnce({ key_version: 1 } as any) // ws-1 ok
      .mockRejectedValueOnce(new Error('timeout'))       // ws-2 fails
      .mockResolvedValueOnce({ key_version: 3 } as any) // ws-3 ok
    vi.mocked(encryptAndSaveKekForDevice).mockResolvedValue(undefined)
    vi.mocked(encryptionApi.saveWorkspaceKekBackup).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.completeKekRotation).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.saveDocumentKey).mockResolvedValue({ key_version: 1 } as any)

    const result = await executeKekRotation(multiParams)

    expect(result.completedWorkspaces).toEqual(['ws-1', 'ws-3'])
    expect(result.failures).toHaveLength(1)
    expect(result.failures[0].workspaceId).toBe('ws-2')
  })

  it('records DEK rotation failures without blocking workspace completion', async () => {
    vi.mocked(encryptionApi.getWorkspaceKey).mockResolvedValue({ key_version: 1 } as any)
    vi.mocked(encryptAndSaveKekForDevice).mockResolvedValue(undefined)
    vi.mocked(encryptionApi.saveWorkspaceKekBackup).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.completeKekRotation).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.saveDocumentKey)
      .mockResolvedValueOnce({ key_version: 1 } as any) // doc-1 ok
      .mockRejectedValueOnce(new Error('DEK save failed'))  // doc-2 fails

    const result = await executeKekRotation(baseParams)

    // Workspace still completed
    expect(result.completedWorkspaces).toContain('ws-1')
    // But DEK failure is recorded
    expect(result.failures.some(f => f.phase === 'dek_rotation')).toBe(true)
  })

  it('records KEK backup failure without blocking rotation', async () => {
    vi.mocked(encryptionApi.getWorkspaceKey).mockResolvedValue({ key_version: 1 } as any)
    vi.mocked(encryptAndSaveKekForDevice).mockResolvedValue(undefined)
    vi.mocked(wrapAndSaveKekBackup).mockRejectedValue(new Error('backup failed'))
    vi.mocked(encryptionApi.completeKekRotation).mockResolvedValue(undefined as any)
    vi.mocked(encryptionApi.saveDocumentKey).mockResolvedValue({ key_version: 1 } as any)

    const result = await executeKekRotation(baseParams)

    expect(result.completedWorkspaces).toContain('ws-1')
    expect(result.failures.some(f => f.phase === 'kek_backup')).toBe(true)
  })
})
