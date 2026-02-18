/**
 * Integration tests for device-approval-service.
 *
 * Tests the approveAndDistributeKeys pipeline:
 *   KEK distribution → UMK distribution → Trust state transfer (SSE)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// --- Mocks ---

vi.mock('@/shared/api', () => ({
  workspaceApi: { list: vi.fn() },
  deviceApi: { distributeUmk: vi.fn() },
  trustTransferApi: { submitState: vi.fn() },
  sseUrls: { deviceEvents: () => '/api/devices/events' },
}))

vi.mock('@/entities/workspace', () => ({
  fetchAndDecryptKek: vi.fn(),
  encryptAndSaveKekForDevice: vi.fn(),
}))

vi.mock('@/shared/lib/crypto', () => ({
  base64UrlDecode: vi.fn((s: string) => new Uint8Array(Buffer.from(s, 'base64url'))),
  base64UrlEncode: vi.fn((a: Uint8Array) => Buffer.from(a).toString('base64url')),
  encryptUmkForDevice: vi.fn(),
  encryptTrustState: vi.fn(),
}))

vi.mock('@/shared/lib/trust-store', () => ({
  getAllTofuEntriesForUser: vi.fn(),
}))

vi.mock('@/shared/lib/sse', () => ({
  waitForSSEEvent: vi.fn(),
}))

vi.mock('@/shared/lib/logger', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

import { approveAndDistributeKeys } from './device-approval-service'
import { workspaceApi, deviceApi, trustTransferApi } from '@/shared/api'
import { fetchAndDecryptKek, encryptAndSaveKekForDevice } from '@/entities/workspace'
import { encryptUmkForDevice, encryptTrustState } from '@/shared/lib/crypto'
import { getAllTofuEntriesForUser } from '@/shared/lib/trust-store'
import { waitForSSEEvent } from '@/shared/lib/sse'

// --- Test fixtures ---

const mockAuth = {
  userId: 'user-1',
  umk: new Uint8Array([10, 20, 30]),
  identityKeys: {
    signingPublic: new Uint8Array([1]),
    signingPrivate: new Uint8Array([2]),
  },
}

const mockDevice = {
  deviceId: 'device-1',
  deviceKeys: {
    signingPublicKey: new Uint8Array([3]),
    signingPrivateKey: new Uint8Array([4]),
    ecdhPublicKey: new Uint8Array([5]),
    ecdhPrivateKey: new Uint8Array([6]),
  },
}

const targetEcdhPk = new Uint8Array([7, 8, 9])
const approvedDeviceId = 'approved-device-1'

const baseParams = {
  auth: mockAuth as any,
  currentDevice: mockDevice as any,
  targetEcdhPk,
  approvedDeviceId,
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('approveAndDistributeKeys', () => {
  it('distributes KEK, UMK, and trust state in order', async () => {
    // KEK distribution setup
    vi.mocked(workspaceApi.list).mockResolvedValue({
      workspaces: [
        { workspace: { id: 'ws-1' } },
        { workspace: { id: 'ws-2' } },
      ],
    } as any)
    vi.mocked(fetchAndDecryptKek).mockResolvedValue({ kek: new Uint8Array([100]), keyVersion: 1 })
    vi.mocked(encryptAndSaveKekForDevice).mockResolvedValue(undefined)

    // UMK distribution setup
    vi.mocked(encryptUmkForDevice).mockReturnValue({
      encryptedUmk: new Uint8Array([200]),
      nonce: new Uint8Array([201]),
    })
    vi.mocked(deviceApi.distributeUmk).mockResolvedValue(undefined as any)

    // SSE + trust transfer setup
    vi.mocked(waitForSSEEvent).mockResolvedValue({
      nonce: 'dGVzdC1ub25jZQ', // base64url of "test-nonce"
      newDeviceId: approvedDeviceId,
    })
    vi.mocked(getAllTofuEntriesForUser).mockResolvedValue([{ deviceId: 'dev-x', signingFingerprint: 'fp' }] as any)
    vi.mocked(encryptTrustState).mockReturnValue({
      encryptedState: new Uint8Array([300]),
      nonce: new Uint8Array([301]),
      signature: new Uint8Array([302]),
    })
    vi.mocked(trustTransferApi.submitState).mockResolvedValue(undefined)

    await approveAndDistributeKeys(baseParams)

    // Verify KEK distributed to both workspaces
    expect(fetchAndDecryptKek).toHaveBeenCalledTimes(2)
    expect(encryptAndSaveKekForDevice).toHaveBeenCalledTimes(2)

    // Verify UMK distributed
    expect(encryptUmkForDevice).toHaveBeenCalledWith(
      mockAuth.umk,
      mockDevice.deviceKeys.ecdhPrivateKey,
      targetEcdhPk,
      mockAuth.userId,
      mockDevice.deviceId,
      approvedDeviceId,
    )
    expect(deviceApi.distributeUmk).toHaveBeenCalledTimes(1)

    // Verify trust state transferred
    expect(waitForSSEEvent).toHaveBeenCalledTimes(1)
    expect(trustTransferApi.submitState).toHaveBeenCalledTimes(1)
  })

  it('continues when KEK distribution fails (non-fatal)', async () => {
    vi.mocked(workspaceApi.list).mockResolvedValue({
      workspaces: [{ workspace: { id: 'ws-1' } }],
    } as any)
    vi.mocked(fetchAndDecryptKek).mockRejectedValue(new Error('KEK fetch failed'))

    vi.mocked(encryptUmkForDevice).mockReturnValue({
      encryptedUmk: new Uint8Array([200]),
      nonce: new Uint8Array([201]),
    })
    vi.mocked(deviceApi.distributeUmk).mockResolvedValue(undefined as any)

    vi.mocked(waitForSSEEvent).mockResolvedValue({ nonce: 'bm9uY2U', newDeviceId: approvedDeviceId })
    vi.mocked(getAllTofuEntriesForUser).mockResolvedValue([])

    await approveAndDistributeKeys(baseParams)

    // UMK should still be distributed
    expect(deviceApi.distributeUmk).toHaveBeenCalledTimes(1)
  })

  it('continues when trust state transfer fails (non-fatal)', async () => {
    vi.mocked(workspaceApi.list).mockResolvedValue({ workspaces: [] } as any)

    vi.mocked(encryptUmkForDevice).mockReturnValue({
      encryptedUmk: new Uint8Array([200]),
      nonce: new Uint8Array([201]),
    })
    vi.mocked(deviceApi.distributeUmk).mockResolvedValue(undefined as any)

    vi.mocked(waitForSSEEvent).mockRejectedValue(new Error('SSE timeout'))

    // Should NOT throw — trust transfer is non-fatal
    await expect(approveAndDistributeKeys(baseParams)).resolves.toBeUndefined()
    expect(deviceApi.distributeUmk).toHaveBeenCalledTimes(1)
  })

  it('throws when UMK distribution fails (fatal)', async () => {
    vi.mocked(workspaceApi.list).mockResolvedValue({ workspaces: [] } as any)

    vi.mocked(encryptUmkForDevice).mockReturnValue({
      encryptedUmk: new Uint8Array([200]),
      nonce: new Uint8Array([201]),
    })
    vi.mocked(deviceApi.distributeUmk).mockRejectedValue(new Error('UMK failed'))

    await expect(approveAndDistributeKeys(baseParams)).rejects.toThrow('UMK failed')
  })

  it('skips trust state submission when no TOFU entries exist', async () => {
    vi.mocked(workspaceApi.list).mockResolvedValue({ workspaces: [] } as any)

    vi.mocked(encryptUmkForDevice).mockReturnValue({
      encryptedUmk: new Uint8Array([200]),
      nonce: new Uint8Array([201]),
    })
    vi.mocked(deviceApi.distributeUmk).mockResolvedValue(undefined as any)

    vi.mocked(waitForSSEEvent).mockResolvedValue({ nonce: 'bm9uY2U', newDeviceId: approvedDeviceId })
    vi.mocked(getAllTofuEntriesForUser).mockResolvedValue([])

    await approveAndDistributeKeys(baseParams)

    // No entries → no encrypt or submit
    expect(encryptTrustState).not.toHaveBeenCalled()
    expect(trustTransferApi.submitState).not.toHaveBeenCalled()
  })
})
