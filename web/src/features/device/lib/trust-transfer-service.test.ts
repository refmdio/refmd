/**
 * Integration tests for trust-transfer-service.
 *
 * Tests the TOFU verification → sender resolution → import pipeline.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// --- Mocks ---

vi.mock('@/shared/lib/crypto', () => ({
  base64UrlDecode: vi.fn((s: string) => new Uint8Array(Buffer.from(s, 'base64url'))),
  evaluateDeviceTofu: vi.fn(),
  verifyDeviceListTofu: vi.fn(),
  toKeyChangeItem: vi.fn(),
  decryptTrustState: vi.fn(),
}))

vi.mock('@/shared/lib/trust-store', () => ({
  importTofuEntries: vi.fn(),
}))

vi.mock('@/shared/api', () => ({
  trustTransferApi: {
    requestNonce: vi.fn(),
    retrieveState: vi.fn(),
    submitState: vi.fn(),
  },
}))

vi.mock('@/shared/lib/logger', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

import {
  verifyAllDevicesTofu,
  buildDirectImportAction,
  verifySenderAndResolve,
  retryRetrieveState,
  TrustTransferAbortError,
  type TrustDeviceInfo,
  type TrustStateResponse,
} from './trust-transfer-service'
import { verifyDeviceListTofu, evaluateDeviceTofu, toKeyChangeItem } from '@/shared/lib/crypto'
import { trustTransferApi } from '@/shared/api'

// --- Fixtures ---

const devices: TrustDeviceInfo[] = [
  { id: 'dev-1', name: 'Device 1', signing_public_key: 'c2lnMQ', ecdh_public_key: 'ZWNkaDE' },
  { id: 'dev-2', name: 'Device 2', signing_public_key: 'c2lnMg', ecdh_public_key: 'ZWNkaDI' },
]

const stateResponse: TrustStateResponse = {
  sender_device_id: 'dev-1',
  ciphertext: 'Y2lwaGVy',
  nonce: 'bm9uY2U',
  signature: 'c2ln',
}

beforeEach(() => {
  vi.clearAllMocks()
})

// --- verifyAllDevicesTofu ---

describe('verifyAllDevicesTofu', () => {
  it('returns empty when all devices pass TOFU', async () => {
    vi.mocked(verifyDeviceListTofu).mockResolvedValue({
      keyChangeItems: [],
      abortedDevice: null,
      failedDevices: [],
    })

    const result = await verifyAllDevicesTofu(devices, 'user-1')
    expect(result).toEqual([])
  })

  it('throws TrustTransferAbortError when a device is aborted', async () => {
    vi.mocked(verifyDeviceListTofu).mockResolvedValue({
      keyChangeItems: [],
      abortedDevice: devices[0],
      failedDevices: [],
    })

    await expect(verifyAllDevicesTofu(devices, 'user-1'))
      .rejects.toThrow(TrustTransferAbortError)
  })

  it('returns key change items for changed devices', async () => {
    const mockItem = { displayName: 'Device 2', oldFingerprint: 'old', newFingerprint: 'new', tofuNewEntry: {} }
    vi.mocked(verifyDeviceListTofu).mockResolvedValue({
      keyChangeItems: [mockItem as any],
      abortedDevice: null,
      failedDevices: [],
    })

    const result = await verifyAllDevicesTofu(devices, 'user-1')
    expect(result).toHaveLength(1)
  })
})

// --- buildDirectImportAction ---

describe('buildDirectImportAction', () => {
  const transferNonce = new Uint8Array([1, 2, 3])
  const ecdhPrivateKey = new Uint8Array([4, 5, 6])

  it('returns import action with correct sender keys', () => {
    const result = buildDirectImportAction(
      devices, stateResponse, transferNonce, 'user-1', 'my-device', ecdhPrivateKey
    )
    expect(result.action).toBe('import')
    if (result.action === 'import') {
      expect(result.senderDeviceId).toBe('dev-1')
      expect(result.importParams.userId).toBe('user-1')
      expect(result.importParams.deviceId).toBe('my-device')
    }
  })

  it('returns skip when sender device is not in list', () => {
    const missingResponse = { ...stateResponse, sender_device_id: 'dev-unknown' }
    const result = buildDirectImportAction(
      devices, missingResponse, transferNonce, 'user-1', 'my-device', ecdhPrivateKey
    )
    expect(result.action).toBe('skip')
  })
})

// --- verifySenderAndResolve ---

describe('verifySenderAndResolve', () => {
  const transferNonce = new Uint8Array([1, 2, 3])
  const ecdhPrivateKey = new Uint8Array([4, 5, 6])

  it('returns import action when sender is verified', async () => {
    vi.mocked(evaluateDeviceTofu).mockResolvedValue({ action: 'proceed', tofuResult: {} } as any)

    const result = await verifySenderAndResolve(
      devices, stateResponse, transferNonce, 'user-1', 'my-device', ecdhPrivateKey
    )
    expect(result.action).toBe('import')
  })

  it('returns abort when sender TOFU fails', async () => {
    vi.mocked(evaluateDeviceTofu).mockResolvedValue({ action: 'abort', reason: 'ECDH mismatch' })

    const result = await verifySenderAndResolve(
      devices, stateResponse, transferNonce, 'user-1', 'my-device', ecdhPrivateKey
    )
    expect(result.action).toBe('abort')
  })

  it('returns show_key_change when sender key has changed', async () => {
    vi.mocked(evaluateDeviceTofu).mockResolvedValue({
      action: 'key_changed',
      oldFingerprint: 'old-fp',
      newFingerprint: 'new-fp',
      tofuResult: { newEntry: { deviceId: 'dev-1' } },
    } as any)
    vi.mocked(toKeyChangeItem).mockReturnValue({
      displayName: 'Device 1',
      oldFingerprint: 'old-fp',
      newFingerprint: 'new-fp',
      tofuNewEntry: { deviceId: 'dev-1' },
    } as any)

    const result = await verifySenderAndResolve(
      devices, stateResponse, transferNonce, 'user-1', 'my-device', ecdhPrivateKey
    )
    expect(result.action).toBe('show_key_change')
    if (result.action === 'show_key_change') {
      expect(result.senderDeviceId).toBe('dev-1')
    }
  })

  it('returns skip when sender device not found', async () => {
    const missingResponse = { ...stateResponse, sender_device_id: 'dev-unknown' }

    const result = await verifySenderAndResolve(
      devices, missingResponse, transferNonce, 'user-1', 'my-device', ecdhPrivateKey
    )
    expect(result.action).toBe('skip')
  })
})

// --- retryRetrieveState ---

describe('retryRetrieveState', () => {
  it('returns state on first successful attempt', async () => {
    const mockState = { sender_device_id: 'dev-1', ciphertext: 'ct', nonce: 'n', signature: 's' }
    vi.mocked(trustTransferApi.retrieveState).mockResolvedValue(mockState as any)

    const result = await retryRetrieveState('my-device', 3, 0)
    expect(result).toEqual(mockState)
    expect(trustTransferApi.retrieveState).toHaveBeenCalledTimes(1)
  })

  it('retries on null response', async () => {
    vi.mocked(trustTransferApi.retrieveState)
      .mockResolvedValueOnce(null as any)
      .mockResolvedValueOnce(null as any)
      .mockResolvedValueOnce({ sender_device_id: 'dev-1', ciphertext: 'ct', nonce: 'n', signature: 's' } as any)

    const result = await retryRetrieveState('my-device', 5, 0)
    expect(result).not.toBeNull()
    expect(trustTransferApi.retrieveState).toHaveBeenCalledTimes(3)
  })

  it('retries on 404 and returns null after exhausting attempts', async () => {
    const error404 = Object.assign(new Error('Not found'), { status: 404 })
    vi.mocked(trustTransferApi.retrieveState).mockRejectedValue(error404)

    const result = await retryRetrieveState('my-device', 3, 0)
    expect(result).toBeNull()
    expect(trustTransferApi.retrieveState).toHaveBeenCalledTimes(3)
  })

  it('returns null immediately on non-404 error', async () => {
    vi.mocked(trustTransferApi.retrieveState).mockRejectedValue(new Error('Network error'))

    const result = await retryRetrieveState('my-device', 5, 0)
    expect(result).toBeNull()
    expect(trustTransferApi.retrieveState).toHaveBeenCalledTimes(1)
  })
})
